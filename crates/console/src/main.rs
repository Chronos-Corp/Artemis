//! Phase 1 fleet console. Accepts agent enrollment, heartbeats, YARA
//! sighting reports, and sample-retrieval requests, and records them in
//! the shared Postgres intel graph (the same schema `src-tauri` uses).
//! Also serves a server-rendered fleet UI (`crate::ui`) for the operator
//! persona. See docs/phase1-design.md for what's deliberately not here
//! yet (plugin/scripting support, rate limiting).
//!
//! TLS is opt-in via `NSIC_TLS_CERT_PATH`/`NSIC_TLS_KEY_PATH` (both or
//! neither -- see `main`). Plain HTTP remains the default so existing
//! local setups keep working unchanged; enabling TLS is a deliberate
//! operator choice, not a breaking change forced on every deployment.
//!
//! Three credentials gate this API (see `nsic_core::proto` and
//! `crate::auth` for the full rationale, kept deliberately distinct rather
//! than collapsed into one token): a bootstrap enrollment secret the
//! operator configures via `NSIC_ENROLLMENT_SECRET`, required on every
//! `POST /api/v1/agents/enroll` call; a per-agent credential minted at
//! enroll time, required on every subsequent agent-authenticated request
//! (heartbeat, sighting submission, sample-request polling/fulfillment);
//! and a console-operator credential (`NSIC_OPERATOR_SECRET`), required on
//! the read endpoints that list sightings back out, on creating/listing
//! sample requests, and on rotating or revoking a host's per-agent
//! credential. An agent's per-agent credential authenticates that one
//! host's own writes -- it must not also authenticate reading or
//! directing the rest of the fleet, hence the separate operator
//! credential. The fleet UI (`crate::ui`) gates on that same operator
//! credential too, presented as HTTP Basic instead of Bearer -- see
//! `auth::authenticate_operator_ui`.
//!
//! `NSIC_SCAN_STALENESS_HOURS` (default `DEFAULT_SCAN_STALENESS_HOURS`)
//! controls when `HostView::scan_stale` flags a host's most recent scan
//! report as too old to trust -- see that constant's doc comment.

mod auth;
mod host;
mod pagination;
mod sample;
mod sighting;
mod ui;
mod validate;

use anyhow::Context;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use sqlx::PgPool;
use std::net::SocketAddr;

#[derive(Clone)]
pub(crate) struct AppState {
    pool: PgPool,
    bootstrap_secret: String,
    operator_secret: String,
    /// The fleet UI's CSRF token -- one per process, generated at
    /// startup. See `auth::generate_csrf_token`'s doc comment for why a
    /// single unrotated value is sufficient here.
    csrf_token: String,
    /// How old `last_scan_at` has to be before `HostView::scan_stale`
    /// flags it -- see `DEFAULT_SCAN_STALENESS_HOURS`'s doc comment.
    scan_staleness_threshold: chrono::Duration,
}

/// Default for `NSIC_SCAN_STALENESS_HOURS`: a sane, documented-as-
/// arbitrary ceiling for a fleet scanned roughly daily (e.g. via cron or
/// a scheduled task running `nsic-agent scan`), not derived from any real
/// workload -- the same "arbitrary but explicit" posture
/// `nsic_core::proto::MAX_SAMPLE_SIZE_BYTES` already takes. Deferred since
/// PR #14 pending exactly this: "a concrete policy for what 'stale' means
/// for this product" (docs/phase1-design.md). Overridable per-deployment
/// for a different scanning cadence.
const DEFAULT_SCAN_STALENESS_HOURS: i64 = 24;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // rustls needs exactly one process-level crypto provider selected
    // before anything builds a `ServerConfig` -- with both `ring` (from
    // sqlx's `runtime-tokio-rustls`) and `aws-lc-rs` (axum-server's
    // rustls default) compiled into this binary, it can't pick one
    // automatically and panics instead of guessing. Installing `ring`
    // explicitly, matching what sqlx already uses elsewhere in this
    // project, resolves the ambiguity regardless of TLS actually being
    // enabled this run -- cheap and harmless when it isn't. Discovered
    // by actually starting the console with TLS configured, not by
    // reading the rustls/axum-server docs: `cargo check`/`clippy`/tests
    // don't exercise this constructor at all, so nothing short of a live
    // run surfaces it.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("installing the rustls ring crypto provider should only ever be attempted once");

    // Checked before touching the network: a misconfigured secret should
    // fail fast on local config, not after paying for a Postgres round trip.
    let bootstrap_secret = std::env::var("NSIC_ENROLLMENT_SECRET").context(
        "NSIC_ENROLLMENT_SECRET must be set: the console refuses to start without a \
         bootstrap enrollment secret to authorize new agents",
    )?;
    let operator_secret = std::env::var("NSIC_OPERATOR_SECRET").context(
        "NSIC_OPERATOR_SECRET must be set: the console refuses to start without a \
         credential gating read access to fleet-wide sighting data",
    )?;
    validate_secret_configuration(&bootstrap_secret, &operator_secret)?;

    // Same both-or-neither shape as the two secrets above, checked at the
    // same point for the same reason: a half-configured TLS setup (a cert
    // path with no key, or vice versa) should fail fast on local config,
    // not fail confusingly later or silently fall back to plain HTTP.
    let tls_cert_path = std::env::var("NSIC_TLS_CERT_PATH").ok();
    let tls_key_path = std::env::var("NSIC_TLS_KEY_PATH").ok();
    let tls_paths = validate_tls_configuration(tls_cert_path, tls_key_path)?;

    let scan_staleness_hours = match std::env::var("NSIC_SCAN_STALENESS_HOURS") {
        Ok(v) => v.parse().with_context(|| {
            format!(
                "NSIC_SCAN_STALENESS_HOURS must be a non-negative integer number of hours, \
                 got {v:?}"
            )
        })?,
        Err(_) => DEFAULT_SCAN_STALENESS_HOURS,
    };
    let scan_staleness_threshold = validate_scan_staleness_hours(scan_staleness_hours)?;

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
    let pool = nsic_core::db::connect_and_migrate(&database_url).await?;
    tracing::info!("connected to postgres and ran migrations");

    let app = build_router(AppState {
        pool,
        bootstrap_secret,
        operator_secret,
        csrf_token: auth::generate_csrf_token(),
        scan_staleness_threshold,
    });

    // Loopback-only by default regardless of TLS: network-wide exposure
    // is an explicit opt-in via NSIC_CONSOLE_ADDR either way, not the
    // out-of-the-box default. TLS and bind address are independent
    // choices -- an operator can widen the bind, enable TLS, both, or
    // neither.
    let addr: SocketAddr = std::env::var("NSIC_CONSOLE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()?;

    match tls_paths {
        Some((cert_path, key_path)) => {
            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                    .await
                    .with_context(|| {
                        format!("loading TLS certificate ({cert_path}) and key ({key_path})")
                    })?;
            tracing::info!("console listening on {addr} (HTTPS)");
            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await?;
        }
        None => {
            tracing::warn!(
                "console listening on {addr} over plain HTTP -- no TLS configured; \
                 credentials and sample content (including retrieved malware bytes) cross \
                 the wire in plaintext. Set NSIC_TLS_CERT_PATH and NSIC_TLS_KEY_PATH to \
                 enable TLS; see docs/phase1-design.md."
            );
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}

/// Fails fast if exactly one of `NSIC_TLS_CERT_PATH`/`NSIC_TLS_KEY_PATH`
/// is set: a cert with no key (or vice versa) can never actually serve
/// TLS, so treating that as "TLS disabled" would silently downgrade a
/// misconfigured deployment to plaintext instead of refusing to start.
/// Returns `Some((cert, key))` when TLS should be enabled, `None` when
/// neither is set and the console should serve plain HTTP.
fn validate_tls_configuration(
    cert_path: Option<String>,
    key_path: Option<String>,
) -> anyhow::Result<Option<(String, String)>> {
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => Ok(Some((cert, key))),
        (None, None) => Ok(None),
        (Some(_), None) => anyhow::bail!(
            "NSIC_TLS_CERT_PATH is set but NSIC_TLS_KEY_PATH is not -- both are required to \
             enable TLS, or neither to run without it"
        ),
        (None, Some(_)) => anyhow::bail!(
            "NSIC_TLS_KEY_PATH is set but NSIC_TLS_CERT_PATH is not -- both are required to \
             enable TLS, or neither to run without it"
        ),
    }
}

/// Fails fast if either secret is empty, or if the two are equal. An
/// empty value would make the corresponding check trivially satisfiable
/// by a request that sends an empty bearer token; two equal values would
/// silently collapse the bootstrap-vs-operator separation the rest of
/// this design depends on -- the same credential would then both enroll
/// new agents and read the entire fleet's sighting history, exactly the
/// conflation `NSIC_OPERATOR_SECRET` exists to avoid. A plain `==`
/// comparison, not `auth::secrets_match`'s constant-time one: this runs
/// once at process startup comparing two local config values, not on a
/// request path an attacker can time over the network.
fn validate_secret_configuration(
    bootstrap_secret: &str,
    operator_secret: &str,
) -> anyhow::Result<()> {
    if bootstrap_secret.is_empty() {
        anyhow::bail!("NSIC_ENROLLMENT_SECRET must not be empty");
    }
    if operator_secret.is_empty() {
        anyhow::bail!("NSIC_OPERATOR_SECRET must not be empty");
    }
    if bootstrap_secret == operator_secret {
        anyhow::bail!(
            "NSIC_ENROLLMENT_SECRET and NSIC_OPERATOR_SECRET must not be equal -- they \
             authorize different things (enrolling new agents vs. reading the fleet's \
             sighting data), and a shared value would collapse that separation"
        );
    }
    Ok(())
}

/// Rejects a negative `NSIC_SCAN_STALENESS_HOURS` -- "negative hours
/// until stale" has no coherent meaning, unlike 0 (a valid, if aggressive,
/// choice: everything but a scan from this exact instant reads as stale).
/// Fails fast at startup for the same reason the secret and TLS
/// configuration checks do, rather than only surfacing as a confusing
/// `chrono::Duration` deep in a request handler.
fn validate_scan_staleness_hours(hours: i64) -> anyhow::Result<chrono::Duration> {
    if hours < 0 {
        anyhow::bail!("NSIC_SCAN_STALENESS_HOURS must not be negative, got {hours}");
    }
    Ok(chrono::Duration::hours(hours))
}

fn build_router(state: AppState) -> Router {
    // The sample-content upload route gets its own sub-router so only it
    // carries a raised body-size limit -- every other route (all JSON)
    // keeps axum's default, so a misbehaving JSON client can't force the
    // server to buffer up to MAX_SAMPLE_SIZE_BYTES on an endpoint that
    // was never meant to receive anything that large.
    let sample_content_route = Router::new()
        .route(
            "/api/v1/agents/{host_id}/sample-requests/{request_id}/content",
            post(sample::fulfill_sample_request),
        )
        .layer(DefaultBodyLimit::max(
            nsic_core::proto::MAX_SAMPLE_SIZE_BYTES,
        ))
        .with_state(state.clone());

    // The fleet UI gets its own sub-router too, so `ui::security_headers`
    // (Cache-Control: no-store, CSP, X-Frame-Options -- see that
    // function's doc comment) applies to every HTML page and download
    // this module serves without also being layered onto the JSON API,
    // which has no use for browser-facing headers like CSP.
    let ui_routes = Router::new()
        .route("/", get(ui::host_directory))
        .route("/hosts", get(ui::host_directory))
        .route("/hosts/{host_id}", get(ui::host_detail))
        .route(
            "/hosts/{host_id}/sample-requests",
            post(ui::create_sample_request_action),
        )
        .route(
            "/hosts/{host_id}/sample-requests/{request_id}/content",
            get(ui::download_sample),
        )
        .route(
            "/hosts/{host_id}/credential/rotate",
            post(ui::rotate_credential_action),
        )
        .route(
            "/hosts/{host_id}/credential/revoke",
            post(ui::revoke_credential_action),
        )
        .layer(axum::middleware::from_fn(ui::security_headers))
        .with_state(state.clone());

    Router::new()
        .route("/api/v1/agents/enroll", post(host::enroll))
        .route("/api/v1/agents/{host_id}/heartbeat", post(host::heartbeat))
        .route("/api/v1/agents/{host_id}/scans", post(host::report_scan))
        .route("/api/v1/hosts", get(host::list_hosts))
        .route("/api/v1/hosts/{host_id}", get(host::get_host))
        .route(
            "/api/v1/hosts/{host_id}/credential/rotate",
            post(host::rotate_credential),
        )
        .route(
            "/api/v1/hosts/{host_id}/credential/revoke",
            post(host::revoke_credential),
        )
        .route(
            "/api/v1/agents/{host_id}/sightings",
            post(sighting::report_sighting),
        )
        .route(
            "/api/v1/hosts/{host_id}/sightings",
            get(sighting::list_host_sightings),
        )
        .route(
            "/api/v1/indicators/{sha256}/sightings",
            get(sighting::list_indicator_sightings),
        )
        .route(
            "/api/v1/hosts/{host_id}/sample-requests",
            post(sample::create_sample_request).get(sample::list_sample_requests),
        )
        .route(
            "/api/v1/hosts/{host_id}/sample-requests/{request_id}/content",
            get(sample::download_sample_by_request),
        )
        .route(
            "/api/v1/samples/{sha256}/content",
            get(sample::download_sample_by_sha256),
        )
        .route(
            "/api/v1/agents/{host_id}/sample-requests",
            get(sample::list_pending_sample_requests),
        )
        .route(
            "/api/v1/agents/{host_id}/sample-requests/{request_id}/failure",
            post(sample::fail_sample_request),
        )
        .with_state(state)
        .merge(sample_content_route)
        .merge(ui_routes)
}

#[cfg(test)]
mod tests {
    use super::{
        validate_scan_staleness_hours, validate_secret_configuration, validate_tls_configuration,
    };

    #[test]
    fn accepts_distinct_non_empty_secrets() {
        assert!(validate_secret_configuration("bootstrap", "operator").is_ok());
    }

    #[test]
    fn rejects_empty_bootstrap_secret() {
        assert!(validate_secret_configuration("", "operator").is_err());
    }

    #[test]
    fn rejects_empty_operator_secret() {
        assert!(validate_secret_configuration("bootstrap", "").is_err());
    }

    #[test]
    fn rejects_equal_secrets() {
        assert!(validate_secret_configuration("same-value", "same-value").is_err());
    }

    #[test]
    fn tls_disabled_when_neither_path_is_set() {
        assert_eq!(validate_tls_configuration(None, None).unwrap(), None);
    }

    #[test]
    fn tls_enabled_when_both_paths_are_set() {
        let result =
            validate_tls_configuration(Some("cert.pem".to_string()), Some("key.pem".to_string()))
                .unwrap();
        assert_eq!(
            result,
            Some(("cert.pem".to_string(), "key.pem".to_string()))
        );
    }

    #[test]
    fn rejects_cert_path_without_key_path() {
        assert!(validate_tls_configuration(Some("cert.pem".to_string()), None).is_err());
    }

    #[test]
    fn rejects_key_path_without_cert_path() {
        assert!(validate_tls_configuration(None, Some("key.pem".to_string())).is_err());
    }

    #[test]
    fn accepts_a_non_negative_scan_staleness_hours() {
        assert_eq!(
            validate_scan_staleness_hours(24).unwrap(),
            chrono::Duration::hours(24)
        );
    }

    #[test]
    fn accepts_zero_scan_staleness_hours() {
        assert_eq!(
            validate_scan_staleness_hours(0).unwrap(),
            chrono::Duration::hours(0)
        );
    }

    #[test]
    fn rejects_negative_scan_staleness_hours() {
        assert!(validate_scan_staleness_hours(-1).is_err());
    }
}
