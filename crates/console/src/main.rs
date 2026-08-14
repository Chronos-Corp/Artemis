//! Phase 1 fleet console. Accepts agent enrollment, heartbeats, YARA
//! sighting reports, and sample-retrieval requests, and records them in
//! the shared Postgres intel graph (the same schema `src-tauri` uses).
//! See docs/phase1-design.md for what's deliberately not here yet (a
//! fleet UI, credential rotation, rate limiting).
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
//! the read endpoints that list sightings back out and on creating/
//! listing sample requests. An agent's per-agent credential authenticates
//! that one host's own writes -- it must not also authenticate reading or
//! directing the rest of the fleet, hence the separate operator
//! credential.

mod auth;
mod host;
mod pagination;
mod sample;
mod sighting;
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
}

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

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
    let pool = nsic_core::db::connect_and_migrate(&database_url).await?;
    tracing::info!("connected to postgres and ran migrations");

    let app = build_router(AppState {
        pool,
        bootstrap_secret,
        operator_secret,
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

    Router::new()
        .route("/api/v1/agents/enroll", post(host::enroll))
        .route("/api/v1/agents/{host_id}/heartbeat", post(host::heartbeat))
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
}

#[cfg(test)]
mod tests {
    use super::{validate_secret_configuration, validate_tls_configuration};

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
}
