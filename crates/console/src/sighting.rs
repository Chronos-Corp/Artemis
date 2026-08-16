use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use nsic_core::models::{DetectionKind, IndicatorKind};
use nsic_core::proto::{SightingListResponse, SightingRequest, SightingResponse, SightingView};
use sqlx::{PgExecutor, PgPool, Row};
use uuid::Uuid;

use crate::auth::{authenticate_host, authenticate_operator, internal_error};
use crate::pagination::truncate_to_limit;
use crate::validate::{bad_request, validate_lowercase_sha256, validate_observed_at};
use crate::AppState;

/// Hard cap on rows returned by the list endpoints below. Not real
/// pagination (there's no cursor, no way to reach rows past the cap) --
/// just a ceiling against an unbounded response once a host or a widely
/// matched hash accumulates enough sightings, which real pagination should
/// eventually replace. See docs/phase1-design.md.
const SIGHTING_LIST_LIMIT: i64 = 1000;

/// Source/confidence for every sighting this endpoint records. Not
/// client-supplied -- see `nsic_core::proto::SightingRequest`'s doc
/// comment for why an agent doesn't get to assert its own trust level.
/// Matches `src-tauri`'s existing convention for local YARA hits
/// (`"local:yara_scan"`, confidence 65; see `verdict.rs`), prefixed
/// `agent:` instead of `local:` so fleet- and desktop-sourced hits stay
/// distinguishable in the graph.
const YARA_SIGHTING_SOURCE: &str = "agent:yara_scan";
const YARA_SIGHTING_CONFIDENCE: i16 = 65;

/// Records that `host_id` observed a YARA rule match, provided the caller
/// presents that host's own per-agent credential and the payload passes
/// validation. Upserts the indicator (the file's hash) and the detection
/// (the rule) if either is new, then both a `detection_detects_indicator`
/// edge (so this hit joins the same graph a local desktop scan would
/// populate) and a `host_sighted_indicator` edge carrying the full
/// authenticated claim: which host, through which detection, saw which
/// indicator, from where, and under which ruleset version. All four
/// writes happen in one transaction: a failure partway through must not
/// leave the graph with, say, a new indicator and detection but no
/// record of which host actually saw them together.
pub async fn report_sighting(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<SightingRequest>,
) -> Result<Json<SightingResponse>, (StatusCode, String)> {
    authenticate_host(&state.pool, host_id, &headers).await?;
    validate_sighting_request(&req)?;

    let mut tx = state.pool.begin().await.map_err(internal_error)?;

    let indicator_id = upsert_indicator(&mut *tx, IndicatorKind::Sha256, &req.sha256)
        .await
        .map_err(internal_error)?;
    let detection_id = upsert_detection(&mut *tx, DetectionKind::Yara, &req.detection_name)
        .await
        .map_err(internal_error)?;

    upsert_detection_detects_indicator(
        &mut *tx,
        detection_id,
        indicator_id,
        YARA_SIGHTING_SOURCE,
        YARA_SIGHTING_CONFIDENCE,
        req.observed_at,
        req.observed_at,
    )
    .await
    .map_err(internal_error)?;

    upsert_host_sighted_indicator(
        &mut *tx,
        host_id,
        detection_id,
        indicator_id,
        YARA_SIGHTING_SOURCE,
        YARA_SIGHTING_CONFIDENCE,
        req.path.as_deref(),
        &req.ruleset_fingerprint,
        req.observed_at,
        req.observed_at,
    )
    .await
    .map_err(internal_error)?;

    tx.commit().await.map_err(internal_error)?;

    Ok(Json(SightingResponse {
        indicator_id,
        recorded_at: Utc::now(),
    }))
}

/// Lists every sighting recorded for a given host, most recently observed
/// first, joined against `indicator`/`detection` so callers get a sha256
/// and rule name directly rather than resolving `indicator_id`/
/// `detection_id` themselves. Requires the console-operator credential
/// (`authenticate_operator`), not the per-agent credential `report_sighting`
/// checks -- a host's own credential proves it may report its own
/// observations, not that it may read any host's data, including its own.
/// An unknown `host_id` returns `200` with an empty list rather than
/// `404`: there is no "list all hosts" endpoint yet for an operator to
/// have confirmed the id exists in the first place (see
/// docs/phase1-design.md), so treating "no sightings" and "no such host"
/// identically doesn't leak anything an operator couldn't already tell by
/// other means once one exists.
pub async fn list_host_sightings(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SightingListResponse>, (StatusCode, String)> {
    authenticate_operator(&state.operator_secret, &headers)?;

    let (sightings, truncated) = fetch_host_sightings(&state.pool, host_id)
        .await
        .map_err(internal_error)?;
    Ok(Json(SightingListResponse {
        sightings,
        truncated,
    }))
}

/// Shared by `list_host_sightings` (JSON API) and the fleet UI's host
/// detail page (`crates/console/src/ui.rs`), so both render from the same
/// query instead of the SQL drifting between a JSON response and an HTML
/// page that happen to want the same rows.
pub(crate) async fn fetch_host_sightings(
    pool: &PgPool,
    host_id: Uuid,
) -> sqlx::Result<(Vec<SightingView>, bool)> {
    // ORDER BY tie-breaks past last_seen with the rest of the primary key
    // (host_id is already fixed by WHERE): last_seen alone is not unique
    // per row, so without a full tie-break the row order -- and therefore
    // which rows land inside vs. past the cap -- is not guaranteed stable
    // across two calls that return the same underlying data.
    let mut rows = sqlx::query(
        "SELECT ho.id AS host_id, ho.hostname, h.indicator_id, i.value AS sha256, \
                h.detection_id, d.name AS detection_name, h.source, h.confidence, \
                h.path, h.ruleset_fingerprint, h.first_seen, h.last_seen, h.received_at \
         FROM host_sighted_indicator h \
         JOIN host ho ON ho.id = h.host_id \
         JOIN indicator i ON i.id = h.indicator_id \
         JOIN detection d ON d.id = h.detection_id \
         WHERE h.host_id = $1 \
         ORDER BY h.last_seen DESC, h.detection_id, h.indicator_id, h.source, \
                  h.ruleset_fingerprint \
         LIMIT $2",
    )
    .bind(host_id)
    .bind(SIGHTING_LIST_LIMIT + 1)
    .fetch_all(pool)
    .await?;

    let truncated = truncate_to_limit(&mut rows, SIGHTING_LIST_LIMIT as usize);
    Ok((
        rows.into_iter().map(sighting_view_from_row).collect(),
        truncated,
    ))
}

/// Lists every host that has sighted a given indicator (by sha256), most
/// recently observed first -- the cross-fleet "who else has seen this
/// hash" pivot the product's core idea (see the README) depends on.
/// Requires the console-operator credential, same as `list_host_sightings`.
/// Scoped to sha256 lookups only, the same deliberate narrowness
/// `SightingRequest` already has: sightings currently only ever carry a
/// sha256 indicator, so there is nothing else to look up by yet.
pub async fn list_indicator_sightings(
    State(state): State<AppState>,
    Path(sha256): Path<String>,
    headers: HeaderMap,
) -> Result<Json<SightingListResponse>, (StatusCode, String)> {
    authenticate_operator(&state.operator_secret, &headers)?;
    validate_lowercase_sha256(&sha256, "sha256")?;

    // Same tie-break reasoning as list_host_sightings, with indicator_id
    // fixed by WHERE instead of host_id, so the remaining primary-key
    // columns break ties here: host_id, detection_id, source,
    // ruleset_fingerprint.
    let mut rows = sqlx::query(
        "SELECT ho.id AS host_id, ho.hostname, h.indicator_id, i.value AS sha256, \
                h.detection_id, d.name AS detection_name, h.source, h.confidence, \
                h.path, h.ruleset_fingerprint, h.first_seen, h.last_seen, h.received_at \
         FROM host_sighted_indicator h \
         JOIN host ho ON ho.id = h.host_id \
         JOIN indicator i ON i.id = h.indicator_id \
         JOIN detection d ON d.id = h.detection_id \
         WHERE i.kind = $1 AND i.value = $2 \
         ORDER BY h.last_seen DESC, h.host_id, h.detection_id, h.source, \
                  h.ruleset_fingerprint \
         LIMIT $3",
    )
    .bind(IndicatorKind::Sha256)
    .bind(&sha256)
    .bind(SIGHTING_LIST_LIMIT + 1)
    .fetch_all(&state.pool)
    .await
    .map_err(internal_error)?;

    let truncated = truncate_to_limit(&mut rows, SIGHTING_LIST_LIMIT as usize);
    Ok(Json(SightingListResponse {
        sightings: rows.into_iter().map(sighting_view_from_row).collect(),
        truncated,
    }))
}

fn sighting_view_from_row(row: sqlx::postgres::PgRow) -> SightingView {
    SightingView {
        host_id: row.get("host_id"),
        hostname: row.get("hostname"),
        indicator_id: row.get("indicator_id"),
        sha256: row.get("sha256"),
        detection_id: row.get("detection_id"),
        detection_name: row.get("detection_name"),
        source: row.get("source"),
        confidence: row.get("confidence"),
        path: row.get("path"),
        ruleset_fingerprint: row.get("ruleset_fingerprint"),
        first_seen: row.get("first_seen"),
        last_seen: row.get("last_seen"),
        received_at: row.get("received_at"),
    }
}

/// Authentication proves which agent sent a request, not that the agent
/// is bug-free or uncompromised -- so the console still validates the
/// payload itself rather than trusting it onto the graph verbatim.
fn validate_sighting_request(req: &SightingRequest) -> Result<(), (StatusCode, String)> {
    validate_lowercase_sha256(&req.sha256, "sha256")?;
    validate_lowercase_sha256(&req.ruleset_fingerprint, "ruleset_fingerprint")?;

    if req.detection_name.trim().is_empty() {
        return Err(bad_request("detection_name must not be empty"));
    }
    if req.detection_name.chars().count() > 256 {
        return Err(bad_request(
            "detection_name must be 256 characters or fewer",
        ));
    }

    validate_observed_at(req.observed_at, "observed_at")?;

    Ok(())
}

/// Reimplements `src-tauri`'s `db::indicators::upsert_indicator` with a
/// runtime-checked query (no `sqlx::query!` macro) rather than sharing it
/// via `nsic-core`, so this crate keeps compiling without an
/// `SQLX_OFFLINE` cache prepared against a live database -- the same
/// tradeoff PR #4's `host.rs` queries already made. Both write the exact
/// same table with the exact same conflict handling; see
/// docs/phase1-design.md for the tradeoff this accepts. Generic over the
/// executor (rather than a concrete `&PgPool`) so `report_sighting` can
/// run all four upserts inside one transaction.
async fn upsert_indicator<'e, E>(
    executor: E,
    kind: IndicatorKind,
    value: &str,
) -> sqlx::Result<Uuid>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar(
        "INSERT INTO indicator (kind, value) VALUES ($1, $2) \
         ON CONFLICT (kind, value) DO UPDATE SET value = EXCLUDED.value \
         RETURNING id",
    )
    .bind(kind)
    .bind(value)
    .fetch_one(executor)
    .await
}

/// See `upsert_indicator`'s doc comment -- same reasoning, mirrors
/// `src-tauri`'s `upsert_detection` but without the `rule_source`/
/// `rule_body`/`author` columns, which a sighting doesn't carry (an
/// existing detection's own metadata from a fuller ingestion path is left
/// untouched by the `ON CONFLICT` clause below, not overwritten with
/// NULLs).
async fn upsert_detection<'e, E>(executor: E, kind: DetectionKind, name: &str) -> sqlx::Result<Uuid>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar(
        "INSERT INTO detection (kind, name) VALUES ($1, $2) \
         ON CONFLICT (kind, name) DO UPDATE SET name = EXCLUDED.name \
         RETURNING id",
    )
    .bind(kind)
    .bind(name)
    .fetch_one(executor)
    .await
}

/// Mirrors `src-tauri`'s `upsert_detection_detects_indicator` verbatim
/// (see `upsert_indicator`'s doc comment for why this isn't shared code).
#[allow(clippy::too_many_arguments)]
async fn upsert_detection_detects_indicator<'e, E>(
    executor: E,
    detection_id: Uuid,
    indicator_id: Uuid,
    source: &str,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO detection_detects_indicator \
            (detection_id, indicator_id, source, confidence, first_seen, last_seen) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (detection_id, indicator_id, source) DO UPDATE SET \
            confidence = EXCLUDED.confidence, \
            first_seen = LEAST(detection_detects_indicator.first_seen, EXCLUDED.first_seen), \
            last_seen = GREATEST(detection_detects_indicator.last_seen, EXCLUDED.last_seen)",
    )
    .bind(detection_id)
    .bind(indicator_id)
    .bind(source)
    .bind(confidence)
    .bind(first_seen)
    .bind(last_seen)
    .execute(executor)
    .await?;
    Ok(())
}

/// New edge this PR introduces (`src-tauri/migrations/
/// 0005_host_sighted_indicator.sql`). Carries `detection_id` as part of
/// the row and the conflict target, not just `indicator_id`: the four
/// upserts here otherwise record "host H saw indicator X" and
/// "detection R flags indicator X" as two independent facts, losing
/// exactly which detection this particular host's sighting went through
/// -- unrecoverable if two hosts report the same indicator via two
/// different rules. `ruleset_fingerprint` is part of the conflict target
/// too: the same host reporting the same indicator+detection again under
/// a materially different ruleset creates a new row rather than silently
/// merging into (and losing the provenance of) an earlier one. `path`
/// only advances when the incoming observation is at least as recent as
/// what's already stored, so an out-of-order report can't regress "where
/// it was last seen" to a stale path while `last_seen` itself still
/// (correctly) only ever advances.
#[allow(clippy::too_many_arguments)]
async fn upsert_host_sighted_indicator<'e, E>(
    executor: E,
    host_id: Uuid,
    detection_id: Uuid,
    indicator_id: Uuid,
    source: &str,
    confidence: i16,
    path: Option<&str>,
    ruleset_fingerprint: &str,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO host_sighted_indicator \
            (host_id, detection_id, indicator_id, source, confidence, path, \
             ruleset_fingerprint, first_seen, last_seen) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (host_id, detection_id, indicator_id, source, ruleset_fingerprint) \
         DO UPDATE SET \
            confidence = EXCLUDED.confidence, \
            path = CASE WHEN EXCLUDED.last_seen >= host_sighted_indicator.last_seen \
                        THEN EXCLUDED.path ELSE host_sighted_indicator.path END, \
            first_seen = LEAST(host_sighted_indicator.first_seen, EXCLUDED.first_seen), \
            last_seen = GREATEST(host_sighted_indicator.last_seen, EXCLUDED.last_seen)",
    )
    .bind(host_id)
    .bind(detection_id)
    .bind(indicator_id)
    .bind(source)
    .bind(confidence)
    .bind(path)
    .bind(ruleset_fingerprint)
    .bind(first_seen)
    .bind(last_seen)
    .execute(executor)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::YARA_SIGHTING_SOURCE;
    use crate::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::{DateTime, Duration, SubsecRound, Utc};
    use http_body_util::BodyExt;
    use sqlx::Row;
    use tower::ServiceExt;
    use uuid::Uuid;

    const BOOTSTRAP_SECRET: &str = "test-bootstrap-secret";
    const OPERATOR_SECRET: &str = "test-operator-secret";
    const CSRF_TOKEN: &str = "test-csrf-token";

    // truncate_to_limit itself is unit-tested in pagination.rs, shared by
    // this file and sample.rs.

    fn valid_sha256(seed: &str) -> String {
        format!("{seed:0<64}")
    }

    fn valid_fingerprint(seed: &str) -> String {
        format!("{seed:0<64}")
    }

    async fn test_state() -> AppState {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = nsic_core::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");
        AppState {
            pool,
            bootstrap_secret: BOOTSTRAP_SECRET.to_string(),
            operator_secret: OPERATOR_SECRET.to_string(),
            csrf_token: CSRF_TOKEN.to_string(),
            scan_staleness_threshold: chrono::Duration::hours(24),
        }
    }

    async fn enroll(app: &axum::Router) -> nsic_core::proto::EnrollResponse {
        let body = serde_json::json!({
            "hostname": "test-host",
            "os": "linux",
            "agent_version": "0.1.0-test",
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agents/enroll")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {BOOTSTRAP_SECRET}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn sighting_request_full(
        host_id: Uuid,
        bearer: Option<&str>,
        sha256: &str,
        detection_name: &str,
        ruleset_fingerprint: &str,
        path: Option<&str>,
        observed_at: DateTime<Utc>,
    ) -> Request<Body> {
        let body = serde_json::json!({
            "sha256": sha256,
            "detection_name": detection_name,
            "ruleset_fingerprint": ruleset_fingerprint,
            "path": path,
            "observed_at": observed_at.to_rfc3339(),
        });
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/agents/{host_id}/sightings"))
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn sighting_request(
        host_id: Uuid,
        bearer: Option<&str>,
        sha256: &str,
        observed_at: DateTime<Utc>,
    ) -> Request<Body> {
        sighting_request_full(
            host_id,
            bearer,
            sha256,
            "Example_EICAR_Test_File",
            &valid_fingerprint("f"),
            Some("/tmp/eicar.txt"),
            observed_at,
        )
    }

    #[tokio::test]
    #[ignore]
    async fn report_sighting_rejects_missing_credential() {
        let state = test_state().await;
        let app = crate::build_router(state);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(sighting_request(
                enrolled.host_id,
                None,
                &valid_sha256("a"),
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn report_sighting_rejects_forged_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(sighting_request(
                enrolled.host_id,
                Some("forged-credential"),
                &valid_sha256("a"),
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn report_sighting_rejects_unknown_host_id() {
        let app = crate::build_router(test_state().await);

        let response = app
            .oneshot(sighting_request(
                Uuid::new_v4(),
                Some("anything"),
                &valid_sha256("a"),
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn report_sighting_rejects_malformed_sha256() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(sighting_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                "banana",
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore]
    async fn report_sighting_rejects_uppercase_sha256() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(sighting_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                &valid_sha256("A"),
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore]
    async fn report_sighting_rejects_empty_detection_name() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(sighting_request_full(
                enrolled.host_id,
                Some(&enrolled.credential),
                &valid_sha256("a"),
                "",
                &valid_fingerprint("f"),
                Some("/tmp/eicar.txt"),
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore]
    async fn report_sighting_rejects_observed_at_too_far_in_future() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(sighting_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                &valid_sha256("a"),
                Utc::now() + Duration::days(1),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore]
    async fn report_sighting_rejects_observed_at_before_earliest_plausible() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(sighting_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                &valid_sha256("a"),
                DateTime::UNIX_EPOCH,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// The full happy path plus the idempotency/timestamp semantics this
    /// endpoint promises: submitting the same (host, indicator, source,
    /// ruleset_fingerprint) sighting twice does not create a second edge
    /// row, extends last_seen to the later observation, and leaves
    /// first_seen at the earlier one -- exactly the LEAST/GREATEST upsert
    /// pattern every other edge in the graph already uses.
    #[tokio::test]
    #[ignore]
    async fn report_sighting_creates_graph_and_is_idempotent() {
        let state = test_state().await;
        let pool = state.pool.clone();
        let app = crate::build_router(state);
        let enrolled = enroll(&app).await;

        let sha256 = valid_sha256("51191171190");
        // Postgres TIMESTAMPTZ has microsecond precision; chrono's Utc::now()
        // has nanosecond precision. Truncate before comparing, or the
        // round-tripped value read back from the database never exactly
        // equals the in-memory one submitted. Both timestamps stay in the
        // past (not `first_seen + Duration::hours(2)`, which would land in
        // the future and trip the observed_at future-skew check).
        let first_seen = (Utc::now() - Duration::hours(2)).trunc_subsecs(6);
        let response = app
            .clone()
            .oneshot(sighting_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                &sha256,
                first_seen,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let first: nsic_core::proto::SightingResponse = serde_json::from_slice(&bytes).unwrap();

        let row = sqlx::query(
            "SELECT confidence, first_seen, last_seen, path FROM host_sighted_indicator \
             WHERE host_id = $1 AND indicator_id = $2 AND source = $3",
        )
        .bind(enrolled.host_id)
        .bind(first.indicator_id)
        .bind(YARA_SIGHTING_SOURCE)
        .fetch_one(&pool)
        .await
        .expect("sighting edge exists after first submission");
        let confidence: i16 = row.get("confidence");
        let stored_first_seen: DateTime<Utc> = row.get("first_seen");
        let stored_last_seen: DateTime<Utc> = row.get("last_seen");
        let stored_path: Option<String> = row.get("path");
        assert_eq!(confidence, 65);
        assert_eq!(stored_first_seen, first_seen);
        assert_eq!(stored_last_seen, first_seen);
        assert_eq!(stored_path.as_deref(), Some("/tmp/eicar.txt"));

        let detection_edge_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM detection_detects_indicator WHERE indicator_id = $1 AND source = $2",
        )
        .bind(first.indicator_id)
        .bind(YARA_SIGHTING_SOURCE)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            detection_edge_count, 1,
            "sighting submission should also populate detection_detects_indicator"
        );

        // Resubmit the same sighting, observed an hour later (still in the
        // past: first_seen was 2h ago, this is 1h ago).
        let last_seen = first_seen + Duration::hours(1);
        let response = app
            .clone()
            .oneshot(sighting_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                &sha256,
                last_seen,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let second: nsic_core::proto::SightingResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            second.indicator_id, first.indicator_id,
            "the same sha256 should resolve to the same indicator, not a duplicate"
        );

        let edge_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM host_sighted_indicator WHERE host_id = $1 AND indicator_id = $2",
        )
        .bind(enrolled.host_id)
        .bind(first.indicator_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            edge_count, 1,
            "resubmission must not create a second edge row"
        );

        let row = sqlx::query(
            "SELECT first_seen, last_seen FROM host_sighted_indicator \
             WHERE host_id = $1 AND indicator_id = $2 AND source = $3",
        )
        .bind(enrolled.host_id)
        .bind(first.indicator_id)
        .bind(YARA_SIGHTING_SOURCE)
        .fetch_one(&pool)
        .await
        .unwrap();
        let stored_first_seen: DateTime<Utc> = row.get("first_seen");
        let stored_last_seen: DateTime<Utc> = row.get("last_seen");
        assert_eq!(
            stored_first_seen, first_seen,
            "first_seen should stay at the earlier observation"
        );
        assert_eq!(
            stored_last_seen, last_seen,
            "last_seen should advance to the later observation"
        );
    }

    /// The same (host, indicator, source) observed under two different
    /// ruleset fingerprints must produce two distinct edge rows, not one
    /// merged/overwritten row -- otherwise the fact that an earlier
    /// sighting was produced by a since-edited rule becomes
    /// unreconstructable.
    #[tokio::test]
    #[ignore]
    async fn report_sighting_with_different_ruleset_fingerprint_creates_separate_edge() {
        let state = test_state().await;
        let pool = state.pool.clone();
        let app = crate::build_router(state);
        let enrolled = enroll(&app).await;

        let sha256 = valid_sha256("522111991190");
        let fingerprint_a = valid_fingerprint("aaaa");
        let fingerprint_b = valid_fingerprint("bbbb");

        for fingerprint in [&fingerprint_a, &fingerprint_b] {
            let response = app
                .clone()
                .oneshot(sighting_request_full(
                    enrolled.host_id,
                    Some(&enrolled.credential),
                    &sha256,
                    "Example_EICAR_Test_File",
                    fingerprint,
                    Some("/tmp/eicar.txt"),
                    Utc::now().trunc_subsecs(6),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let indicator_id: Uuid =
            sqlx::query_scalar("SELECT id FROM indicator WHERE kind = 'sha256' AND value = $1")
                .bind(&sha256)
                .fetch_one(&pool)
                .await
                .unwrap();
        let edge_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM host_sighted_indicator WHERE host_id = $1 AND indicator_id = $2",
        )
        .bind(enrolled.host_id)
        .bind(indicator_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            edge_count, 2,
            "two materially different rulesets should leave two distinct sighting rows"
        );
    }

    /// Two different hosts matching the same hash through two different
    /// rules must remain distinguishable: host A saw indicator X via rule
    /// Alpha, host B saw the same indicator X via rule Beta. Before
    /// detection_id was part of host_sighted_indicator, the graph could
    /// only reconstruct "A saw X" and "B saw X" plus "Alpha detects X" and
    /// "Beta detects X" -- not which host matched which rule.
    #[tokio::test]
    #[ignore]
    async fn report_sighting_preserves_which_rule_each_host_saw() {
        let state = test_state().await;
        let pool = state.pool.clone();
        let app = crate::build_router(state);
        let host_a = enroll(&app).await;
        let host_b = enroll(&app).await;

        let sha256 = valid_sha256("a17e1000a1e1000");
        let fingerprint = valid_fingerprint("f");
        let now = Utc::now().trunc_subsecs(6);

        let response = app
            .clone()
            .oneshot(sighting_request_full(
                host_a.host_id,
                Some(&host_a.credential),
                &sha256,
                "Alpha",
                &fingerprint,
                Some("/tmp/eicar.txt"),
                now,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(sighting_request_full(
                host_b.host_id,
                Some(&host_b.credential),
                &sha256,
                "Beta",
                &fingerprint,
                Some("/tmp/eicar.txt"),
                now,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let indicator_id: Uuid =
            sqlx::query_scalar("SELECT id FROM indicator WHERE kind = 'sha256' AND value = $1")
                .bind(&sha256)
                .fetch_one(&pool)
                .await
                .unwrap();

        let host_a_rule: String = sqlx::query_scalar(
            "SELECT d.name FROM host_sighted_indicator h \
             JOIN detection d ON d.id = h.detection_id \
             WHERE h.host_id = $1 AND h.indicator_id = $2",
        )
        .bind(host_a.host_id)
        .bind(indicator_id)
        .fetch_one(&pool)
        .await
        .expect("host A's sighting row, joined to the rule it actually matched");
        let host_b_rule: String = sqlx::query_scalar(
            "SELECT d.name FROM host_sighted_indicator h \
             JOIN detection d ON d.id = h.detection_id \
             WHERE h.host_id = $1 AND h.indicator_id = $2",
        )
        .bind(host_b.host_id)
        .bind(indicator_id)
        .fetch_one(&pool)
        .await
        .expect("host B's sighting row, joined to the rule it actually matched");

        assert_eq!(
            host_a_rule, "Alpha",
            "host A's sighting must stay tied to the rule it matched"
        );
        assert_eq!(
            host_b_rule, "Beta",
            "host B's sighting must stay tied to the rule it matched"
        );
    }

    /// An out-of-order report (an older observation arriving after a
    /// newer one) must not regress the stored path, even though
    /// first_seen/last_seen still correctly track the full observed
    /// range via LEAST/GREATEST.
    #[tokio::test]
    #[ignore]
    async fn report_sighting_does_not_regress_path_on_stale_observation() {
        let state = test_state().await;
        let pool = state.pool.clone();
        let app = crate::build_router(state);
        let enrolled = enroll(&app).await;

        let sha256 = valid_sha256("70a7104de121190");
        let fingerprint = valid_fingerprint("f");
        let earlier = (Utc::now() - Duration::hours(2)).trunc_subsecs(6);
        let later = (Utc::now() - Duration::hours(1)).trunc_subsecs(6);

        // The later observation, with the new path, arrives first.
        let response = app
            .clone()
            .oneshot(sighting_request_full(
                enrolled.host_id,
                Some(&enrolled.credential),
                &sha256,
                "Example_EICAR_Test_File",
                &fingerprint,
                Some("/new/malware.exe"),
                later,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The earlier observation, with a stale path, arrives second.
        let response = app
            .oneshot(sighting_request_full(
                enrolled.host_id,
                Some(&enrolled.credential),
                &sha256,
                "Example_EICAR_Test_File",
                &fingerprint,
                Some("/old/malware.exe"),
                earlier,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let indicator_id: Uuid =
            sqlx::query_scalar("SELECT id FROM indicator WHERE kind = 'sha256' AND value = $1")
                .bind(&sha256)
                .fetch_one(&pool)
                .await
                .unwrap();
        let row = sqlx::query(
            "SELECT path, first_seen, last_seen FROM host_sighted_indicator \
             WHERE host_id = $1 AND indicator_id = $2 AND source = $3",
        )
        .bind(enrolled.host_id)
        .bind(indicator_id)
        .bind(YARA_SIGHTING_SOURCE)
        .fetch_one(&pool)
        .await
        .unwrap();
        let stored_path: Option<String> = row.get("path");
        let stored_first_seen: DateTime<Utc> = row.get("first_seen");
        let stored_last_seen: DateTime<Utc> = row.get("last_seen");
        assert_eq!(
            stored_path.as_deref(),
            Some("/new/malware.exe"),
            "the stale, out-of-order report must not regress the path"
        );
        assert_eq!(
            stored_first_seen, earlier,
            "first_seen still tracks the earliest observation"
        );
        assert_eq!(
            stored_last_seen, later,
            "last_seen still tracks the latest observation"
        );
    }

    fn list_host_sightings_request(host_id: Uuid, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/hosts/{host_id}/sightings"));
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    fn list_indicator_sightings_request(sha256: &str, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/indicators/{sha256}/sightings"));
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn list_host_sightings_rejects_missing_operator_credential() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(list_host_sightings_request(Uuid::new_v4(), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn list_host_sightings_rejects_wrong_operator_credential() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(list_host_sightings_request(
                Uuid::new_v4(),
                Some("not-the-operator-secret"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A per-agent credential -- valid for that host's own writes -- must
    /// not also authenticate reading fleet-wide sighting data. Without
    /// this, a single compromised agent could read every other host's
    /// sighting history using only its own credential.
    #[tokio::test]
    #[ignore]
    async fn list_host_sightings_rejects_per_agent_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(list_host_sightings_request(
                enrolled.host_id,
                Some(&enrolled.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn list_host_sightings_for_unknown_host_returns_empty_list() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(list_host_sightings_request(
                Uuid::new_v4(),
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let listed: nsic_core::proto::SightingListResponse =
            serde_json::from_slice(&bytes).unwrap();
        assert!(listed.sightings.is_empty());
    }

    /// The full read-path happy path: report a sighting, then list it back
    /// out by host, and check every denormalized field on the response
    /// (hostname, sha256, rule name) matches what was actually reported
    /// rather than trusting the join compiled at all.
    #[tokio::test]
    #[ignore]
    async fn list_host_sightings_returns_reported_sightings() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let sha256 = valid_sha256("11eaf00d1eaf00d");

        let response = app
            .clone()
            .oneshot(sighting_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                &sha256,
                Utc::now().trunc_subsecs(6),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(list_host_sightings_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let listed: nsic_core::proto::SightingListResponse =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(listed.sightings.len(), 1);
        let view = &listed.sightings[0];
        assert_eq!(view.host_id, enrolled.host_id);
        assert_eq!(view.hostname, "test-host");
        assert_eq!(view.sha256, sha256);
        assert_eq!(view.detection_name, "Example_EICAR_Test_File");
        assert_eq!(view.source, YARA_SIGHTING_SOURCE);
        assert_eq!(view.confidence, 65);
        assert_eq!(view.path.as_deref(), Some("/tmp/eicar.txt"));
    }

    #[tokio::test]
    #[ignore]
    async fn list_indicator_sightings_rejects_missing_operator_credential() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(list_indicator_sightings_request(&valid_sha256("a"), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn list_indicator_sightings_rejects_malformed_sha256() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(list_indicator_sightings_request(
                "banana",
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Two different hosts sighting the same hash through two different
    /// rules must both show up when querying by that hash -- the
    /// cross-fleet "who else has seen this" pivot this endpoint exists
    /// for -- each still correctly attributed to the rule it actually
    /// matched.
    #[tokio::test]
    #[ignore]
    async fn list_indicator_sightings_returns_all_hosts_that_saw_it() {
        let app = crate::build_router(test_state().await);
        let host_a = enroll(&app).await;
        let host_b = enroll(&app).await;
        let sha256 = valid_sha256("fee1dead1eaf00d");
        let now = Utc::now().trunc_subsecs(6);

        let response = app
            .clone()
            .oneshot(sighting_request_full(
                host_a.host_id,
                Some(&host_a.credential),
                &sha256,
                "Alpha",
                &valid_fingerprint("f"),
                Some("/tmp/eicar.txt"),
                now,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(sighting_request_full(
                host_b.host_id,
                Some(&host_b.credential),
                &sha256,
                "Beta",
                &valid_fingerprint("f"),
                Some("/tmp/eicar.txt"),
                now,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(list_indicator_sightings_request(
                &sha256,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let listed: nsic_core::proto::SightingListResponse =
            serde_json::from_slice(&bytes).unwrap();

        // Scoped to the two hosts this test actually created, not the
        // response's total length: this sha256 is a fixed seed, and a
        // long-lived console (or this same test suite run twice against a
        // persistent local database, as opposed to a fresh one per CI run)
        // can accumulate other hosts' sightings against it too. Asserting
        // on a bare total count would make the test flaky against data it
        // doesn't own; asserting exactly these two hosts are present and
        // correctly attributed is the actual invariant this test is for.
        let for_host_a: Vec<_> = listed
            .sightings
            .iter()
            .filter(|v| v.host_id == host_a.host_id)
            .collect();
        let for_host_b: Vec<_> = listed
            .sightings
            .iter()
            .filter(|v| v.host_id == host_b.host_id)
            .collect();
        assert_eq!(for_host_a.len(), 1, "expected exactly one row for host A");
        assert_eq!(for_host_b.len(), 1, "expected exactly one row for host B");
        assert_eq!(for_host_a[0].detection_name, "Alpha");
        assert_eq!(for_host_b[0].detection_name, "Beta");
    }

    /// Two sightings for the same host with the exact same `last_seen`
    /// (the only column the original `ORDER BY` sorted on) must still come
    /// back in a stable, repeatable order across separate requests --
    /// `ORDER BY last_seen DESC` alone does not guarantee that for tied
    /// rows, since Postgres is free to return ties in any order absent a
    /// fully-determining sort key. Calls the endpoint twice and asserts
    /// the two responses agree, rather than asserting one specific order:
    /// the tie-break columns are internal ids this test doesn't control,
    /// so "the same every time" is the actual guarantee being tested, not
    /// any particular ordering.
    #[tokio::test]
    #[ignore]
    async fn list_host_sightings_orders_deterministically_when_last_seen_ties() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let tied_at = Utc::now().trunc_subsecs(6);

        for (sha_seed, rule) in [("d0000000e000001", "Rule1"), ("d0000000e000002", "Rule2")] {
            let response = app
                .clone()
                .oneshot(sighting_request_full(
                    enrolled.host_id,
                    Some(&enrolled.credential),
                    &valid_sha256(sha_seed),
                    rule,
                    &valid_fingerprint("f"),
                    Some("/tmp/eicar.txt"),
                    tied_at,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let fetch_order = || {
            let app = app.clone();
            let enrolled_host_id = enrolled.host_id;
            async move {
                let response = app
                    .oneshot(list_host_sightings_request(
                        enrolled_host_id,
                        Some(OPERATOR_SECRET),
                    ))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                let listed: nsic_core::proto::SightingListResponse =
                    serde_json::from_slice(&bytes).unwrap();
                listed
                    .sightings
                    .into_iter()
                    .map(|v| v.detection_name)
                    .collect::<Vec<_>>()
            }
        };

        let first_order = fetch_order().await;
        let second_order = fetch_order().await;
        assert_eq!(
            first_order, second_order,
            "identical last_seen values must not produce a different row order between calls"
        );
    }
}
