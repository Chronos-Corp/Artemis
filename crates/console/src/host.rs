use axum::extract::{Path, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use nsic_core::proto::{
    CredentialRotated, EnrollRequest, EnrollResponse, HeartbeatRequest, HeartbeatResponse,
    HostListResponse, HostView, ScanReport, ScanReportResponse,
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::auth::{
    authenticate_host, authenticate_operator, bearer_token, generate_credential, hash_credential,
    internal_error, secrets_match,
};
use crate::pagination::truncate_to_limit;
use crate::validate::{bad_request, validate_lowercase_sha256, validate_observed_at};
use crate::AppState;

/// Row cap for `list_hosts`, same reasoning and truncated-flag pattern as
/// `sighting.rs`'s `SIGHTING_LIST_LIMIT`. A fleet numbering in the low
/// thousands is still a small page; real pagination is deferred for the
/// same "not a problem yet" reason as the other list endpoints.
const HOST_LIST_LIMIT: i64 = 1000;

/// Stored in `host.credential_hash` for a host whose credential has been
/// explicitly revoked. Not a real SHA-256 hex digest (`hash_credential`
/// always produces exactly 64 lowercase hex characters), so no presented
/// credential can ever hash to this value -- `authenticate_host` rejects
/// every request for this host until an operator rotates in a fresh
/// credential. Distinct from `0004_host_credential.sql`'s
/// `'legacy-host-requires-re-enrollment'` sentinel, which marks a host
/// that never had a real credential minted for it at all -- but
/// `rotate_credential` doesn't care which sentinel (if any) is currently
/// stored, so it recovers a legacy host in place exactly the same way it
/// recovers a revoked one; see that function's doc comment.
pub(crate) const REVOKED_CREDENTIAL_SENTINEL: &str = "revoked-requires-credential-rotation";

/// A response header set on every response that hands back a raw
/// credential (`enroll`, `rotate_credential`): the value is shown exactly
/// once and is never recoverable from the console again, so it must not
/// be retained by an intermediate cache or the browser/HTTP client's own
/// response cache beyond this one delivery.
fn no_store() -> [(axum::http::HeaderName, HeaderValue); 1] {
    [(CACHE_CONTROL, HeaderValue::from_static("no-store"))]
}

/// Enrolls a new host, provided the caller presents the console's
/// bootstrap enrollment secret as a bearer token. On success, mints a
/// fresh per-agent credential, stores only its hash, and returns the raw
/// credential exactly once -- the agent is responsible for keeping it.
pub async fn enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let presented = bearer_token(&headers).ok_or((
        StatusCode::UNAUTHORIZED,
        "missing bootstrap enrollment credential".to_string(),
    ))?;
    if !secrets_match(presented, &state.bootstrap_secret) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid bootstrap enrollment credential".to_string(),
        ));
    }

    let credential = generate_credential();
    let credential_hash = hash_credential(&credential);

    let host_id: Uuid = sqlx::query_scalar(
        "INSERT INTO host (hostname, os, agent_version, credential_hash) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&req.hostname)
    .bind(&req.os)
    .bind(&req.agent_version)
    .bind(&credential_hash)
    .fetch_one(&state.pool)
    .await
    .map_err(internal_error)?;

    Ok((
        no_store(),
        Json(EnrollResponse {
            host_id,
            credential,
        }),
    ))
}

/// Records a heartbeat for an already-enrolled host, provided the caller
/// presents that host's own per-agent credential. Unknown host id and
/// wrong credential both come back as the same 401, so this endpoint
/// can't be used to enumerate valid host ids.
pub async fn heartbeat(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, String)> {
    authenticate_host(&state.pool, host_id, &headers).await?;

    let now = Utc::now();
    sqlx::query("UPDATE host SET last_heartbeat_at = $1, agent_version = $2 WHERE id = $3")
        .bind(now)
        .bind(&req.agent_version)
        .bind(host_id)
        .execute(&state.pool)
        .await
        .map_err(internal_error)?;

    Ok(Json(HeartbeatResponse { received_at: now }))
}

/// Records that this host attempted a scan, independent of whether
/// anything matched -- the sensor-health signal a sighting alone can't
/// provide (see [`nsic_core::proto::ScanReport`]'s doc comment). Per-agent
/// credential, same as heartbeat; overwrites the four `last_scan_*`
/// columns unconditionally, the same plain "most recent snapshot"
/// semantics `heartbeat` already has for `last_heartbeat_at` -- not the
/// `GREATEST`-guarded accumulation `host_sighted_indicator` uses, since
/// there's no first-seen/last-seen range being tracked here, just "when
/// did this host last check in with this coverage."
pub async fn report_scan(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<ScanReport>,
) -> Result<Json<ScanReportResponse>, (StatusCode, String)> {
    authenticate_host(&state.pool, host_id, &headers).await?;
    validate_scan_report(&req)?;

    let received_at = Utc::now();
    sqlx::query(
        "UPDATE host SET last_scan_at = $1, last_scan_rule_count = $2, \
                last_scan_ruleset_fingerprint = $3, last_scan_matched_count = $4 \
         WHERE id = $5",
    )
    .bind(req.scanned_at)
    .bind(req.rule_count)
    .bind(&req.ruleset_fingerprint)
    .bind(req.matched_count)
    .bind(host_id)
    .execute(&state.pool)
    .await
    .map_err(internal_error)?;

    Ok(Json(ScanReportResponse { received_at }))
}

/// Authentication proves which agent sent a request, not that the agent
/// is bug-free or uncompromised -- the same reasoning
/// `sighting::validate_sighting_request` already applies to sighting
/// reports applies here.
fn validate_scan_report(req: &ScanReport) -> Result<(), (StatusCode, String)> {
    validate_lowercase_sha256(&req.ruleset_fingerprint, "ruleset_fingerprint")?;
    if req.rule_count < 0 {
        return Err(bad_request("rule_count must not be negative"));
    }
    if req.matched_count < 0 {
        return Err(bad_request("matched_count must not be negative"));
    }
    validate_observed_at(req.scanned_at, "scanned_at")?;
    Ok(())
}

/// Lists every enrolled host -- the fleet directory that's been a
/// documented gap since PR #7 ("no way to discover valid host_ids
/// through the API at all"). Operator-credential only, same as every
/// other fleet-wide read. Ordered by hostname so the list is stable and
/// legible rather than insertion-ordered.
pub async fn list_hosts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<HostListResponse>, (StatusCode, String)> {
    authenticate_operator(&state.operator_secret, &headers)?;

    let (hosts, truncated) = fetch_all_hosts(&state.pool).await.map_err(internal_error)?;
    Ok(Json(HostListResponse { hosts, truncated }))
}

/// Looks up a single host by id. Operator-credential only. `404` for an
/// unknown id, the same "operator already privileged, nothing to hide"
/// reasoning `create_sample_request` and `set_host_credential` already
/// apply to their own unknown-`host_id` cases.
pub async fn get_host(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<HostView>, (StatusCode, String)> {
    authenticate_operator(&state.operator_secret, &headers)?;

    let host = fetch_host(&state.pool, host_id)
        .await
        .map_err(internal_error)?;
    host.map(Json)
        .ok_or((StatusCode::NOT_FOUND, "unknown host_id".to_string()))
}

/// Shared by `list_hosts` (JSON API) and the fleet UI's host directory
/// page (`crates/console/src/ui.rs`), so both render from one query
/// instead of the SQL drifting between a JSON response and an HTML page
/// that happen to want the same rows.
pub(crate) async fn fetch_all_hosts(pool: &PgPool) -> sqlx::Result<(Vec<HostView>, bool)> {
    let mut rows = sqlx::query(
        "SELECT id, hostname, os, agent_version, enrolled_at, last_heartbeat_at, \
                last_scan_at, last_scan_rule_count, last_scan_ruleset_fingerprint, \
                last_scan_matched_count \
         FROM host ORDER BY hostname, id LIMIT $1",
    )
    .bind(HOST_LIST_LIMIT + 1)
    .fetch_all(pool)
    .await?;

    let truncated = truncate_to_limit(&mut rows, HOST_LIST_LIMIT as usize);
    Ok((
        rows.into_iter().map(host_view_from_row).collect(),
        truncated,
    ))
}

/// Shared by `get_host` (JSON API) and the fleet UI's host detail page.
pub(crate) async fn fetch_host(pool: &PgPool, host_id: Uuid) -> sqlx::Result<Option<HostView>> {
    let row = sqlx::query(
        "SELECT id, hostname, os, agent_version, enrolled_at, last_heartbeat_at, \
                last_scan_at, last_scan_rule_count, last_scan_ruleset_fingerprint, \
                last_scan_matched_count \
         FROM host WHERE id = $1",
    )
    .bind(host_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(host_view_from_row))
}

fn host_view_from_row(row: sqlx::postgres::PgRow) -> HostView {
    HostView {
        id: row.get("id"),
        hostname: row.get("hostname"),
        os: row.get("os"),
        agent_version: row.get("agent_version"),
        enrolled_at: row.get("enrolled_at"),
        last_heartbeat_at: row.get("last_heartbeat_at"),
        last_scan_at: row.get("last_scan_at"),
        last_scan_rule_count: row.get("last_scan_rule_count"),
        last_scan_ruleset_fingerprint: row.get("last_scan_ruleset_fingerprint"),
        last_scan_matched_count: row.get("last_scan_matched_count"),
    }
}

/// Mints a fresh per-agent credential for an already-enrolled host and
/// stores only its hash, the same shown-once contract `enroll` uses --
/// overwriting `credential_hash` means whatever credential the host was
/// using before this call, including a legitimate one, immediately stops
/// authenticating. Operator-credential gated: an analyst responding to a
/// suspected-compromised host does this, not the host itself (a host that
/// could rotate its own credential could also use that to shrug off a
/// revocation -- see `revoke_credential`). The host's id, enrollment
/// history, and every sighting/sample-request it's associated with are
/// untouched; only the credential changes.
///
/// This also recovers a host stuck on either sentinel value
/// (`REVOKED_CREDENTIAL_SENTINEL`, or `0004_host_credential.sql`'s
/// legacy `'legacy-host-requires-re-enrollment'`) in place: the `UPDATE`
/// below doesn't inspect the current `credential_hash` value before
/// overwriting it, so it works identically regardless of what was there
/// before. Re-enrolling under a brand-new host id is still the only way
/// to recover a legacy host's *original* enrollment record if that
/// matters, but it is not the only way to give one a working credential.
pub async fn rotate_credential(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authenticate_operator(&state.operator_secret, &headers)?;

    let credential = generate_credential();
    let credential_hash = hash_credential(&credential);
    set_host_credential(&state, host_id, &credential_hash, "rotated").await?;

    Ok((no_store(), Json(CredentialRotated { credential })))
}

/// Blocks all subsequent authentication attempts for a host without
/// issuing a new credential, for decommissioning or an in-progress
/// compromise where an operator wants a suspected-compromised host
/// stopped now and doesn't yet want to hand it anything usable. This
/// changes what `authenticate_host` will accept going forward; it has no
/// effect on a request that already passed that check before this call
/// completed; there is no in-flight-request cancellation here or
/// anywhere else in this API. Recoverable in place via
/// `rotate_credential` later -- unlike deleting the `host` row outright,
/// this doesn't discard the host's sighting/sample-request audit trail to
/// achieve the same lockout. Operator-credential gated, same reasoning as
/// `rotate_credential`.
pub async fn revoke_credential(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    authenticate_operator(&state.operator_secret, &headers)?;

    set_host_credential(&state, host_id, REVOKED_CREDENTIAL_SENTINEL, "revoked").await?;

    Ok(StatusCode::OK)
}

/// Shared by `rotate_credential` and `revoke_credential`: both overwrite
/// `credential_hash` (differing only in what value they write -- a real
/// hash vs. a sentinel that can never match one) and append a row to
/// `host_credential_event` recording which of the two just happened.
/// Deliberately an append-only log rather than a single "last changed"
/// column on `host`: overwriting one timestamp on every call would lose
/// the fact and timing of every event but the most recent, which for a
/// design built around preserving an audit trail (locked architecture
/// decision #3) is exactly the provenance this feature exists to keep.
/// Both writes happen in one transaction so a crash between them can't
/// leave a credential change with no corresponding event, or vice versa.
///
/// A single `UPDATE ... WHERE id = $1` can't distinguish "no such host"
/// from "host exists, nothing changed," so existence is checked via
/// `rows_affected` and reported as 404 -- the same "operator already
/// privileged, no existence to hide" reasoning `create_sample_request`
/// already applies to its own unknown-`host_id` case, unlike the
/// deliberately existence-hiding 401s on agent-facing endpoints like
/// `heartbeat`.
pub(crate) async fn set_host_credential(
    state: &AppState,
    host_id: Uuid,
    new_credential_hash: &str,
    event_type: &str,
) -> Result<(), (StatusCode, String)> {
    let mut tx = state.pool.begin().await.map_err(internal_error)?;

    let rows_affected = sqlx::query("UPDATE host SET credential_hash = $1 WHERE id = $2")
        .bind(new_credential_hash)
        .bind(host_id)
        .execute(&mut *tx)
        .await
        .map_err(internal_error)?
        .rows_affected();

    if rows_affected == 0 {
        return Err((StatusCode::NOT_FOUND, "unknown host_id".to_string()));
    }

    sqlx::query("INSERT INTO host_credential_event (host_id, event_type) VALUES ($1, $2)")
        .bind(host_id)
        .bind(event_type)
        .execute(&mut *tx)
        .await
        .map_err(internal_error)?;

    tx.commit().await.map_err(internal_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const BOOTSTRAP_SECRET: &str = "test-bootstrap-secret";
    const OPERATOR_SECRET: &str = "test-operator-secret";
    const CSRF_TOKEN: &str = "test-csrf-token";

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
        }
    }

    fn enroll_request(bearer: Option<&str>) -> Request<Body> {
        let body = serde_json::json!({
            "hostname": "test-host",
            "os": "linux",
            "agent_version": "0.1.0-test",
        });
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/v1/agents/enroll")
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn heartbeat_request(host_id: uuid::Uuid, bearer: Option<&str>) -> Request<Body> {
        let body = serde_json::json!({ "agent_version": "0.1.0-test" });
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/agents/{host_id}/heartbeat"))
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn valid_fingerprint(seed: &str) -> String {
        format!("{seed:0<64}")
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_report_request(
        host_id: uuid::Uuid,
        bearer: Option<&str>,
        rule_count: i32,
        ruleset_fingerprint: &str,
        matched_count: i32,
        scanned_at: chrono::DateTime<chrono::Utc>,
    ) -> Request<Body> {
        let body = serde_json::json!({
            "rule_count": rule_count,
            "ruleset_fingerprint": ruleset_fingerprint,
            "matched_count": matched_count,
            "scanned_at": scanned_at.to_rfc3339(),
        });
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/agents/{host_id}/scans"))
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn rotate_credential_request(host_id: uuid::Uuid, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/hosts/{host_id}/credential/rotate"));
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    fn revoke_credential_request(host_id: uuid::Uuid, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/hosts/{host_id}/credential/revoke"));
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    async fn enroll(app: &axum::Router) -> nsic_core::proto::EnrollResponse {
        let response = app
            .clone()
            .oneshot(enroll_request(Some(BOOTSTRAP_SECRET)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Full happy path: enroll with the correct bootstrap secret, then
    /// heartbeat with the credential that enrollment returned.
    #[tokio::test]
    #[ignore]
    async fn enroll_then_heartbeat_round_trip() {
        let app = crate::build_router(test_state().await);

        let response = app
            .clone()
            .oneshot(enroll_request(Some(BOOTSTRAP_SECRET)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let enrolled: nsic_core::proto::EnrollResponse = serde_json::from_slice(&bytes).unwrap();

        let response = app
            .oneshot(heartbeat_request(
                enrolled.host_id,
                Some(&enrolled.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[ignore]
    async fn enroll_rejects_missing_bootstrap_secret() {
        let app = crate::build_router(test_state().await);
        let response = app.oneshot(enroll_request(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn enroll_rejects_wrong_bootstrap_secret() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(enroll_request(Some("not-the-secret")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn heartbeat_rejects_forged_credential() {
        let app = crate::build_router(test_state().await);

        let response = app
            .clone()
            .oneshot(enroll_request(Some(BOOTSTRAP_SECRET)))
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let enrolled: nsic_core::proto::EnrollResponse = serde_json::from_slice(&bytes).unwrap();

        let response = app
            .oneshot(heartbeat_request(
                enrolled.host_id,
                Some("forged-credential"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn heartbeat_rejects_missing_credential() {
        let app = crate::build_router(test_state().await);

        let response = app
            .clone()
            .oneshot(enroll_request(Some(BOOTSTRAP_SECRET)))
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let enrolled: nsic_core::proto::EnrollResponse = serde_json::from_slice(&bytes).unwrap();

        let response = app
            .oneshot(heartbeat_request(enrolled.host_id, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A credential from one host must not authenticate a heartbeat for a
    /// different host id -- the credential is checked against the
    /// specific host_id in the path, not just "is this any valid credential".
    #[tokio::test]
    #[ignore]
    async fn heartbeat_rejects_credential_for_different_host() {
        let app = crate::build_router(test_state().await);

        let response = app
            .clone()
            .oneshot(enroll_request(Some(BOOTSTRAP_SECRET)))
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let host_a: nsic_core::proto::EnrollResponse = serde_json::from_slice(&bytes).unwrap();

        let response = app
            .clone()
            .oneshot(enroll_request(Some(BOOTSTRAP_SECRET)))
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let host_b: nsic_core::proto::EnrollResponse = serde_json::from_slice(&bytes).unwrap();

        // host_a's credential presented against host_b's id.
        let response = app
            .oneshot(heartbeat_request(host_b.host_id, Some(&host_a.credential)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn heartbeat_rejects_unknown_host_id() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(heartbeat_request(uuid::Uuid::new_v4(), Some("anything")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Full happy path: rotating a credential returns a new one that
    /// authenticates a heartbeat, and the old one, which worked a moment
    /// earlier, no longer does.
    #[tokio::test]
    #[ignore]
    async fn rotate_credential_replaces_old_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .clone()
            .oneshot(rotate_credential_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let rotated: nsic_core::proto::CredentialRotated = serde_json::from_slice(&bytes).unwrap();
        assert_ne!(rotated.credential, enrolled.credential);

        let response = app
            .clone()
            .oneshot(heartbeat_request(
                enrolled.host_id,
                Some(&enrolled.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(heartbeat_request(
                enrolled.host_id,
                Some(&rotated.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Rotating twice keeps only the most recent credential valid -- the
    /// credential from the first rotation stops working once the second
    /// rotation lands, the same "last write wins" property enrollment vs.
    /// heartbeat already has for a single credential.
    #[tokio::test]
    #[ignore]
    async fn rotate_credential_twice_only_the_latest_works() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .clone()
            .oneshot(rotate_credential_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let first_rotation: nsic_core::proto::CredentialRotated =
            serde_json::from_slice(&bytes).unwrap();

        let response = app
            .clone()
            .oneshot(rotate_credential_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let second_rotation: nsic_core::proto::CredentialRotated =
            serde_json::from_slice(&bytes).unwrap();
        assert_ne!(first_rotation.credential, second_rotation.credential);

        let response = app
            .clone()
            .oneshot(heartbeat_request(
                enrolled.host_id,
                Some(&first_rotation.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(heartbeat_request(
                enrolled.host_id,
                Some(&second_rotation.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[ignore]
    async fn rotate_credential_rejects_missing_operator_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(rotate_credential_request(enrolled.host_id, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn rotate_credential_rejects_wrong_operator_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(rotate_credential_request(
                enrolled.host_id,
                Some("not-the-operator-secret"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A host's own per-agent credential must not authorize rotating its
    /// own (or any other host's) credential -- rotation is an analyst
    /// action, the same operator-vs-agent separation every other
    /// operator-only endpoint already enforces.
    #[tokio::test]
    #[ignore]
    async fn rotate_credential_rejects_per_agent_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(rotate_credential_request(
                enrolled.host_id,
                Some(&enrolled.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn rotate_credential_rejects_unknown_host_id() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(rotate_credential_request(
                uuid::Uuid::new_v4(),
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Full happy path: revoking a credential locks the host out even
    /// though its original, still-otherwise-valid credential hasn't
    /// changed on the agent's end -- the console-side hash is what moved.
    #[tokio::test]
    #[ignore]
    async fn revoke_credential_locks_out_the_existing_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .clone()
            .oneshot(heartbeat_request(
                enrolled.host_id,
                Some(&enrolled.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(revoke_credential_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(heartbeat_request(
                enrolled.host_id,
                Some(&enrolled.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A revoked host isn't gone for good: rotating afterward hands it a
    /// fresh, working credential without needing to re-enroll (and
    /// without losing its host id or history) -- the whole point of
    /// revoke-then-rotate over deleting the host row outright.
    #[tokio::test]
    #[ignore]
    async fn revoke_then_rotate_recovers_the_host() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .clone()
            .oneshot(revoke_credential_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(rotate_credential_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let rotated: nsic_core::proto::CredentialRotated = serde_json::from_slice(&bytes).unwrap();

        let response = app
            .oneshot(heartbeat_request(
                enrolled.host_id,
                Some(&rotated.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[ignore]
    async fn revoke_credential_rejects_missing_operator_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(revoke_credential_request(enrolled.host_id, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn revoke_credential_rejects_wrong_operator_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(revoke_credential_request(
                enrolled.host_id,
                Some("not-the-operator-secret"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn revoke_credential_rejects_per_agent_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(revoke_credential_request(
                enrolled.host_id,
                Some(&enrolled.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn revoke_credential_rejects_unknown_host_id() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(revoke_credential_request(
                uuid::Uuid::new_v4(),
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// A different host's credential must not be affected by rotating or
    /// revoking this one -- both operations are scoped to the `host_id`
    /// in the path, not global.
    #[tokio::test]
    #[ignore]
    async fn rotate_credential_does_not_affect_a_different_host() {
        let app = crate::build_router(test_state().await);
        let host_a = enroll(&app).await;
        let host_b = enroll(&app).await;

        let response = app
            .clone()
            .oneshot(rotate_credential_request(
                host_a.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(heartbeat_request(host_b.host_id, Some(&host_b.credential)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The regression this PR's review round exists to fix: a single
    /// "last changed" column on `host` would leave only the most recent
    /// of these three events. Revoke, then rotate, then rotate again must
    /// all persist as separate rows in `host_credential_event`, not
    /// collapse into one.
    #[tokio::test]
    #[ignore]
    async fn credential_events_accumulate_instead_of_being_overwritten() {
        let state = test_state().await;
        let app = crate::build_router(state.clone());
        let enrolled = enroll(&app).await;

        let response = app
            .clone()
            .oneshot(revoke_credential_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(rotate_credential_request(
                    enrolled.host_id,
                    Some(OPERATOR_SECRET),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let events: Vec<String> = sqlx::query_scalar(
            "SELECT event_type FROM host_credential_event WHERE host_id = $1 ORDER BY occurred_at ASC",
        )
        .bind(enrolled.host_id)
        .fetch_all(&state.pool)
        .await
        .unwrap();
        assert_eq!(events, vec!["revoked", "rotated", "rotated"]);
    }

    /// `rotate_credential` doesn't inspect the current `credential_hash`
    /// value before overwriting it, so it recovers a host stuck on the
    /// PR #4 legacy sentinel (`'legacy-host-requires-re-enrollment'`,
    /// from a host enrolled before per-agent credentials existed) exactly
    /// the same way it recovers a `REVOKED_CREDENTIAL_SENTINEL` host --
    /// in place, keeping the same host id, rather than requiring
    /// re-enrollment under a new one.
    #[tokio::test]
    #[ignore]
    async fn rotate_credential_recovers_a_legacy_sentinel_host_in_place() {
        let state = test_state().await;
        let app = crate::build_router(state.clone());

        let host_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO host (hostname, os, agent_version, credential_hash) \
             VALUES ('legacy-host', 'linux', '0.0.1', 'legacy-host-requires-re-enrollment') \
             RETURNING id",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();

        let response = app
            .clone()
            .oneshot(rotate_credential_request(host_id, Some(OPERATOR_SECRET)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let rotated: nsic_core::proto::CredentialRotated = serde_json::from_slice(&bytes).unwrap();

        let response = app
            .oneshot(heartbeat_request(host_id, Some(&rotated.credential)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Both endpoints hand back a raw, shown-once credential (`enroll`'s
    /// and `rotate_credential`'s) -- neither response may be retained by
    /// an intermediate cache or client-side response cache beyond this
    /// one delivery.
    #[tokio::test]
    #[ignore]
    async fn enroll_and_rotate_credential_responses_are_not_cacheable() {
        let app = crate::build_router(test_state().await);

        let response = app
            .clone()
            .oneshot(enroll_request(Some(BOOTSTRAP_SECRET)))
            .await
            .unwrap();
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let enrolled: nsic_core::proto::EnrollResponse = serde_json::from_slice(&bytes).unwrap();

        let response = app
            .oneshot(rotate_credential_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }

    fn list_hosts_request(bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("GET").uri("/api/v1/hosts");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    fn get_host_request(host_id: uuid::Uuid, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/hosts/{host_id}"));
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn list_hosts_rejects_missing_operator_credential() {
        let app = crate::build_router(test_state().await);
        let response = app.oneshot(list_hosts_request(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn list_hosts_rejects_per_agent_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(list_hosts_request(Some(&enrolled.credential)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The fleet directory: a host enrolled in this test must actually
    /// show up, with every field matching what enrollment reported --
    /// this is the endpoint that's been a documented gap since PR #7
    /// ("no way to discover valid host_ids through the API"), so the
    /// happy path is worth checking field-by-field rather than just
    /// asserting a non-empty list.
    #[tokio::test]
    #[ignore]
    async fn list_hosts_returns_enrolled_hosts() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(list_hosts_request(Some(OPERATOR_SECRET)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let listed: nsic_core::proto::HostListResponse = serde_json::from_slice(&bytes).unwrap();

        let found = listed
            .hosts
            .iter()
            .find(|h| h.id == enrolled.host_id)
            .expect("newly enrolled host appears in the fleet directory");
        assert_eq!(found.hostname, "test-host");
        assert_eq!(found.os, "linux");
        assert_eq!(found.agent_version, "0.1.0-test");
        assert!(found.last_heartbeat_at.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn get_host_rejects_missing_operator_credential() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(get_host_request(uuid::Uuid::new_v4(), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn get_host_returns_404_for_unknown_host_id() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(get_host_request(
                uuid::Uuid::new_v4(),
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[ignore]
    async fn get_host_returns_the_matching_host() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(get_host_request(enrolled.host_id, Some(OPERATOR_SECRET)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let host: nsic_core::proto::HostView = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(host.id, enrolled.host_id);
        assert_eq!(host.hostname, "test-host");
    }

    #[tokio::test]
    #[ignore]
    async fn report_scan_rejects_missing_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(scan_report_request(
                enrolled.host_id,
                None,
                3,
                &valid_fingerprint("f"),
                0,
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn report_scan_rejects_forged_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(scan_report_request(
                enrolled.host_id,
                Some("forged-credential"),
                3,
                &valid_fingerprint("f"),
                0,
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A per-agent credential must not authorize reporting scan coverage
    /// for a *different* host -- same cross-host check every other
    /// per-agent-credentialed endpoint already enforces.
    #[tokio::test]
    #[ignore]
    async fn report_scan_rejects_credential_for_different_host() {
        let app = crate::build_router(test_state().await);
        let host_a = enroll(&app).await;
        let host_b = enroll(&app).await;
        let response = app
            .oneshot(scan_report_request(
                host_b.host_id,
                Some(&host_a.credential),
                3,
                &valid_fingerprint("f"),
                0,
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn report_scan_rejects_malformed_ruleset_fingerprint() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(scan_report_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                3,
                "not-a-fingerprint",
                0,
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore]
    async fn report_scan_rejects_negative_rule_count() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(scan_report_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                -1,
                &valid_fingerprint("f"),
                0,
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore]
    async fn report_scan_rejects_negative_matched_count() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(scan_report_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                3,
                &valid_fingerprint("f"),
                -1,
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore]
    async fn report_scan_rejects_scanned_at_too_far_in_future() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(scan_report_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                3,
                &valid_fingerprint("f"),
                0,
                Utc::now() + chrono::Duration::days(1),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// The full happy path and the actual point of this feature: a scan
    /// report with zero matches -- the case `report_sightings` on the
    /// agent side is a no-op for, and so would otherwise leave this host
    /// looking identical to one that never scanned at all -- still
    /// updates the host's coverage fields, visible through `get_host`.
    #[tokio::test]
    #[ignore]
    async fn report_scan_with_zero_matches_updates_coverage_fields() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let fingerprint = valid_fingerprint("f");
        let scanned_at = Utc::now();

        let response = app
            .clone()
            .oneshot(scan_report_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                12,
                &fingerprint,
                0,
                scanned_at,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(get_host_request(enrolled.host_id, Some(OPERATOR_SECRET)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let host: nsic_core::proto::HostView = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(host.last_scan_rule_count, Some(12));
        assert_eq!(host.last_scan_ruleset_fingerprint, Some(fingerprint));
        assert_eq!(host.last_scan_matched_count, Some(0));
        assert!(host.last_scan_at.is_some());
    }

    /// A host that's never reported a scan must show `None` for all four
    /// coverage fields together -- the "never scanned" state
    /// `ui::scan_status_badge` keys off of.
    #[tokio::test]
    #[ignore]
    async fn a_host_with_no_scan_report_has_no_coverage_fields() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .oneshot(get_host_request(enrolled.host_id, Some(OPERATOR_SECRET)))
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let host: nsic_core::proto::HostView = serde_json::from_slice(&bytes).unwrap();
        assert!(host.last_scan_at.is_none());
        assert!(host.last_scan_rule_count.is_none());
        assert!(host.last_scan_ruleset_fingerprint.is_none());
        assert!(host.last_scan_matched_count.is_none());
    }

    /// A later scan report overwrites the earlier one's coverage fields
    /// -- unlike `host_credential_event`, there's no accumulation here to
    /// preserve, only "what's the most recent state."
    #[tokio::test]
    #[ignore]
    async fn a_second_scan_report_overwrites_the_first() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;

        let response = app
            .clone()
            .oneshot(scan_report_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                5,
                &valid_fingerprint("a"),
                1,
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let second_fingerprint = valid_fingerprint("b");
        let response = app
            .clone()
            .oneshot(scan_report_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                7,
                &second_fingerprint,
                0,
                Utc::now(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(get_host_request(enrolled.host_id, Some(OPERATOR_SECRET)))
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let host: nsic_core::proto::HostView = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(host.last_scan_rule_count, Some(7));
        assert_eq!(host.last_scan_ruleset_fingerprint, Some(second_fingerprint));
        assert_eq!(host.last_scan_matched_count, Some(0));
    }
}
