use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use nsic_core::proto::{
    SampleRequestCreate, SampleRequestCreated, SampleRequestFailure, SampleRequestFulfilled,
    SampleRequestListResponse, SampleRequestStatus, SampleRequestView,
};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::auth::{authenticate_host, authenticate_operator, internal_error};
use crate::pagination::truncate_to_limit;
use crate::validate::{bad_request, validate_lowercase_sha256};
use crate::AppState;

/// Hard cap on a single sample's size, enforced two ways: as an
/// `axum::extract::DefaultBodyLimit` on the upload route in `main.rs` (so
/// an oversized body is rejected before it's fully buffered into memory)
/// and again here as a belt-and-suspenders check, in case that layer is
/// ever misconfigured or removed in a future refactor. 100 MiB is an
/// arbitrary but documented ceiling for storing raw sample bytes directly
/// in Postgres -- see docs/phase1-design.md for why that storage choice
/// itself is not the final answer.
pub const MAX_SAMPLE_SIZE_BYTES: usize = 100 * 1024 * 1024;

/// Row cap for both list endpoints below, same reasoning and same
/// truncated-flag pattern as `sighting.rs`'s `SIGHTING_LIST_LIMIT`.
/// Sample requests are analyst-initiated and comparatively rare compared
/// to automated sighting reports, so 500 is a generous ceiling, not a
/// tight one.
const SAMPLE_REQUEST_LIST_LIMIT: i64 = 500;

const MAX_PATH_LEN: usize = 4096;

/// Creates a pending request to retrieve a specific file from a specific
/// host. Operator-credential only -- this is an analyst action, not
/// something an agent does to itself. This row is the audit log locked
/// architecture decision #3 requires: see the migration
/// (`0006_sample_request.sql`) and `nsic_core::proto::SampleRequestCreate`
/// for what "logged and attributed" does and doesn't mean yet.
pub async fn create_sample_request(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<SampleRequestCreate>,
) -> Result<Json<SampleRequestCreated>, (StatusCode, String)> {
    authenticate_operator(&state.operator_secret, &headers)?;
    validate_sample_request_create(&req)?;

    let host_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM host WHERE id = $1)")
        .bind(host_id)
        .fetch_one(&state.pool)
        .await
        .map_err(internal_error)?;
    if !host_exists {
        return Err((StatusCode::NOT_FOUND, "unknown host_id".to_string()));
    }

    let request_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sample_request (host_id, path, expected_sha256) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(host_id)
    .bind(&req.path)
    .bind(&req.expected_sha256)
    .fetch_one(&state.pool)
    .await
    .map_err(internal_error)?;

    Ok(Json(SampleRequestCreated { request_id }))
}

fn validate_sample_request_create(req: &SampleRequestCreate) -> Result<(), (StatusCode, String)> {
    if req.path.trim().is_empty() {
        return Err(bad_request("path must not be empty"));
    }
    if req.path.chars().count() > MAX_PATH_LEN {
        return Err(bad_request(&format!(
            "path must be {MAX_PATH_LEN} characters or fewer"
        )));
    }
    if let Some(sha256) = &req.expected_sha256 {
        validate_lowercase_sha256(sha256, "expected_sha256")?;
    }
    Ok(())
}

/// Lists every sample request for a given host, most recently requested
/// first -- operator-credential only. Metadata and status, never sample
/// content: there is no endpoint that returns bytes back to an operator
/// yet (see `nsic_core::proto::SampleRequestView`'s doc comment).
pub async fn list_sample_requests(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SampleRequestListResponse>, (StatusCode, String)> {
    authenticate_operator(&state.operator_secret, &headers)?;

    let mut rows = sqlx::query(
        "SELECT sr.id, sr.host_id, sr.path, sr.expected_sha256, sr.status, \
                sr.failure_reason, sr.sha256, sb.size_bytes, sr.requested_at, sr.resolved_at \
         FROM sample_request sr \
         LEFT JOIN sample_blob sb ON sb.sha256 = sr.sha256 \
         WHERE sr.host_id = $1 \
         ORDER BY sr.requested_at DESC, sr.id \
         LIMIT $2",
    )
    .bind(host_id)
    .bind(SAMPLE_REQUEST_LIST_LIMIT + 1)
    .fetch_all(&state.pool)
    .await
    .map_err(internal_error)?;

    let truncated = truncate_to_limit(&mut rows, SAMPLE_REQUEST_LIST_LIMIT as usize);
    Ok(Json(SampleRequestListResponse {
        requests: rows.into_iter().map(sample_request_view_from_row).collect(),
        truncated,
    }))
}

/// Lists only this host's own *pending* requests -- what the agent polls
/// to find out what it still needs to act on. Per-agent credential, not
/// the operator credential: an agent may see (and fulfill) its own
/// pending requests, not any other host's, and not its own already-
/// resolved history, which it has no need for.
pub async fn list_pending_sample_requests(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SampleRequestListResponse>, (StatusCode, String)> {
    authenticate_host(&state.pool, host_id, &headers).await?;

    let mut rows = sqlx::query(
        "SELECT sr.id, sr.host_id, sr.path, sr.expected_sha256, sr.status, \
                sr.failure_reason, sr.sha256, sb.size_bytes, sr.requested_at, sr.resolved_at \
         FROM sample_request sr \
         LEFT JOIN sample_blob sb ON sb.sha256 = sr.sha256 \
         WHERE sr.host_id = $1 AND sr.status = 'pending' \
         ORDER BY sr.requested_at, sr.id \
         LIMIT $2",
    )
    .bind(host_id)
    .bind(SAMPLE_REQUEST_LIST_LIMIT + 1)
    .fetch_all(&state.pool)
    .await
    .map_err(internal_error)?;

    let truncated = truncate_to_limit(&mut rows, SAMPLE_REQUEST_LIST_LIMIT as usize);
    Ok(Json(SampleRequestListResponse {
        requests: rows.into_iter().map(sample_request_view_from_row).collect(),
        truncated,
    }))
}

/// Fulfills a pending request with the agent's uploaded bytes. Per-agent
/// credential; the request must belong to `host_id` (looked up by both
/// `id` and `host_id` together, same as `authenticate_host`'s
/// cross-host-credential check, so a request id can't be probed against
/// the wrong host to learn whether it exists) and must still be
/// `pending` -- a request that's already `fulfilled`/`mismatched`/
/// `failed` is not silently overwritten by a second upload, since that
/// would let a stale or replayed upload quietly rewrite already-recorded
/// evidence. The raw body (not JSON: base64 would inflate a
/// multi-megabyte sample by another third for no benefit) is hashed,
/// stored in `sample_blob` keyed by that hash (deduplicating identical
/// content), and compared against `expected_sha256` if the request set
/// one.
pub async fn fulfill_sample_request(
    State(state): State<AppState>,
    Path((host_id, request_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SampleRequestFulfilled>, (StatusCode, String)> {
    authenticate_host(&state.pool, host_id, &headers).await?;

    if body.len() > MAX_SAMPLE_SIZE_BYTES {
        return Err(bad_request(&format!(
            "sample exceeds the {MAX_SAMPLE_SIZE_BYTES}-byte limit"
        )));
    }

    let expected_sha256: Option<String> =
        claim_pending_request(&state, host_id, request_id).await?;

    let sha256 = hex::encode(Sha256::digest(&body));
    let size_bytes = body.len() as i64;

    let mut tx = state.pool.begin().await.map_err(internal_error)?;

    sqlx::query(
        "INSERT INTO sample_blob (sha256, content, size_bytes) VALUES ($1, $2, $3) \
         ON CONFLICT (sha256) DO NOTHING",
    )
    .bind(&sha256)
    .bind(body.as_ref())
    .bind(size_bytes)
    .execute(&mut *tx)
    .await
    .map_err(internal_error)?;

    let status = match &expected_sha256 {
        Some(expected) if expected != &sha256 => SampleRequestStatus::Mismatched,
        _ => SampleRequestStatus::Fulfilled,
    };

    sqlx::query(
        "UPDATE sample_request SET status = $1, sha256 = $2, resolved_at = $3 WHERE id = $4",
    )
    .bind(status_to_str(status))
    .bind(&sha256)
    .bind(Utc::now())
    .bind(request_id)
    .execute(&mut *tx)
    .await
    .map_err(internal_error)?;

    tx.commit().await.map_err(internal_error)?;

    Ok(Json(SampleRequestFulfilled {
        status,
        sha256,
        size_bytes,
    }))
}

/// Records that the agent tried and could not fulfill a request, so it
/// doesn't sit at `pending` forever with no way for an operator to tell
/// "still in flight" from "never going to happen."
pub async fn fail_sample_request(
    State(state): State<AppState>,
    Path((host_id, request_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(req): Json<SampleRequestFailure>,
) -> Result<StatusCode, (StatusCode, String)> {
    authenticate_host(&state.pool, host_id, &headers).await?;
    claim_pending_request(&state, host_id, request_id).await?;

    if req.reason.trim().is_empty() {
        return Err(bad_request("reason must not be empty"));
    }

    sqlx::query(
        "UPDATE sample_request SET status = 'failed', failure_reason = $1, resolved_at = $2 \
         WHERE id = $3",
    )
    .bind(&req.reason)
    .bind(Utc::now())
    .bind(request_id)
    .execute(&state.pool)
    .await
    .map_err(internal_error)?;

    Ok(StatusCode::OK)
}

/// Looks up a request by `(id, host_id)` together and confirms it's still
/// `pending`, returning its `expected_sha256`. Shared by both resolution
/// paths (`fulfill_sample_request`, `fail_sample_request`) so "wrong
/// host", "unknown id", and "already resolved" are checked identically
/// by both. Wrong host and unknown id return the same `404` -- a request
/// id can't be used to probe whether it belongs to some other host.
async fn claim_pending_request(
    state: &AppState,
    host_id: Uuid,
    request_id: Uuid,
) -> Result<Option<String>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT status, expected_sha256 FROM sample_request WHERE id = $1 AND host_id = $2",
    )
    .bind(request_id)
    .bind(host_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal_error)?;

    let Some(row) = row else {
        return Err((StatusCode::NOT_FOUND, "unknown sample request".to_string()));
    };

    let status: String = row.get("status");
    if status != "pending" {
        return Err((
            StatusCode::CONFLICT,
            format!("sample request is already resolved (status: {status})"),
        ));
    }

    Ok(row.get("expected_sha256"))
}

fn status_to_str(status: SampleRequestStatus) -> &'static str {
    match status {
        SampleRequestStatus::Pending => "pending",
        SampleRequestStatus::Fulfilled => "fulfilled",
        SampleRequestStatus::Mismatched => "mismatched",
        SampleRequestStatus::Failed => "failed",
    }
}

fn status_from_str(status: &str) -> SampleRequestStatus {
    match status {
        "pending" => SampleRequestStatus::Pending,
        "fulfilled" => SampleRequestStatus::Fulfilled,
        "mismatched" => SampleRequestStatus::Mismatched,
        "failed" => SampleRequestStatus::Failed,
        other => unreachable!(
            "sample_request.status check constraint allows only the four known values, got {other}"
        ),
    }
}

fn sample_request_view_from_row(row: sqlx::postgres::PgRow) -> SampleRequestView {
    let status: String = row.get("status");
    SampleRequestView {
        id: row.get("id"),
        host_id: row.get("host_id"),
        path: row.get("path"),
        expected_sha256: row.get("expected_sha256"),
        status: status_from_str(&status),
        failure_reason: row.get("failure_reason"),
        sha256: row.get("sha256"),
        size_bytes: row.get("size_bytes"),
        requested_at: row.get("requested_at"),
        resolved_at: row.get("resolved_at"),
    }
}

#[cfg(test)]
mod tests {
    use crate::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use nsic_core::proto::{SampleRequestListResponse, SampleRequestStatus};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use uuid::Uuid;

    const BOOTSTRAP_SECRET: &str = "test-bootstrap-secret";
    const OPERATOR_SECRET: &str = "test-operator-secret";

    fn valid_sha256(seed: &str) -> String {
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

    fn create_request(
        host_id: Uuid,
        bearer: Option<&str>,
        path: &str,
        expected_sha256: Option<&str>,
    ) -> Request<Body> {
        let body = serde_json::json!({ "path": path, "expected_sha256": expected_sha256 });
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/hosts/{host_id}/sample-requests"))
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn list_operator_view_request(host_id: Uuid, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/hosts/{host_id}/sample-requests"));
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    fn list_pending_request(host_id: Uuid, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/agents/{host_id}/sample-requests"));
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    fn fulfill_content_request(
        host_id: Uuid,
        request_id: Uuid,
        bearer: Option<&str>,
        content: Vec<u8>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agents/{host_id}/sample-requests/{request_id}/content"
            ))
            .header("content-type", "application/octet-stream");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(content)).unwrap()
    }

    fn fail_request(
        host_id: Uuid,
        request_id: Uuid,
        bearer: Option<&str>,
        reason: &str,
    ) -> Request<Body> {
        let body = serde_json::json!({ "reason": reason });
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agents/{host_id}/sample-requests/{request_id}/failure"
            ))
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    /// Creates a pending request through the real endpoint (rather than
    /// inserting a row directly) so every test that needs one already
    /// pending also exercises `create_sample_request`, and returns its id.
    async fn create_pending(
        app: &axum::Router,
        host_id: Uuid,
        path: &str,
        expected_sha256: Option<&str>,
    ) -> Uuid {
        let response = app
            .clone()
            .oneshot(create_request(
                host_id,
                Some(OPERATOR_SECRET),
                path,
                expected_sha256,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let created: nsic_core::proto::SampleRequestCreated =
            serde_json::from_slice(&bytes).unwrap();
        created.request_id
    }

    #[tokio::test]
    #[ignore]
    async fn create_sample_request_rejects_missing_operator_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(create_request(enrolled.host_id, None, "/tmp/x", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn create_sample_request_rejects_wrong_operator_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(create_request(
                enrolled.host_id,
                Some("not-the-secret"),
                "/tmp/x",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A host's own per-agent credential must not authorize creating
    /// sample requests -- that's an analyst action against the fleet, not
    /// something a host does to itself, and this is the same
    /// credential-separation property PR #7 verified for reading
    /// sightings.
    #[tokio::test]
    #[ignore]
    async fn create_sample_request_rejects_per_agent_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(create_request(
                enrolled.host_id,
                Some(&enrolled.credential),
                "/tmp/x",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn create_sample_request_rejects_empty_path() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(create_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
                "",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore]
    async fn create_sample_request_rejects_malformed_expected_sha256() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(create_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
                "/tmp/x",
                Some("banana"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore]
    async fn create_sample_request_rejects_unknown_host_id() {
        let app = crate::build_router(test_state().await);
        let response = app
            .oneshot(create_request(
                Uuid::new_v4(),
                Some(OPERATOR_SECRET),
                "/tmp/x",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[ignore]
    async fn create_sample_request_creates_pending_request() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let request_id = create_pending(&app, enrolled.host_id, "/tmp/malware.exe", None).await;

        let response = app
            .oneshot(list_operator_view_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let listed: SampleRequestListResponse = serde_json::from_slice(&bytes).unwrap();
        let view = listed
            .requests
            .iter()
            .find(|r| r.id == request_id)
            .expect("the created request appears in the operator's list");
        assert_eq!(view.status, SampleRequestStatus::Pending);
        assert_eq!(view.path, "/tmp/malware.exe");
        assert!(view.sha256.is_none());
        assert!(view.resolved_at.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn list_pending_sample_requests_rejects_missing_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(list_pending_request(enrolled.host_id, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The operator credential -- valid for creating and listing requests
    /// -- must not also authenticate the agent-facing poll endpoint. The
    /// mirror image of the per-agent-credential check above: neither
    /// credential should work in the other's place.
    #[tokio::test]
    #[ignore]
    async fn list_pending_sample_requests_rejects_operator_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(list_pending_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn list_pending_sample_requests_returns_only_pending_for_that_host() {
        let app = crate::build_router(test_state().await);
        let host_a = enroll(&app).await;
        let host_b = enroll(&app).await;

        let pending_id = create_pending(&app, host_a.host_id, "/tmp/pending.exe", None).await;
        let resolved_id = create_pending(&app, host_a.host_id, "/tmp/resolved.exe", None).await;
        let _other_hosts_request =
            create_pending(&app, host_b.host_id, "/tmp/other-host.exe", None).await;

        // Resolve one of host A's two requests, so it must drop out of the
        // pending view while the other stays.
        let response = app
            .clone()
            .oneshot(fulfill_content_request(
                host_a.host_id,
                resolved_id,
                Some(&host_a.credential),
                b"content".to_vec(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(list_pending_request(
                host_a.host_id,
                Some(&host_a.credential),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let listed: SampleRequestListResponse = serde_json::from_slice(&bytes).unwrap();
        let ids: Vec<Uuid> = listed.requests.iter().map(|r| r.id).collect();
        assert!(ids.contains(&pending_id));
        assert!(
            !ids.contains(&resolved_id),
            "a resolved request must not appear in the pending poll view"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn fulfill_sample_request_rejects_missing_credential() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let request_id = create_pending(&app, enrolled.host_id, "/tmp/x", None).await;
        let response = app
            .oneshot(fulfill_content_request(
                enrolled.host_id,
                request_id,
                None,
                b"data".to_vec(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Host A's credential must not fulfill host B's sample request, the
    /// same cross-host-credential property `heartbeat` and `sightings`
    /// already enforce.
    #[tokio::test]
    #[ignore]
    async fn fulfill_sample_request_rejects_credential_for_different_host() {
        let app = crate::build_router(test_state().await);
        let host_a = enroll(&app).await;
        let host_b = enroll(&app).await;
        let request_id = create_pending(&app, host_b.host_id, "/tmp/x", None).await;

        let response = app
            .oneshot(fulfill_content_request(
                host_b.host_id,
                request_id,
                Some(&host_a.credential),
                b"data".to_vec(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore]
    async fn fulfill_sample_request_rejects_unknown_request_id() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let response = app
            .oneshot(fulfill_content_request(
                enrolled.host_id,
                Uuid::new_v4(),
                Some(&enrolled.credential),
                b"data".to_vec(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[ignore]
    async fn fulfill_sample_request_marks_fulfilled_and_stores_blob() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let request_id = create_pending(&app, enrolled.host_id, "/tmp/x", None).await;

        let content = b"totally a malware sample".to_vec();
        let expected_sha256 = hex::encode(Sha256::digest(&content));

        let response = app
            .clone()
            .oneshot(fulfill_content_request(
                enrolled.host_id,
                request_id,
                Some(&enrolled.credential),
                content.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let resp: nsic_core::proto::SampleRequestFulfilled =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp.status, SampleRequestStatus::Fulfilled);
        assert_eq!(resp.sha256, expected_sha256);
        assert_eq!(resp.size_bytes, content.len() as i64);

        let response = app
            .oneshot(list_operator_view_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let listed: SampleRequestListResponse = serde_json::from_slice(&bytes).unwrap();
        let view = listed.requests.iter().find(|r| r.id == request_id).unwrap();
        assert_eq!(view.status, SampleRequestStatus::Fulfilled);
        assert_eq!(view.sha256.as_deref(), Some(expected_sha256.as_str()));
        assert_eq!(view.size_bytes, Some(content.len() as i64));
        assert!(view.resolved_at.is_some());
    }

    #[tokio::test]
    #[ignore]
    async fn fulfill_sample_request_matching_expected_sha256_marks_fulfilled() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let content = b"known content".to_vec();
        let expected = hex::encode(Sha256::digest(&content));
        let request_id = create_pending(&app, enrolled.host_id, "/tmp/x", Some(&expected)).await;

        let response = app
            .oneshot(fulfill_content_request(
                enrolled.host_id,
                request_id,
                Some(&enrolled.credential),
                content,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let resp: nsic_core::proto::SampleRequestFulfilled =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp.status, SampleRequestStatus::Fulfilled);
    }

    /// An analyst asserted a hash, and the agent uploaded something else
    /// -- wrong file, changed since the hash was recorded, or worse. That
    /// must surface as a distinct 'mismatched' outcome, not get silently
    /// accepted as an ordinary fulfillment.
    #[tokio::test]
    #[ignore]
    async fn fulfill_sample_request_mismatched_expected_sha256_marks_mismatched() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let request_id =
            create_pending(&app, enrolled.host_id, "/tmp/x", Some(&valid_sha256("a"))).await;

        let response = app
            .clone()
            .oneshot(fulfill_content_request(
                enrolled.host_id,
                request_id,
                Some(&enrolled.credential),
                b"not what was expected".to_vec(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let resp: nsic_core::proto::SampleRequestFulfilled =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp.status, SampleRequestStatus::Mismatched);

        let response = app
            .oneshot(list_operator_view_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let listed: SampleRequestListResponse = serde_json::from_slice(&bytes).unwrap();
        let view = listed.requests.iter().find(|r| r.id == request_id).unwrap();
        assert_eq!(
            view.status,
            SampleRequestStatus::Mismatched,
            "the mismatch must be visible in the operator's view, not silently upgraded to fulfilled"
        );
    }

    /// A request that's already resolved (fulfilled, mismatched, or
    /// failed) must not be silently overwritten by a second upload -- that
    /// would let a stale or replayed request rewrite already-recorded
    /// evidence.
    #[tokio::test]
    #[ignore]
    async fn fulfill_sample_request_rejects_already_resolved_request() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let request_id = create_pending(&app, enrolled.host_id, "/tmp/x", None).await;

        let response = app
            .clone()
            .oneshot(fulfill_content_request(
                enrolled.host_id,
                request_id,
                Some(&enrolled.credential),
                b"first upload".to_vec(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(fulfill_content_request(
                enrolled.host_id,
                request_id,
                Some(&enrolled.credential),
                b"second upload, should be rejected".to_vec(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    /// The same content retrieved from two different hosts must be stored
    /// once in `sample_blob` (content-addressed by sha256), not
    /// duplicated -- verified indirectly, by confirming both hosts'
    /// requests independently resolve to the same sha256 rather than
    /// erroring on some kind of storage conflict.
    #[tokio::test]
    #[ignore]
    async fn fulfill_sample_request_dedupes_identical_content_across_hosts() {
        let app = crate::build_router(test_state().await);
        let host_a = enroll(&app).await;
        let host_b = enroll(&app).await;
        let request_a = create_pending(&app, host_a.host_id, "/tmp/same.exe", None).await;
        let request_b = create_pending(&app, host_b.host_id, "/tmp/same.exe", None).await;
        let content = b"identical bytes on both hosts".to_vec();

        let response = app
            .clone()
            .oneshot(fulfill_content_request(
                host_a.host_id,
                request_a,
                Some(&host_a.credential),
                content.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let resp_a: nsic_core::proto::SampleRequestFulfilled =
            serde_json::from_slice(&bytes).unwrap();

        let response = app
            .oneshot(fulfill_content_request(
                host_b.host_id,
                request_b,
                Some(&host_b.credential),
                content,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let resp_b: nsic_core::proto::SampleRequestFulfilled =
            serde_json::from_slice(&bytes).unwrap();

        assert_eq!(resp_a.sha256, resp_b.sha256);
    }

    #[tokio::test]
    #[ignore]
    async fn fail_sample_request_marks_failed_with_reason() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let request_id = create_pending(&app, enrolled.host_id, "/tmp/gone.exe", None).await;

        let response = app
            .clone()
            .oneshot(fail_request(
                enrolled.host_id,
                request_id,
                Some(&enrolled.credential),
                "file no longer exists",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(list_operator_view_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let listed: SampleRequestListResponse = serde_json::from_slice(&bytes).unwrap();
        let view = listed.requests.iter().find(|r| r.id == request_id).unwrap();
        assert_eq!(view.status, SampleRequestStatus::Failed);
        assert_eq!(
            view.failure_reason.as_deref(),
            Some("file no longer exists")
        );
        assert!(view.resolved_at.is_some());
    }

    #[tokio::test]
    #[ignore]
    async fn fail_sample_request_rejects_empty_reason() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let request_id = create_pending(&app, enrolled.host_id, "/tmp/x", None).await;

        let response = app
            .oneshot(fail_request(
                enrolled.host_id,
                request_id,
                Some(&enrolled.credential),
                "",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore]
    async fn fail_sample_request_rejects_already_resolved_request() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let request_id = create_pending(&app, enrolled.host_id, "/tmp/x", None).await;

        let response = app
            .clone()
            .oneshot(fulfill_content_request(
                enrolled.host_id,
                request_id,
                Some(&enrolled.credential),
                b"already fulfilled".to_vec(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(fail_request(
                enrolled.host_id,
                request_id,
                Some(&enrolled.credential),
                "too late",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    /// The operator's view, unlike the agent's poll view, must show
    /// requests in every status -- an operator needs to see what
    /// happened, not just what's still outstanding.
    #[tokio::test]
    #[ignore]
    async fn list_sample_requests_operator_view_includes_resolved_requests() {
        let app = crate::build_router(test_state().await);
        let enrolled = enroll(&app).await;
        let pending_id = create_pending(&app, enrolled.host_id, "/tmp/pending.exe", None).await;
        let failed_id = create_pending(&app, enrolled.host_id, "/tmp/failed.exe", None).await;

        let response = app
            .clone()
            .oneshot(fail_request(
                enrolled.host_id,
                failed_id,
                Some(&enrolled.credential),
                "permission denied",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(list_operator_view_request(
                enrolled.host_id,
                Some(OPERATOR_SECRET),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let listed: SampleRequestListResponse = serde_json::from_slice(&bytes).unwrap();
        let ids: Vec<Uuid> = listed.requests.iter().map(|r| r.id).collect();
        assert!(ids.contains(&pending_id));
        assert!(ids.contains(&failed_id));
    }
}
