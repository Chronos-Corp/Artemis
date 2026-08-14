use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use nsic_core::proto::{EnrollRequest, EnrollResponse, HeartbeatRequest, HeartbeatResponse};
use uuid::Uuid;

use crate::auth::{
    authenticate_host, bearer_token, generate_credential, hash_credential, internal_error,
    secrets_match,
};
use crate::AppState;

/// Enrolls a new host, provided the caller presents the console's
/// bootstrap enrollment secret as a bearer token. On success, mints a
/// fresh per-agent credential, stores only its hash, and returns the raw
/// credential exactly once -- the agent is responsible for keeping it.
pub async fn enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, (StatusCode, String)> {
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

    Ok(Json(EnrollResponse {
        host_id,
        credential,
    }))
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

#[cfg(test)]
mod tests {
    use crate::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const BOOTSTRAP_SECRET: &str = "test-bootstrap-secret";
    const OPERATOR_SECRET: &str = "test-operator-secret";

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
}
