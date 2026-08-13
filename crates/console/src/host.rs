use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use nsic_core::proto::{EnrollRequest, EnrollResponse, HeartbeatRequest, HeartbeatResponse};
use sqlx::PgPool;
use uuid::Uuid;

/// Registers a new host and returns its assigned id. No authentication yet
/// -- see docs/phase1-design.md for why that is a tracked gap rather than
/// an oversight, and what has to land before any real fleet points at this.
pub async fn enroll(
    State(pool): State<PgPool>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, (StatusCode, String)> {
    let host_id: Uuid = sqlx::query_scalar(
        "INSERT INTO host (hostname, os, agent_version) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(&req.hostname)
    .bind(&req.os)
    .bind(&req.agent_version)
    .fetch_one(&pool)
    .await
    .map_err(internal_error)?;

    Ok(Json(EnrollResponse { host_id }))
}

pub async fn heartbeat(
    State(pool): State<PgPool>,
    Path(host_id): Path<Uuid>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, String)> {
    let now = Utc::now();
    let updated =
        sqlx::query("UPDATE host SET last_heartbeat_at = $1, agent_version = $2 WHERE id = $3")
            .bind(now)
            .bind(&req.agent_version)
            .bind(host_id)
            .execute(&pool)
            .await
            .map_err(internal_error)?;

    if updated.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, format!("unknown host_id {host_id}")));
    }

    Ok(Json(HeartbeatResponse { received_at: now }))
}

fn internal_error(e: sqlx::Error) -> (StatusCode, String) {
    tracing::error!("db error: {e:#}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// End-to-end round trip through the real router: enroll a host, then
    /// heartbeat it, and check both succeed. Requires a live Postgres
    /// reachable at DATABASE_URL; run explicitly with `cargo test --
    /// --ignored`, matching the pattern src-tauri's own DB-backed test uses.
    #[tokio::test]
    #[ignore]
    async fn enroll_then_heartbeat_round_trip() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = nsic_core::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let app = crate::build_router(pool);

        let enroll_body = serde_json::json!({
            "hostname": "test-host",
            "os": "linux",
            "agent_version": "0.1.0-test",
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/enroll")
                    .header("content-type", "application/json")
                    .body(Body::from(enroll_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let enrolled: nsic_core::proto::EnrollResponse = serde_json::from_slice(&bytes).unwrap();

        let heartbeat_body = serde_json::json!({ "agent_version": "0.1.0-test" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/agents/{}/heartbeat", enrolled.host_id))
                    .header("content-type", "application/json")
                    .body(Body::from(heartbeat_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
