use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use nsic_core::proto::{
    CredentialRotated, EnrollRequest, EnrollResponse, HeartbeatRequest, HeartbeatResponse,
};
use uuid::Uuid;

use crate::auth::{
    authenticate_host, authenticate_operator, bearer_token, generate_credential, hash_credential,
    internal_error, secrets_match,
};
use crate::AppState;

/// Stored in `host.credential_hash` for a host whose credential has been
/// explicitly revoked. Not a real SHA-256 hex digest (`hash_credential`
/// always produces exactly 64 lowercase hex characters), so no presented
/// credential can ever hash to this value -- `authenticate_host` rejects
/// every request for this host until an operator rotates in a fresh
/// credential. Distinct from `0004_host_credential.sql`'s
/// `'legacy-host-requires-re-enrollment'` sentinel: that one marks a host
/// that never had a real credential at all and can only recover by
/// re-enrolling under a new host id, losing its old one's history. A
/// revoked host keeps its id and history and can recover in place via
/// `rotate_credential`.
const REVOKED_CREDENTIAL_SENTINEL: &str = "revoked-requires-credential-rotation";

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
pub async fn rotate_credential(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<CredentialRotated>, (StatusCode, String)> {
    authenticate_operator(&state.operator_secret, &headers)?;

    let credential = generate_credential();
    let credential_hash = hash_credential(&credential);
    set_host_credential(&state, host_id, &credential_hash).await?;

    Ok(Json(CredentialRotated { credential }))
}

/// Invalidates a host's credential without issuing a new one, for
/// decommissioning or an in-progress compromise where an operator wants
/// the host locked out immediately and doesn't yet want to hand it
/// anything usable. Recoverable in place via `rotate_credential` later --
/// unlike deleting the `host` row outright, this doesn't discard the
/// host's sighting/sample-request audit trail to achieve the same
/// lockout. Operator-credential gated, same reasoning as
/// `rotate_credential`.
pub async fn revoke_credential(
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    authenticate_operator(&state.operator_secret, &headers)?;

    set_host_credential(&state, host_id, REVOKED_CREDENTIAL_SENTINEL).await?;

    Ok(StatusCode::OK)
}

/// Shared by `rotate_credential` and `revoke_credential`: both write a new
/// value into `credential_hash` and stamp `credential_rotated_at`,
/// differing only in what that value is (a real hash vs. a sentinel that
/// can never match one). A single `UPDATE ... WHERE id = $1` can't
/// distinguish "no such host" from "host exists, nothing changed," so
/// existence is checked first and reported as 404 -- the same "operator
/// already privileged, no existence to hide" reasoning
/// `create_sample_request` already applies to its own unknown-`host_id`
/// case, unlike the deliberately existence-hiding 401s on agent-facing
/// endpoints like `heartbeat`.
async fn set_host_credential(
    state: &AppState,
    host_id: Uuid,
    new_credential_hash: &str,
) -> Result<(), (StatusCode, String)> {
    let rows_affected = sqlx::query(
        "UPDATE host SET credential_hash = $1, credential_rotated_at = $2 WHERE id = $3",
    )
    .bind(new_credential_hash)
    .bind(Utc::now())
    .bind(host_id)
    .execute(&state.pool)
    .await
    .map_err(internal_error)?
    .rows_affected();

    if rows_affected == 0 {
        return Err((StatusCode::NOT_FOUND, "unknown host_id".to_string()));
    }
    Ok(())
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
}
