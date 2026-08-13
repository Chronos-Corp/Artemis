use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Generates a fresh per-agent credential: 32 random bytes, hex-encoded.
/// Returned to the agent exactly once at enroll time; only its hash is
/// ever stored (see `hash_credential`).
pub fn generate_credential() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Hashes a credential for storage or comparison. The raw value (bootstrap
/// enrollment secret or per-agent credential) is never persisted.
pub fn hash_credential(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

/// Extracts the bearer token from an `Authorization: Bearer <token>`
/// header, if present and well-formed.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Constant-time comparison of two secrets. Used for the bootstrap
/// enrollment secret (compared directly against operator config) and, out
/// of caution, for credential-hash comparisons too, even though SHA-256's
/// preimage resistance already makes timing on the hash impractical to
/// exploit.
pub fn secrets_match(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Maps a database error to the 500 response every handler in this crate
/// returns for one, logging the real cause server-side without leaking it
/// to the caller.
pub fn internal_error(e: sqlx::Error) -> (StatusCode, String) {
    tracing::error!("db error: {e:#}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error".to_string(),
    )
}

/// Verifies the bearer token in `headers` is the correct per-agent
/// credential for `host_id`. Shared by every authenticated agent-facing
/// endpoint (heartbeat, sightings) so the check can't drift between them.
/// Unknown host id and wrong credential return the same 401, so callers
/// can't use this to enumerate valid host ids.
pub async fn authenticate_host(
    pool: &PgPool,
    host_id: Uuid,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, String)> {
    let presented = bearer_token(headers).ok_or((
        StatusCode::UNAUTHORIZED,
        "missing agent credential".to_string(),
    ))?;

    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            "invalid agent credential".to_string(),
        )
    };

    let stored_hash: Option<String> =
        sqlx::query_scalar("SELECT credential_hash FROM host WHERE id = $1")
            .bind(host_id)
            .fetch_optional(pool)
            .await
            .map_err(internal_error)?;
    let stored_hash = stored_hash.ok_or_else(unauthorized)?;

    if !secrets_match(&hash_credential(presented), &stored_hash) {
        return Err(unauthorized());
    }
    Ok(())
}
