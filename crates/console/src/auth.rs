use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

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
