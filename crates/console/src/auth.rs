use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
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

/// Verifies the bearer token in `headers` is the console-operator
/// credential (`NSIC_OPERATOR_SECRET`), gating read access to fleet-wide
/// sighting data. Deliberately a separate check from `authenticate_host`:
/// a per-agent credential proves "I am this one host, reporting my own
/// observations," not "I may read what any host in the fleet has
/// reported." Collapsing the two would let a compromised or malicious
/// agent read the entire fleet's sighting history using nothing but its
/// own per-agent credential -- the same class of conflation PR #4 already
/// rejected once for the bootstrap-vs-per-agent split. No database lookup
/// here, unlike `authenticate_host`: the operator secret is a single
/// operator-configured value compared directly, not a per-row hash.
pub fn authenticate_operator(
    operator_secret: &str,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, String)> {
    let presented = bearer_token(headers).ok_or((
        StatusCode::UNAUTHORIZED,
        "missing operator credential".to_string(),
    ))?;
    if !secrets_match(presented, operator_secret) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid operator credential".to_string(),
        ));
    }
    Ok(())
}

/// Verifies HTTP Basic credentials carry the console-operator secret as
/// the password (the username is not checked; there is only one operator
/// identity -- see docs/phase1-design.md on that gap). Used exclusively
/// by the fleet UI (`crates/console/src/ui.rs`), never the JSON API,
/// which stays Bearer-only via `authenticate_operator` -- the same
/// credential, two different wire representations for two different
/// audiences: a browser gets a native login prompt for free from Basic
/// Auth (no login form, no session/cookie machinery to build), while a
/// script or `curl` keeps using `Authorization: Bearer` as documented
/// everywhere else in this API.
///
/// Returns `None` when authenticated. On failure, returns `Some` of a
/// full `401` response (not just a status/message pair) carrying
/// `WWW-Authenticate: Basic`, which is what actually triggers a browser's
/// native credential prompt -- without that header, the browser has no
/// reason to ask and would just show a plain error page instead.
/// `Option<Response>` rather than `Result<(), Response>`: clippy flags a
/// `Response`-sized `Err` variant (`result_large_err`), and there's no
/// error value here worth threading through `?` anyway -- every caller
/// just wants to know "is there a response to return right now instead."
pub fn authenticate_operator_ui(operator_secret: &str, headers: &HeaderMap) -> Option<Response> {
    let challenge = || {
        Some(
            (
                StatusCode::UNAUTHORIZED,
                [(WWW_AUTHENTICATE, "Basic realm=\"nsic-console\"")],
                "operator credential required",
            )
                .into_response(),
        )
    };

    let Some(presented_password) = basic_auth_password(headers) else {
        return challenge();
    };
    if !secrets_match(&presented_password, operator_secret) {
        return challenge();
    }
    None
}

/// Extracts the password portion of an `Authorization: Basic <base64>`
/// header (`base64("username:password")`), if present and well-formed.
/// The username is discarded -- there is nothing to check it against.
fn basic_auth_password(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = BASE64.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (_username, password) = decoded.split_once(':')?;
    Some(password.to_string())
}
