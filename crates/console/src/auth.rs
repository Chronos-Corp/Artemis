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

/// 32 random bytes, hex-encoded. Shared primitive behind both
/// `generate_credential` (a per-agent credential) and `generate_csrf_token`
/// (the fleet UI's per-process CSRF token) -- the two have nothing to do
/// with each other conceptually, but "unpredictable enough that an
/// attacker can't guess or brute-force it" is the same requirement either
/// way.
fn random_hex_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generates a fresh per-agent credential. Returned to the agent exactly
/// once at enroll time; only its hash is ever stored (see
/// `hash_credential`).
pub fn generate_credential() -> String {
    random_hex_token()
}

/// Generates the fleet UI's CSRF token, once per console process at
/// startup (`main()` stores it in `AppState::csrf_token`) -- not rotated,
/// not per-session. That's sufficient here: the defense this token
/// provides doesn't depend on it changing over time, only on a
/// cross-origin attacker being unable to read it. The Same-Origin Policy
/// already guarantees that -- a malicious page can *submit* a form to
/// this console (the browser will attach a cached Basic Auth credential
/// automatically regardless of the form's origin), but it cannot *read*
/// this console's authenticated HTML to discover what value belongs in
/// the hidden `csrf_token` field, so it cannot forge a request that
/// passes `verify_csrf`. See `ui.rs` for where this is rendered into
/// every UI POST form and checked on every UI POST handler.
pub fn generate_csrf_token() -> String {
    random_hex_token()
}

/// Constant-time comparison of a UI form's `csrf_token` field against
/// `AppState::csrf_token`. Every UI POST handler (`ui::rotate_credential_
/// action`, `ui::revoke_credential_action`,
/// `ui::create_sample_request_action`) must call this before doing
/// anything else -- HTTP Basic auth alone proves the request carries a
/// valid operator credential, not that the request was actually initiated
/// by the operator: a cross-origin page can trigger a form submission
/// that the browser attaches cached Basic Auth credentials to just as
/// automatically as it would a cookie, so Basic Auth is not itself CSRF
/// protection. See `generate_csrf_token`'s doc comment for why a single
/// unrotated per-process token is enough to close that gap.
pub fn verify_csrf(state_token: &str, form_token: &str) -> bool {
    secrets_match(state_token, form_token)
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
