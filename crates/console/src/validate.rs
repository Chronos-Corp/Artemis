use axum::http::StatusCode;

/// Exactly 64 lowercase hexadecimal characters -- the only sha256
/// representation this API accepts anywhere it appears (sighting reports,
/// sample-request hash assertions). Shared across handlers so the two (and
/// future) call sites can't silently drift into accepting different
/// formats.
pub fn validate_lowercase_sha256(value: &str, field: &str) -> Result<(), (StatusCode, String)> {
    let is_valid = value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !is_valid {
        return Err(bad_request(&format!(
            "{field} must be exactly 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

pub fn bad_request(message: &str) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, message.to_string())
}
