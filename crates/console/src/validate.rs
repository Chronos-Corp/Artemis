use axum::http::StatusCode;
use chrono::{DateTime, Utc};

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

/// How far ahead of the console's own clock an agent-claimed timestamp is
/// tolerated before being rejected outright, and (with
/// `earliest_plausible_timestamp` below) how far in the past. Originally
/// `sighting.rs`'s own `MAX_FUTURE_SKEW`, moved here once the new scan
/// report endpoint needed the identical bound for `ScanReport::scanned_at`
/// -- this bounds, but does not eliminate, what a misconfigured or
/// compromised endpoint clock can claim: anything within the window is
/// still accepted at face value. What actually limits the damage is a
/// server-controlled `received_at`/equivalent ingestion timestamp,
/// wherever the caller stores one -- a value analysts can compare the
/// claim against, not a guarantee the claim is honest.
const MAX_FUTURE_SKEW: chrono::Duration = chrono::Duration::minutes(5);

/// A floor sanity bound, not a moving target: nothing this project ever
/// produced can predate its own existence. Catches obviously-bogus clocks
/// (an unset RTC defaulting to the epoch, etc.) without constraining
/// legitimate delayed or batched reports.
fn earliest_plausible_timestamp() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
        .expect("valid constant")
        .with_timezone(&Utc)
}

/// Rejects an agent-claimed timestamp (`SightingRequest::observed_at`,
/// `ScanReport::scanned_at`) more than 5 minutes ahead of the console's
/// own clock, or predating 2020-01-01. `field` names the rejected field in
/// the error message so both call sites get an accurate message from one
/// shared check.
pub fn validate_observed_at(
    observed_at: DateTime<Utc>,
    field: &str,
) -> Result<(), (StatusCode, String)> {
    let now = Utc::now();
    if observed_at > now + MAX_FUTURE_SKEW {
        return Err(bad_request(&format!(
            "{field} {observed_at} is too far in the future (more than 5 minutes ahead of the \
             console's clock)"
        )));
    }
    if observed_at < earliest_plausible_timestamp() {
        return Err(bad_request(&format!(
            "{field} {observed_at} predates any plausible deployment of this software"
        )));
    }
    Ok(())
}

pub fn bad_request(message: &str) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, message.to_string())
}
