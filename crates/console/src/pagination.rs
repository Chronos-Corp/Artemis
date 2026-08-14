/// Shared by every list endpoint's cap-plus-`truncated`-flag pattern (see
/// `sighting.rs`'s `SIGHTING_LIST_LIMIT` and `sample.rs`'s
/// `SAMPLE_REQUEST_LIST_LIMIT`). Callers fetch one row past their limit;
/// if that extra row shows up here, it's trimmed back off and the caller
/// learns its response was cut short instead of that being
/// indistinguishable from "this is genuinely everything." Generic over
/// the row type (rather than `sqlx::postgres::PgRow` directly) so the
/// off-by-one logic can be unit-tested on a plain `Vec` without a
/// database.
pub fn truncate_to_limit<T>(rows: &mut Vec<T>, limit: usize) -> bool {
    let truncated = rows.len() > limit;
    if truncated {
        rows.truncate(limit);
    }
    truncated
}

#[cfg(test)]
mod tests {
    use super::truncate_to_limit;

    #[test]
    fn truncate_to_limit_trims_and_reports_truncation_past_the_cap() {
        let mut rows = vec![1, 2, 3];
        assert!(truncate_to_limit(&mut rows, 2));
        assert_eq!(rows, vec![1, 2]);
    }

    #[test]
    fn truncate_to_limit_reports_no_truncation_exactly_at_the_cap() {
        let mut rows = vec![1, 2];
        assert!(!truncate_to_limit(&mut rows, 2));
        assert_eq!(rows, vec![1, 2]);
    }

    #[test]
    fn truncate_to_limit_reports_no_truncation_under_the_cap() {
        let mut rows = vec![1];
        assert!(!truncate_to_limit(&mut rows, 2));
        assert_eq!(rows, vec![1]);
    }
}
