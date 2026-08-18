use chrono::Utc;
use uuid::Uuid;

use super::{indicators, relationship_bounds};
use crate::models::{IndicatorKind, RelationshipKind};

/// Round 9 regression: the old `MAX_RELATIONSHIPS` budget counted
/// report->CVE assertion edges. More than 200 independently-provenanced
/// assertions about CVE-A could therefore consume the whole allowance and
/// hide CVE-B even though the analyst-facing pivot set contains only two
/// distinct concepts.
///
/// This fixture deliberately exceeds that old assertion budget. The
/// concept-aware fallback must return both targets, mark CVE-A's evidence as
/// partial, and *not* claim the relationship set itself is truncated because
/// there are only two CVE concepts.
#[tokio::test]
#[ignore]
async fn many_assertions_for_one_cve_cannot_starve_a_second_cve_target() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
    let pool = crate::db::connect_and_migrate(&database_url)
        .await
        .expect("connect to test database");

    let marker = Uuid::new_v4();
    let sha256 = format!("{:0<64}", marker.simple());
    let md5 = format!("{:0<32}", &marker.simple().to_string()[..16]);
    let (indicator_id, _) = indicators::upsert_indicator(&pool, IndicatorKind::Sha256, &sha256)
        .await
        .expect("seed indicator");

    let now = Utc::now();
    let cve_a = format!("CVE-R9-A-{}", marker.simple());
    let cve_b = format!("CVE-R9-B-{}", marker.simple());
    indicators::upsert_cve(&pool, &cve_a, None, None, None)
        .await
        .expect("seed CVE A");
    indicators::upsert_cve(&pool, &cve_b, None, None, None)
        .await
        .expect("seed CVE B");

    // More than the old 200 assertion-edge budget, all for the same target.
    for n in 0..205 {
        let (report_id, _) = indicators::upsert_report(
            &pool,
            "r9-concept-test",
            Some(&format!("a-{marker}-{n:03}")),
            Some("Repeated assertion for CVE A"),
            None,
            Some(now),
            &serde_json::json!({}),
        )
        .await
        .expect("seed A report");
        indicators::upsert_indicator_observed_in_report(
            &pool,
            indicator_id,
            report_id,
            "r9-parent",
            50,
            now,
            now,
        )
        .await
        .expect("seed A parent edge");
        indicators::upsert_report_references_cve(
            &pool,
            report_id,
            &cve_a,
            "r9-cve-source",
            70,
            now,
            now,
        )
        .await
        .expect("seed A CVE edge");
    }

    let (report_b, _) = indicators::upsert_report(
        &pool,
        "r9-concept-test",
        Some(&format!("b-{marker}")),
        Some("Single assertion for CVE B"),
        None,
        Some(now),
        &serde_json::json!({}),
    )
    .await
    .expect("seed B report");
    indicators::upsert_indicator_observed_in_report(
        &pool,
        indicator_id,
        report_b,
        "r9-parent",
        50,
        now,
        now,
    )
    .await
    .expect("seed B parent edge");
    indicators::upsert_report_references_cve(
        &pool,
        report_b,
        &cve_b,
        "r9-cve-source",
        70,
        now,
        now,
    )
    .await
    .expect("seed B CVE edge");

    let result = relationship_bounds::cve_matches_via_report(&pool, &sha256, &md5)
        .await
        .expect("concept-aware CVE lookup");

    assert!(
        !result.truncated,
        "two CVE concepts are exhaustive even though one has >200 assertions"
    );
    let a = result
        .items
        .iter()
        .find(|r| r.kind == RelationshipKind::Cve && r.target == cve_a)
        .expect("CVE A must be returned");
    let b = result
        .items
        .iter()
        .find(|r| r.kind == RelationshipKind::Cve && r.target == cve_b)
        .expect("CVE B must not be starved by CVE A's assertion volume");

    assert_eq!(
        a.evidence_paths.len() as i64,
        indicators::MAX_EVIDENCE_PER_RELATIONSHIP
    );
    assert!(a.has_more_evidence);
    assert_eq!(b.evidence_paths.len(), 1);
    assert!(!b.has_more_evidence);
}
