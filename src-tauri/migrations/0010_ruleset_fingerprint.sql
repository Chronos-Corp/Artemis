-- Rule identity is (kind, name); rule *content* is not. Editing a YARA
-- rule's body keeps the same detection row (upsert_detection's ON CONFLICT
-- is (kind, name)), so any detection_covers_cve edge attached to that row
-- would otherwise silently apply to whatever content the rule holds today,
-- not the content it held when the coverage assertion was made. A review
-- caught this as a way for CVE coverage to cross rule revisions unnoticed.
--
-- ruleset_fingerprint records which compiled ruleset (see
-- YaraEngine::ruleset_fingerprint's doc comment) produced a given
-- observation or assertion. Nullable on both: existing/synthetic rows and
-- any writer that genuinely can't attach a fingerprint aren't forced to
-- fabricate one, and a NULL detection_covers_cve.ruleset_fingerprint is
-- read as "applies to any ruleset version" (permissive default, since no
-- real ingestion writes this table yet).
ALTER TABLE detection_detects_indicator ADD COLUMN ruleset_fingerprint TEXT;
ALTER TABLE detection_covers_cve ADD COLUMN ruleset_fingerprint TEXT;
