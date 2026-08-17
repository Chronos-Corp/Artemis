-- Rule identity is (kind, name); rule *content* is not. Editing a YARA
-- rule's body keeps the same detection row (upsert_detection's ON CONFLICT
-- is (kind, name)), so any detection_covers_cve edge attached to that row
-- would otherwise silently apply to whatever content the rule holds today,
-- not the content it held when the coverage assertion was made. A review
-- caught this as a way for CVE coverage to cross rule revisions unnoticed.
--
-- rule_fingerprint records which specific rule content (see
-- YaraEngine::rule_fingerprint's doc comment -- the SHA-256 of the one
-- file that declared this exact rule, not the whole compiled ruleset)
-- produced a given observation or assertion. A round-6 review caught an
-- earlier version of this column scoped by the *whole-ruleset* fingerprint
-- instead: hashing every rule file in the directory together meant editing
-- an entirely unrelated rule B invalidated rule A's own, unchanged CVE
-- coverage -- a false negative on every unrelated edit, not just a real
-- content change.
--
-- NOT NULL with an empty-string sentinel, not a nullable column: a
-- nullable column can't participate in a primary key (Postgres treats
-- every NULL as distinct for uniqueness purposes, which is not what
-- "unscoped" should mean here), and rule_fingerprint needs to be part of
-- the edge's identity, not mutable metadata on an otherwise versionless
-- edge -- the same round-6 review caught that the original nullable
-- column was excluded from both tables' primary keys, so upserting a v2
-- observation of the same (detection, indicator/cve, source) silently
-- overwrote v1's row via ON CONFLICT, merging (and losing) both versions'
-- separate observation histories into one. '' means "applies to any
-- ruleset version" (existing/synthetic rows and any writer that genuinely
-- can't attach a fingerprint), and is now a normal, distinct key value
-- rather than a special NULL case queries have to remember to handle.
ALTER TABLE detection_detects_indicator ADD COLUMN rule_fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE detection_covers_cve ADD COLUMN rule_fingerprint TEXT NOT NULL DEFAULT '';

ALTER TABLE detection_detects_indicator DROP CONSTRAINT detection_detects_indicator_pkey;
ALTER TABLE detection_detects_indicator
    ADD PRIMARY KEY (detection_id, indicator_id, source, rule_fingerprint);

ALTER TABLE detection_covers_cve DROP CONSTRAINT detection_covers_cve_pkey;
ALTER TABLE detection_covers_cve
    ADD PRIMARY KEY (detection_id, cve_id, source, rule_fingerprint);
