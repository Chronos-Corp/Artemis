-- Phase 1 PR #14: sensor health / scan coverage. Documented as a gap
-- since PR #6: a sighting only ever fires on a YARA match, so zero
-- active rules and zero detections looked identical from the console's
-- side -- both are just an absence of sightings for that host. A host
-- that never scanned anything, or whose rules directory failed to load,
-- was indistinguishable from a genuinely clean one.
--
-- These four columns record the most recent scan *attempt*, independent
-- of whether it matched anything -- the same "last known state" shape
-- last_heartbeat_at already has on this table, not an append-only log
-- (unlike host_credential_event, there's no analogous "lost provenance
-- on overwrite" concern here: this is coverage telemetry, not an audit
-- trail of security-relevant state changes). All four are nullable and
-- NULL together until the host's agent reports its first scan.
ALTER TABLE host ADD COLUMN last_scan_at TIMESTAMPTZ;
ALTER TABLE host ADD COLUMN last_scan_rule_count INTEGER;
ALTER TABLE host ADD COLUMN last_scan_ruleset_fingerprint TEXT;
ALTER TABLE host ADD COLUMN last_scan_matched_count INTEGER;
