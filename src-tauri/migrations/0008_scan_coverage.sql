-- Phase 1 PR #14: sensor health / scan coverage. Documented as a gap
-- since PR #6: a sighting only ever fires on a YARA match, so zero
-- active rules and zero detections looked identical from the console's
-- side -- both are just an absence of sightings for that host. A host
-- that never scanned anything, or whose rules directory failed to load,
-- was indistinguishable from a genuinely clean one.
--
-- These columns record the most recent scan *attempt*, independent of
-- whether it matched anything -- the same "last known state" shape
-- last_heartbeat_at already has on this table, not an append-only log
-- (unlike host_credential_event, there's no analogous "lost provenance
-- on overwrite" concern here: this is coverage telemetry, not an audit
-- trail of security-relevant state changes). All are nullable and NULL
-- together until the host's agent reports its first scan.
--
-- last_scan_at is agent-claimed (the wire type validates it's within a
-- 5-minute-future/2020-01-01 window, same as sighting.observed_at, but
-- doesn't otherwise second-guess it) and so, unlike last_heartbeat_at
-- (always the console's own clock, monotonic by construction), can
-- legitimately arrive out of order -- a delayed retry, a race between
-- overlapping invocations. console::host::report_scan only overwrites
-- the snapshot when the incoming scanned_at is strictly newer than what's
-- already stored, so a stale report can't regress it.
-- last_scan_received_at is the console's own clock at write time --
-- always monotonic, always trustworthy in a way an agent-claimed
-- timestamp alone isn't -- kept alongside last_scan_at for the same
-- "provenance an analyst can compare the claim against" reason
-- host_sighted_indicator.received_at already exists for sightings.
ALTER TABLE host ADD COLUMN last_scan_at TIMESTAMPTZ;
ALTER TABLE host ADD COLUMN last_scan_received_at TIMESTAMPTZ;
ALTER TABLE host ADD COLUMN last_scan_rule_count INTEGER;
ALTER TABLE host ADD COLUMN last_scan_ruleset_fingerprint TEXT;
ALTER TABLE host ADD COLUMN last_scan_matched_count INTEGER;
