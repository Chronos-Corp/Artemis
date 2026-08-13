-- Phase 1 PR #4: enrollment now mints a per-agent credential instead of
-- leaving the reserved column unused. Renamed for clarity, since this is
-- NOT the bootstrap enrollment secret (that's a single console-operator-
-- configured value, never stored per host) -- it's the hash of the
-- unique credential minted for this one host at enroll time.
--
-- Any host enrolled under PR #3 (before this credential concept existed)
-- has no credential and therefore nothing to hash here. Back-filling with
-- a sentinel that can never equal a real SHA-256 hex digest -- rather than
-- deleting the row outright, or leaving it NULL and skipping NOT NULL --
-- means those hosts simply cannot authenticate a heartbeat until they
-- re-enroll (which mints them a real credential), while their enrollment
-- history is preserved instead of silently dropped. See
-- crates/nsic-core/src/db.rs's migration_0004_backfills_legacy_hosts_
-- without_a_credential test, which exercises exactly this upgrade path.
ALTER TABLE host RENAME COLUMN enrollment_token_hash TO credential_hash;
UPDATE host SET credential_hash = 'legacy-host-requires-re-enrollment'
    WHERE credential_hash IS NULL;
ALTER TABLE host ALTER COLUMN credential_hash SET NOT NULL;
