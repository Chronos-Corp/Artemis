-- Phase 1 PR #12: credential rotation and revocation. Neither existed
-- before this -- a compromised or decommissioned host's credential could
-- only be invalidated by deleting its `host` row outright, losing its
-- sighting/sample-request history along with it.
--
-- credential_rotated_at tracks the most recent rotate-or-revoke event,
-- distinct from enrolled_at (which never changes after the initial
-- enrollment). NULL means the host's credential is still the one minted
-- at enrollment.
ALTER TABLE host ADD COLUMN credential_rotated_at TIMESTAMPTZ;
