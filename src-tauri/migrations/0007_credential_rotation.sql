-- Phase 1 PR #12: credential rotation and revocation. Neither existed
-- before this -- a compromised or decommissioned host's credential could
-- only be invalidated by deleting its `host` row outright, losing its
-- sighting/sample-request history along with it.
--
-- An append-only event log, not a single "last changed" timestamp on
-- `host`: a column that's overwritten on every rotate/revoke would lose
-- exactly the provenance this PR exists to preserve -- e.g. revoke during
-- a compromise, rotate during recovery, rotate again later would leave
-- only the final timestamp, with no record that a revocation ever
-- happened or when. `event_type` is deliberately just an enum tag with a
-- timestamp for Phase 1, not per-analyst identity or a reason -- there is
-- no per-user operator identity yet (see docs/phase1-design.md), so
-- there's nothing truthful to attribute an event to beyond "the operator,
-- as a whole."
CREATE TABLE host_credential_event (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES host(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL CHECK (event_type IN ('rotated', 'revoked')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_host_credential_event_host_id ON host_credential_event (host_id);
