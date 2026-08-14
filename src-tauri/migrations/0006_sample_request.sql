-- Phase 1 PR #8: sample retrieval, write path only (request + agent
-- fulfillment). Reading retrieved sample content back out is deferred to
-- a follow-up PR, the same way PR #6 (write sightings) preceded PR #7
-- (read sightings) -- this PR only needs to get bytes off a host and
-- record what happened; a download endpoint is its own scope.
--
-- sample_blob is content-addressed by sha256, the same convention
-- `indicator` already uses: the same file retrieved from two different
-- hosts (or the same host twice) is stored once, not duplicated. Raw
-- bytes in Postgres (BYTEA), not a separate object store -- the simplest
-- thing that works for Phase 1. See docs/phase1-design.md for what that
-- deliberately doesn't cover yet (no encryption at rest, no size-tiered
-- storage, no retention/TTL policy for old samples).
CREATE TABLE sample_blob (
    sha256 TEXT PRIMARY KEY,
    content BYTEA NOT NULL,
    size_bytes BIGINT NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per analyst request to pull a specific file off a specific
-- host. This *is* the audit trail the README's locked architecture
-- decision #3 ("file contents leave the host only on explicit analyst
-- request, logged and attributed") requires: what was asked for, from
-- which host, when, and what happened. "Attributed" is currently only to
-- "the operator" as an undifferentiated whole -- there is no per-user
-- operator identity yet (see PR #7's deferred RBAC note); this row
-- doesn't pretend otherwise.
--
-- expected_sha256 is optional: a request pivoting from an existing
-- sighting already knows the hash and can assert it; a cold request
-- (arbitrary path, hash unknown ahead of time) can't. When set, a
-- mismatch between the asserted hash and what the agent actually uploads
-- lands as 'mismatched', not silently accepted as 'fulfilled' -- see
-- sample.rs.
--
-- sha256 (nullable until resolved) references sample_blob once the
-- request is fulfilled or mismatched; it stays NULL if the request is
-- still pending or ended in 'failed' (the agent never got bytes to hash
-- at all).
CREATE TABLE sample_request (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES host(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    expected_sha256 TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'fulfilled', 'mismatched', 'failed')),
    failure_reason TEXT,
    sha256 TEXT REFERENCES sample_blob(sha256),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ
);
CREATE INDEX idx_sample_request_host ON sample_request (host_id);
-- Partial index: the only query pattern that needs to be fast at scale is
-- "what does this host still need to act on" (the agent's poll query),
-- which only ever touches pending rows -- resolved requests accumulate as
-- history and don't need to be in this index.
CREATE INDEX idx_sample_request_pending ON sample_request (host_id, status)
    WHERE status = 'pending';
