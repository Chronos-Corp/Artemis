-- Phase 1: one row per fleet host that has enrolled with the console.
--
-- No authentication is wired up yet (see docs/phase1-design.md);
-- enrollment_token_hash is reserved for when that lands and stays nullable
-- until then. hostname is intentionally not unique: VMs and containers can
-- legitimately share a hostname, and disambiguating hosts is not solved by
-- a database constraint.
CREATE TABLE host (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    enrollment_token_hash TEXT,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat_at TIMESTAMPTZ
);
CREATE INDEX idx_host_hostname ON host (hostname);
