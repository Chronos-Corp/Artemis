-- Phase 1 PR #6: a fleet host observing an indicator through a specific
-- detection becomes its own edge, distinct from detection_detects_indicator
-- (which says "this detection flags this indicator" in the abstract -- the
-- same edge Phase 0's local desktop verdict engine already writes for
-- local YARA hits). This edge preserves the full authenticated claim a
-- sighting actually makes: host H observed indicator X through detection R
-- under ruleset V. detection_id is part of the row (and the primary key),
-- not dropped: without it, two different hosts each matching a different
-- rule against the same hash would be indistinguishable from the console's
-- perspective -- "host A saw X" and "host B saw X" both recorded, but
-- which host matched which rule lost.
--
-- ruleset_fingerprint is part of the primary key too: rule content can
-- change after a match is recorded, so a sighting citing only a rule name
-- becomes unreconstructable evidence once that rule is edited. The same
-- host reporting the same indicator+detection again under a materially
-- different ruleset creates a new, distinct row instead of silently
-- merging into (and losing the history of) an earlier one. This is an
-- agent-reported value from an authenticated host, not something the
-- console independently verifies against real rule content -- the console
-- only checks that it looks like a 64-character lowercase SHA-256 (see
-- sighting.rs's validate_lowercase_sha256). It becomes console-verifiable
-- only once the console itself distributes or maintains known rulesets.
--
-- received_at is when the console first accepted this specific
-- (host, detection, indicator, source, ruleset_fingerprint) fact,
-- independent of the agent-claimed first_seen/last_seen below. A
-- compromised or misconfigured endpoint clock can still report any
-- observed_at within the bounds sighting.rs enforces (2020-01-01 through
-- 5 minutes ahead of the console's clock) -- received_at does not prevent
-- that, it gives analysts a server-controlled anchor alongside the
-- endpoint's claimed observation time so a suspect clock is at least
-- visible, not an unrecoverable poisoned extremum that can never be
-- distinguished from a legitimate one.
--
-- path is nullable (not every indicator kind sightings will eventually
-- cover has a file path). On conflict it only advances to the newly
-- reported value when that report's observation is at least as recent as
-- what's already stored (see sighting.rs's upsert query) -- otherwise an
-- out-of-order report could regress "where it was last seen" to a stale
-- path.
CREATE TABLE host_sighted_indicator (
    host_id UUID NOT NULL REFERENCES host(id) ON DELETE CASCADE,
    detection_id UUID NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    indicator_id UUID NOT NULL REFERENCES indicator(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    path TEXT,
    ruleset_fingerprint TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (host_id, detection_id, indicator_id, source, ruleset_fingerprint)
);
CREATE INDEX idx_hsi_host ON host_sighted_indicator (host_id);
CREATE INDEX idx_hsi_indicator ON host_sighted_indicator (indicator_id);
CREATE INDEX idx_hsi_detection ON host_sighted_indicator (detection_id);
