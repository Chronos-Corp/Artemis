-- Phase 1 PR #6: a fleet host observing an indicator becomes its own edge,
-- distinct from detection_detects_indicator (which says "this detection
-- flags this indicator" in the abstract -- the same edge Phase 0's local
-- desktop verdict engine already writes for local YARA hits). This edge
-- says "this specific fleet host observed that indicator," which is what
-- turns the console into a fleet view instead of just a shared feed.
--
-- ruleset_fingerprint is part of the primary key, not just a column: rule
-- content can change after a match is recorded, so a sighting citing only
-- a rule name becomes unreconstructable evidence once that rule is
-- edited. The same host reporting the same indicator again under a
-- materially different ruleset creates a new, distinct row instead of
-- silently merging into (and losing the history of) an earlier one; the
-- console assigns this from YaraEngine::ruleset_fingerprint, never the
-- agent's own claim about which ruleset it used.
--
-- received_at is when the console first accepted this specific
-- (host, indicator, source, ruleset_fingerprint) fact, independent of the
-- agent-claimed first_seen/last_seen below -- see the review discussion
-- on PR #6 about not letting a single misconfigured or compromised
-- endpoint clock poison first_seen/last_seen extrema that later,
-- legitimate sightings can never repair. Set once at first insert, never
-- updated on conflict.
--
-- path is nullable (not every indicator kind sightings will eventually
-- cover has a file path). On conflict it only advances to the newly
-- reported value when that report's observation is at least as recent as
-- what's already stored (see sighting.rs's upsert query) -- otherwise an
-- out-of-order report could regress "where it was last seen" to a stale
-- path.
CREATE TABLE host_sighted_indicator (
    host_id UUID NOT NULL REFERENCES host(id) ON DELETE CASCADE,
    indicator_id UUID NOT NULL REFERENCES indicator(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    path TEXT,
    ruleset_fingerprint TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (host_id, indicator_id, source, ruleset_fingerprint)
);
CREATE INDEX idx_hsi_host ON host_sighted_indicator (host_id);
CREATE INDEX idx_hsi_indicator ON host_sighted_indicator (indicator_id);
