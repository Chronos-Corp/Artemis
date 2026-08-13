-- Phase 1 PR #6: a fleet host observing an indicator becomes its own edge,
-- distinct from detection_detects_indicator (which says "this detection
-- flags this indicator" in the abstract -- the same edge Phase 0's local
-- desktop verdict engine already writes for local YARA hits). This edge
-- says "this specific fleet host observed that indicator," which is what
-- turns the console into a fleet view instead of just a shared feed.
--
-- path is nullable (not every indicator kind sightings will eventually
-- cover has a file path) and always overwritten with the latest reported
-- value on conflict, since "where it was last seen" is the useful
-- semantic, not "where it was first seen."
CREATE TABLE host_sighted_indicator (
    host_id UUID NOT NULL REFERENCES host(id) ON DELETE CASCADE,
    indicator_id UUID NOT NULL REFERENCES indicator(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    path TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (host_id, indicator_id, source)
);
CREATE INDEX idx_hsi_host ON host_sighted_indicator (host_id);
CREATE INDEX idx_hsi_indicator ON host_sighted_indicator (indicator_id);
