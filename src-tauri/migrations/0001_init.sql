-- Intel graph schema.
--
-- Source, confidence, and first/last-seen live on edges, not nodes. The same
-- hash arrives from multiple feeds with differing confidence; this schema
-- surfaces that disagreement instead of flattening it to a single verdict.
--
-- Graph shape:
--   Indicator (hash | path | regkey | mutex | domain | ip) --observed_in--> Report
--   Report --references--> CVE
--   CVE --attributed_to--> Actor/Campaign
--   Detection (YARA | Sigma) --detects--> Indicator
--   Detection --covers--> CVE

CREATE TYPE indicator_kind AS ENUM (
    'sha256', 'md5', 'sha1',
    'imphash', 'tlsh', 'ssdeep',
    'path', 'regkey', 'mutex', 'domain', 'ip'
);

CREATE TYPE detection_kind AS ENUM ('yara', 'sigma');

CREATE TYPE actor_kind AS ENUM ('actor', 'campaign');

CREATE TABLE indicator (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind indicator_kind NOT NULL,
    value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, value)
);
CREATE INDEX idx_indicator_value ON indicator (value);

CREATE TABLE report (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source TEXT NOT NULL,
    external_id TEXT,
    title TEXT,
    url TEXT,
    published_at TIMESTAMPTZ,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    raw JSONB,
    UNIQUE (source, external_id)
);

CREATE TABLE cve (
    id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score REAL,
    published_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE actor (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind actor_kind NOT NULL,
    name TEXT NOT NULL,
    aliases TEXT[] NOT NULL DEFAULT '{}',
    description TEXT,
    UNIQUE (kind, name)
);

CREATE TABLE detection (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind detection_kind NOT NULL,
    name TEXT NOT NULL,
    rule_source TEXT,
    rule_body TEXT,
    author TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, name)
);

-- Edges: source, confidence, first_seen, last_seen live here so the same
-- fact from two feeds does not collapse into one number.

CREATE TABLE indicator_observed_in_report (
    indicator_id UUID NOT NULL REFERENCES indicator(id) ON DELETE CASCADE,
    report_id UUID NOT NULL REFERENCES report(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (indicator_id, report_id, source)
);
CREATE INDEX idx_iorr_indicator ON indicator_observed_in_report (indicator_id);

CREATE TABLE report_references_cve (
    report_id UUID NOT NULL REFERENCES report(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (report_id, cve_id, source)
);
CREATE INDEX idx_rrc_cve ON report_references_cve (cve_id);

CREATE TABLE cve_attributed_to_actor (
    cve_id TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    actor_id UUID NOT NULL REFERENCES actor(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (cve_id, actor_id, source)
);

CREATE TABLE detection_detects_indicator (
    detection_id UUID NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    indicator_id UUID NOT NULL REFERENCES indicator(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (detection_id, indicator_id, source)
);
CREATE INDEX idx_ddi_indicator ON detection_detects_indicator (indicator_id);

CREATE TABLE detection_covers_cve (
    detection_id UUID NOT NULL REFERENCES detection(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (detection_id, cve_id, source)
);

-- Local per-host hash cache, keyed on path + size + mtime so rescans are
-- near-instant. usn stays NULL until the Windows agent can read the USN
-- journal; Phase 0 runs cross-platform and cannot rely on it.
CREATE TABLE hash_cache (
    path TEXT NOT NULL,
    size BIGINT NOT NULL,
    mtime TIMESTAMPTZ NOT NULL,
    usn BIGINT,
    sha256 TEXT NOT NULL,
    md5 TEXT,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (path, size, mtime)
);

-- Tracks incremental ingestion progress per feed source.
CREATE TABLE feed_sync_state (
    source TEXT PRIMARY KEY,
    last_synced_at TIMESTAMPTZ,
    last_cursor TEXT
);
