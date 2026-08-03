-- Speeds up tier 4 (path/naming pattern): the query filters on
-- indicator.kind = 'path' before running the ILIKE substring test, so an
-- index on kind alone keeps that filter cheap regardless of how large the
-- indicator table (dominated by hash rows) grows.
CREATE INDEX idx_indicator_kind ON indicator (kind);

-- Speeds up tier 5 (contextual): file_name comparisons are an exact,
-- case-insensitive match, not a substring search, so a functional index on
-- the lowercased value turns what was a full sequential scan of the report
-- table (see contextual_matches) into an index lookup.
CREATE INDEX idx_report_file_name_lower ON report ((lower(raw ->> 'file_name')));
