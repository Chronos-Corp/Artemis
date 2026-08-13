-- Phase 1 PR #4: enrollment now mints a per-agent credential instead of
-- leaving the reserved column unused. Renamed for clarity, since this is
-- NOT the bootstrap enrollment secret (that's a single console-operator-
-- configured value, never stored per host) -- it's the hash of the
-- unique credential minted for this one host at enroll time. NOT NULL
-- because every host enrolled from this point on has one; see
-- docs/phase1-design.md.
ALTER TABLE host RENAME COLUMN enrollment_token_hash TO credential_hash;
ALTER TABLE host ALTER COLUMN credential_hash SET NOT NULL;
