-- registry/schema.sql — the real four-table record schema for the Phase-4
-- identifier registry (lens-A §2 data model).
--
-- SCHEMA-OF-RECORD ONLY. No live binding is created this increment (RAILS: no
-- D1/R2/KV provisioned). This DDL is the artifact the live-binding provisioning
-- ticket (bd model-gap) implements against. It is written in SQLite/D1 dialect
-- as the concrete point-lookup shape; lens-A's target body store is R2 + parquet
-- partitioned by GCP prefix + grain, of which these tables are the logical model.
--
-- The four tables have INDEPENDENT lifecycles (lens-A §2): a brand proves
-- ownership once (owner_ref) and writes linksets thousands of times (linkset,
-- link_entry) without re-proving; an individual claims one instance
-- (identifier_record with an instance-scoped owner_ref) without touching the
-- class record; policy (policy_ref) inherits class → lot → instance.

-- ── owner_ref: the proven claimant (written once per proof) ──────────────────
CREATE TABLE IF NOT EXISTS owner_ref (
  owner_id      TEXT PRIMARY KEY,           -- org_… | human_… | agent_…
  claim_method  TEXT NOT NULL,              -- gcp-vc | dns | vc | anchor
  claim_subject TEXT NOT NULL,              -- owner id the claim binds
  scope_kind    TEXT NOT NULL,              -- range | instance | hostname
  scope_value   TEXT NOT NULL,              -- gcpPrefix | key | host (per scope_kind)
  proof_digest  TEXT NOT NULL,              -- hash over the proof artifact
  proved_at     TEXT NOT NULL,              -- ISO-8601
  strength      TEXT NOT NULL,              -- range | hostname | attested | anchored
  gcp_prefix    TEXT,                       -- for GS1 keys: the ASSERTED licensed prefix (never derived)
  updated_at    TEXT NOT NULL
);

-- ── linkset: the RFC 9264 set (written thousands of times per owner) ─────────
CREATE TABLE IF NOT EXISTS linkset (
  id            TEXT PRIMARY KEY,
  default_link  TEXT NOT NULL,              -- linkId | 'gs1:pip' — the 303 target
  well_known_ref TEXT,                      -- → resolver capability advert
  updated_at    TEXT NOT NULL
);

-- link_entry: one row per link in a linkset (RFC 9264 relation → target).
CREATE TABLE IF NOT EXISTS link_entry (
  linkset_id    TEXT NOT NULL REFERENCES linkset(id),
  link_type     TEXT NOT NULL,             -- full relation URI (gs1:* or id:* superset)
  href          TEXT NOT NULL,
  title         TEXT,
  hreflang      TEXT,
  media_type    TEXT,                      -- the RFC 9264 "type" attribute
  grain         TEXT,                      -- class | lot | instance | place | asset | document
  ord           INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (linkset_id, link_type, href)
);

-- ── policy_ref: tier / cacheability / existence-neutrality (inherited) ───────
CREATE TABLE IF NOT EXISTS policy_ref (
  id                TEXT PRIMARY KEY,
  tier              INTEGER NOT NULL,
  cacheable         INTEGER NOT NULL,      -- 0|1
  existence_neutral INTEGER NOT NULL,      -- 0|1
  offer_bindings    TEXT                   -- JSON array of linkIds, nullable
);

-- ── identifier_record: the joining record ────────────────────────────────────
-- Partition key is (gcp_prefix, grain) — lens-A §2 R2/parquet partitioning. A
-- resolve is a point lookup: prefix → partition → key.
CREATE TABLE IF NOT EXISTS identifier_record (
  key           TEXT PRIMARY KEY,          -- canonical uncompressed DL path, grain-typed
  grain         TEXT NOT NULL,             -- class | lot | instance | place | asset | document
  canonical_id  TEXT NOT NULL,             -- the {type}_{sqid} $id it dereferences to
  owner_ref     TEXT NOT NULL REFERENCES owner_ref(owner_id),
  linkset_ref   TEXT NOT NULL REFERENCES linkset(id),
  default_link  TEXT NOT NULL,             -- linkId | 'gs1:pip'
  policy_ref    TEXT REFERENCES policy_ref(id),  -- nullable: inherit class → lot → instance
  prov_proof_id TEXT NOT NULL,
  prov_proved_at TEXT NOT NULL,
  prov_method   TEXT NOT NULL,             -- gcp-vc | dns | vc | anchor
  gcp_prefix    TEXT,                      -- partition key component (ASSERTED, never derived)
  etag          TEXT NOT NULL,             -- edge-cache versioning; a linkset write bumps + purges
  updated_at    TEXT NOT NULL
);

-- Point-lookup + partition-scan indexes (lens-A §2 "prefix → partition → key").
CREATE INDEX IF NOT EXISTS idx_identifier_partition ON identifier_record (gcp_prefix, grain);
CREATE INDEX IF NOT EXISTS idx_identifier_owner ON identifier_record (owner_ref);
CREATE INDEX IF NOT EXISTS idx_link_entry_linkset ON link_entry (linkset_id);
