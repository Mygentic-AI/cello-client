-- V2__client_schema_structured.sql
-- CELLO-PERSIST-024: Structured client-side SQLCipher schema.
--
-- This migration:
--   1. Drops the V1 client_store table (placeholder KV store, no production users)
--   2. Creates 18 structured tables covering all durable state
--
-- All data at rest is protected by SQLCipher (AES-256-CBC with PBKDF2 key derivation).
-- The db_key is never stored here — derived at runtime from K_local via HKDF.

-- Drop the placeholder KV table — all state migrates to structured tables.
DROP TABLE IF EXISTS client_store;

-- ── 1. agents ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agents (
    pubkey              TEXT    NOT NULL,
    agent_name          TEXT    NOT NULL DEFAULT '',
    key_file_path       TEXT    NOT NULL,
    ml_dsa_key_file_path TEXT,
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    is_active           INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (pubkey)
);

-- ── 2. registration_state ────────────────────────────────────
CREATE TABLE IF NOT EXISTS registration_state (
    agent_pubkey    TEXT    NOT NULL,
    agent_id        TEXT    NOT NULL,
    primary_pubkey  TEXT    NOT NULL,
    ml_dsa_pubkey   TEXT    NOT NULL,
    registered_at   INTEGER NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active')),
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (agent_pubkey),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE,
    UNIQUE (agent_id)
);

-- ── 3. frost_key_shares ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS frost_key_shares (
    agent_pubkey            TEXT    NOT NULL,
    epoch_id                TEXT    NOT NULL,
    primary_pubkey          TEXT    NOT NULL,
    identifier              TEXT    NOT NULL,
    signing_share           BLOB    NOT NULL,
    threshold               INTEGER NOT NULL,
    participants            INTEGER NOT NULL,
    commitments_cbor        BLOB    NOT NULL,
    verifying_shares_cbor   BLOB    NOT NULL,
    dkg_method              TEXT    NOT NULL CHECK (dkg_method IN ('trusted_dealer','network_dkg')),
    is_active               INTEGER NOT NULL DEFAULT 1,
    created_at              TEXT    NOT NULL DEFAULT (datetime('now')),
    validated_at            TEXT,
    PRIMARY KEY (agent_pubkey, epoch_id),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_frost_key_shares_active
    ON frost_key_shares(agent_pubkey) WHERE is_active = 1;

-- ── 4. ml_dsa_keypairs ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS ml_dsa_keypairs (
    agent_pubkey        TEXT    NOT NULL,
    ml_dsa_pubkey       TEXT    NOT NULL,
    secret_key_blob     BLOB    NOT NULL,
    algorithm           TEXT    NOT NULL DEFAULT 'ML-DSA-44',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (agent_pubkey),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE
);

-- ── 5. connection_policy ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS connection_policy (
    agent_pubkey    TEXT    NOT NULL,
    mode            TEXT    NOT NULL CHECK (mode IN ('open','selective','guarded','closed')),
    review_mode     TEXT    NOT NULL CHECK (review_mode IN ('deterministic','inference')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (agent_pubkey),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE
);

-- ── 6. connection_policy_requirements ───────────────────────
CREATE TABLE IF NOT EXISTS connection_policy_requirements (
    agent_pubkey    TEXT    NOT NULL,
    position        INTEGER NOT NULL,
    signal_type     TEXT    NOT NULL CHECK (signal_type IN ('endorsement','attestation','pseudonym_age','registration_age')),
    condition_json  TEXT    NOT NULL,
    PRIMARY KEY (agent_pubkey, position),
    FOREIGN KEY (agent_pubkey) REFERENCES connection_policy(agent_pubkey) ON DELETE CASCADE
);

-- ── 7. connections ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS connections (
    connection_id               TEXT    NOT NULL,
    agent_pubkey                TEXT    NOT NULL,
    counterparty_pubkey         TEXT    NOT NULL,
    counterparty_primary_pubkey TEXT    NOT NULL DEFAULT '',
    counterparty_ml_dsa_pubkey  TEXT    NOT NULL DEFAULT '',
    established_at              INTEGER NOT NULL,
    status                      TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active')),
    profile_unchecked           INTEGER NOT NULL DEFAULT 0,
    created_at                  TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (connection_id),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE,
    UNIQUE (agent_pubkey, counterparty_pubkey)
);
CREATE INDEX IF NOT EXISTS idx_connections_agent ON connections(agent_pubkey);

-- ── 8. endorsements ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS endorsements (
    agent_pubkey            TEXT    NOT NULL,
    endorser_pubkey         TEXT    NOT NULL,
    endorser_ml_dsa_pubkey  BLOB    NOT NULL,
    target_pubkey           TEXT    NOT NULL,
    endorsement_type        TEXT    NOT NULL,
    created_at              INTEGER NOT NULL,
    expires_at              INTEGER NOT NULL,
    endorser_ml_dsa_sig     BLOB    NOT NULL,
    received_at             TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (agent_pubkey, endorser_pubkey),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_endorsements_expires ON endorsements(expires_at);

-- ── 9. attestations ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attestations (
    agent_pubkey            TEXT    NOT NULL,
    attester_pubkey         TEXT    NOT NULL,
    attestation_type        TEXT    NOT NULL,
    attester_ml_dsa_pubkey  BLOB    NOT NULL,
    attestation_data        BLOB    NOT NULL,
    created_at              INTEGER NOT NULL,
    expires_at              INTEGER NOT NULL,
    attester_ml_dsa_sig     BLOB    NOT NULL,
    received_at             TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (agent_pubkey, attester_pubkey, attestation_type),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_attestations_expires ON attestations(expires_at);

-- ── 10. peers ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS peers (
    agent_pubkey    TEXT    NOT NULL,
    peer_pubkey_hex TEXT    NOT NULL,
    peer_id         TEXT    NOT NULL,
    multiaddrs      TEXT    NOT NULL,
    added_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen_at    TEXT,
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (agent_pubkey, peer_pubkey_hex),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_peers_peer_id ON peers(agent_pubkey, peer_id);

-- ── 11. sessions ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    session_id              TEXT    NOT NULL,
    agent_pubkey            TEXT    NOT NULL,
    counterparty_pubkey     BLOB    NOT NULL,
    counterparty_peer_id    TEXT    NOT NULL,
    counterparty_multiaddrs TEXT    NOT NULL,
    relay_peer_id           TEXT    NOT NULL,
    relay_multiaddrs        TEXT    NOT NULL,
    directory_peer_id       TEXT    NOT NULL,
    directory_multiaddrs    TEXT    NOT NULL,
    directory_pubkey        BLOB    NOT NULL,
    genesis_prev_root       BLOB    NOT NULL,
    last_seen_seq           INTEGER NOT NULL DEFAULT 0,
    last_sent_seq           INTEGER NOT NULL DEFAULT 0,
    next_expected_seq       INTEGER NOT NULL DEFAULT 1,
    status                  TEXT    NOT NULL CHECK (status IN ('active','transport_lost','sealing','sealed','seal_rejected','seal_deferred')),
    desynchronized          INTEGER NOT NULL DEFAULT 0,
    leaf_count              INTEGER NOT NULL DEFAULT 0,
    sealed_root             BLOB,
    seal_type               TEXT    CHECK (seal_type IN ('frost','bilateral','unilateral')),
    close_timestamp         INTEGER,
    frost_signature         BLOB,
    signer_pubkey           BLOB,
    directory_signature     BLOB,
    checkpoint_status       TEXT    NOT NULL DEFAULT 'pending' CHECK (checkpoint_status IN ('pending','confirmed')),
    checkpoint_peak_hash    TEXT,
    checkpoint_leaf_index   INTEGER,
    checkpoint_sibling_hashes TEXT,
    created_at              TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at              TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (session_id, agent_pubkey),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_pubkey, status);

-- ── 12. session_tree_leaves ──────────────────────────────────
CREATE TABLE IF NOT EXISTS session_tree_leaves (
    session_id      TEXT    NOT NULL,
    agent_pubkey    TEXT    NOT NULL,
    leaf_index      INTEGER NOT NULL,
    leaf_kind       TEXT    NOT NULL CHECK (leaf_kind IN ('msg','ctrl')),
    s2_cbor         BLOB    NOT NULL,
    sequence_number INTEGER NOT NULL,
    accepted_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (session_id, agent_pubkey, leaf_index),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE,
    FOREIGN KEY (session_id, agent_pubkey) REFERENCES sessions(session_id, agent_pubkey) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_session_tree_leaves_seq
    ON session_tree_leaves(session_id, agent_pubkey, sequence_number);

-- ── 13. pending_hashes ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS pending_hashes (
    id              INTEGER NOT NULL PRIMARY KEY,
    agent_pubkey    TEXT    NOT NULL,
    session_id      TEXT    NOT NULL,
    hash_hex        TEXT    NOT NULL,
    enqueued_at     INTEGER NOT NULL,
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE,
    UNIQUE (agent_pubkey, session_id, hash_hex)
);
CREATE INDEX IF NOT EXISTS idx_pending_hashes_agent_session
    ON pending_hashes(agent_pubkey, session_id);

-- ── 14. relay_ack_receipts ───────────────────────────────────
CREATE TABLE IF NOT EXISTS relay_ack_receipts (
    hash_hex            TEXT    NOT NULL,
    agent_pubkey        TEXT    NOT NULL,
    session_id          TEXT    NOT NULL,
    relay_id            TEXT    NOT NULL,
    relay_pubkey_hex    TEXT    NOT NULL,
    sequence_number     INTEGER NOT NULL,
    relay_timestamp     INTEGER NOT NULL,
    signature_hex       TEXT    NOT NULL,
    acked_at            TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (hash_hex, agent_pubkey),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE
);

-- ── 15. backup_metadata ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS backup_metadata (
    agent_pubkey    TEXT    NOT NULL,
    completed_at    TEXT    NOT NULL,
    destination_url TEXT    NOT NULL,
    checksum        TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (agent_pubkey),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE
);

-- ── 16. known_relays ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS known_relays (
    relay_id        TEXT NOT NULL PRIMARY KEY,
    relay_pubkey_hex TEXT NOT NULL,
    source          TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── 17. pending_connection_requests ──────────────────────────
CREATE TABLE IF NOT EXISTS pending_connection_requests (
    request_id      TEXT    NOT NULL,
    agent_pubkey    TEXT    NOT NULL,
    from_pubkey     TEXT    NOT NULL,
    package_cbor    BLOB    NOT NULL,
    arrived_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    round           INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (request_id, agent_pubkey),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE
);

-- ── 18. decided_connection_requests ──────────────────────────
CREATE TABLE IF NOT EXISTS decided_connection_requests (
    request_id      TEXT    NOT NULL,
    agent_pubkey    TEXT    NOT NULL,
    decision        TEXT    NOT NULL CHECK (decision IN ('accepted','rejected','more_disclosure')),
    decided_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (request_id, agent_pubkey),
    FOREIGN KEY (agent_pubkey) REFERENCES agents(pubkey) ON DELETE CASCADE
);
