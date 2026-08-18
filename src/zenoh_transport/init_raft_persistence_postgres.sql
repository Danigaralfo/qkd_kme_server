/* Last Raft-committed state per key-id, restored into KeyStates on startup */
CREATE TABLE IF NOT EXISTS raft_key_states (
    key_id TEXT PRIMARY KEY,
    state TEXT NOT NULL
);

/* Append-only history of committed transitions, keyed by request_id for idempotency */
CREATE TABLE IF NOT EXISTS raft_committed_requests (
    request_id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    master_kme TEXT NOT NULL,
    slave_kme TEXT NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_raft_committed_requests_keyid ON raft_committed_requests(key_id);
