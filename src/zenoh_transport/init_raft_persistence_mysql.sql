/* Last Raft-committed state per key-id, restored into KeyStates on startup */
CREATE TABLE IF NOT EXISTS raft_key_states (
    key_id VARCHAR(255) NOT NULL,
    state VARCHAR(32) NOT NULL,
    PRIMARY KEY (key_id)
);

/* Append-only history of committed transitions, keyed by request_id for idempotency */
CREATE TABLE IF NOT EXISTS raft_committed_requests (
    request_id VARCHAR(64) NOT NULL,
    key_id VARCHAR(255) NOT NULL,
    from_state VARCHAR(32) NOT NULL,
    to_state VARCHAR(32) NOT NULL,
    master_kme VARCHAR(255) NOT NULL,
    slave_kme VARCHAR(255) NOT NULL,
    committed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (request_id),
    INDEX (key_id)
);
