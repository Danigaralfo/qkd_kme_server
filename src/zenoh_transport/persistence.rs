//! Phase 7: durable persistence for Raft-lite state, so restarts do not lose consensus.
//!
//! Reuses the same database already configured for this KME's QKD keys (`db_uri`, via
//! [`crate::qkd_manager::QkdManager::db_pool`]/[`crate::qkd_manager::QkdManager::dbms_type`])
//! instead of standing up a separate datastore, so operators only have one database to run
//! and back up. Two tables (see `init_raft_persistence_*.sql`):
//! - `raft_key_states`: the last Raft-committed state for every key-id this node has ever
//!   seen. This is the durable source of truth [`super::raft::KeyStates`] is seeded from on
//!   startup - "node state" and "keys in transit" (a key found in `Syncing` is exactly one
//!   caught mid-flight by a crash) are both recovered from this single table.
//! - `raft_committed_requests`: append-only history of every committed transition, keyed by
//!   `request_id` - the "minimal request history" needed to make committing idempotent
//!   across restarts *and* across retried deliveries of an already-committed proposal (a
//!   follower re-validating a request it already applied would otherwise wrongly reject it,
//!   since its local state has since moved past `request.current_state`).
//!
//! Deliberately NOT persisted: proposals that have not reached quorum yet. A client always
//! proposes with a fresh `request_id` and already retries/times out on its own (see
//! `raft.rs`'s `RAFT_ACK_TIMEOUT`/`propose_transition_and_await_decision`), so losing an
//! in-flight proposal on crash is recovered for free by the caller's existing retry path;
//! persisting them would add real complexity (durable ack-tracking) for no correctness gain.
//!
//! Writes here are best-effort/write-through: a failure to durably persist a commit is
//! logged but does not block or roll back the in-memory Raft state, which remains the
//! operational source of truth while this node is up. This trades strict
//! write-ahead-of-broadcast guarantees for keeping the live cluster available even if the
//! shared database has a transient hiccup.

use crate::io_err;
use crate::qkd_manager::key_handler::DbmsType;
use crate::zenoh_transport::contract::ZenohKeyState;
use sqlx::{AnyPool, Executor, Row};
use std::collections::HashMap;
use std::io;

const INIT_SQLITE: &str = include_str!("init_raft_persistence_sqlite.sql");
const INIT_POSTGRES: &str = include_str!("init_raft_persistence_postgres.sql");
const INIT_MYSQL: &str = include_str!("init_raft_persistence_mysql.sql");

/// Durable, crash-recoverable store for Raft-lite key states and committed-transition
/// history. See module docs for the schema and design rationale.
#[derive(Clone)]
pub(crate) struct RaftPersistence {
    db: AnyPool,
    dbms_type: DbmsType,
}

impl RaftPersistence {
    /// Wrap the KME's existing database pool and ensure this module's own tables exist.
    pub(crate) async fn new(db: AnyPool, dbms_type: DbmsType) -> Result<Self, io::Error> {
        let init_sql = match dbms_type {
            DbmsType::Sqlite => INIT_SQLITE,
            DbmsType::Postgres => INIT_POSTGRES,
            DbmsType::MySQL => INIT_MYSQL,
        };
        db.execute(init_sql)
            .await
            .map_err(|e| io_err(&format!("Cannot create Raft persistence tables: {e}")))?;
        Ok(Self { db, dbms_type })
    }

    /// Every key-id's last committed state, to seed [`super::raft::KeyStates`] (and, on the
    /// leader, `LeaderState::committed_states`) on startup.
    pub(crate) async fn load_all_key_states(&self) -> Result<HashMap<String, ZenohKeyState>, io::Error> {
        let rows = sqlx::query("SELECT key_id, state FROM raft_key_states;")
            .fetch_all(&self.db)
            .await
            .map_err(|e| io_err(&format!("Cannot load persisted Raft key states: {e}")))?;

        let mut states = HashMap::with_capacity(rows.len());
        for row in rows {
            let key_id: String = row.try_get("key_id").map_err(|e| io_err(&format!("Cannot read persisted key_id: {e}")))?;
            let state_str: String = row.try_get("state").map_err(|e| io_err(&format!("Cannot read persisted state: {e}")))?;
            let state = key_state_from_str(&state_str)
                .ok_or_else(|| io_err(&format!("Unknown persisted Raft key state '{state_str}' for key '{key_id}'")))?;
            states.insert(key_id, state);
        }
        Ok(states)
    }

    /// Whether `request_id` has already been durably committed - the idempotency check used
    /// to detect a retried/replayed delivery of an already-applied proposal.
    pub(crate) async fn is_request_already_committed(&self, request_id: &str) -> Result<bool, io::Error> {
        let (postgres_or_sqlite, mysql) = (
            "SELECT 1 AS present FROM raft_committed_requests WHERE request_id = $1;",
            "SELECT 1 AS present FROM raft_committed_requests WHERE request_id = ?;",
        );
        let statement = match self.dbms_type {
            DbmsType::MySQL => mysql,
            DbmsType::Postgres | DbmsType::Sqlite => postgres_or_sqlite,
        };
        let row = sqlx::query(statement)
            .bind(request_id)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| io_err(&format!("Cannot check Raft committed-request history: {e}")))?;
        Ok(row.is_some())
    }

    /// Durably record a committed transition: append it to the `request_id`-keyed history
    /// (a no-op if `request_id` was already recorded) and upsert `key_id`'s last committed
    /// state. Called by both the leader (once quorum is reached) and every follower (once it
    /// applies the leader's commit broadcast) so each node's own durable view stays complete
    /// regardless of role.
    pub(crate) async fn record_commit(
        &self,
        request_id: &str,
        key_id: &str,
        from_state: ZenohKeyState,
        to_state: ZenohKeyState,
        master_kme: &str,
        slave_kme: &str,
    ) -> Result<(), io::Error> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| io_err(&format!("Cannot start Raft persistence transaction: {e}")))?;

        let (history_postgres_or_sqlite, history_mysql) = (
            "INSERT INTO raft_committed_requests (request_id, key_id, from_state, to_state, master_kme, slave_kme) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (request_id) DO NOTHING;",
            "INSERT IGNORE INTO raft_committed_requests (request_id, key_id, from_state, to_state, master_kme, slave_kme) \
             VALUES (?, ?, ?, ?, ?, ?);",
        );
        let history_statement = match self.dbms_type {
            DbmsType::MySQL => history_mysql,
            DbmsType::Postgres | DbmsType::Sqlite => history_postgres_or_sqlite,
        };
        sqlx::query(history_statement)
            .bind(request_id)
            .bind(key_id)
            .bind(key_state_to_str(from_state))
            .bind(key_state_to_str(to_state))
            .bind(master_kme)
            .bind(slave_kme)
            .execute(&mut *tx)
            .await
            .map_err(|e| io_err(&format!("Cannot append Raft committed-request history: {e}")))?;

        let (state_postgres_or_sqlite, state_mysql) = (
            "INSERT INTO raft_key_states (key_id, state) VALUES ($1, $2) \
             ON CONFLICT (key_id) DO UPDATE SET state = excluded.state;",
            "INSERT INTO raft_key_states (key_id, state) VALUES (?, ?) \
             ON DUPLICATE KEY UPDATE state = VALUES(state);",
        );
        let state_statement = match self.dbms_type {
            DbmsType::MySQL => state_mysql,
            DbmsType::Postgres | DbmsType::Sqlite => state_postgres_or_sqlite,
        };
        sqlx::query(state_statement)
            .bind(key_id)
            .bind(key_state_to_str(to_state))
            .execute(&mut *tx)
            .await
            .map_err(|e| io_err(&format!("Cannot persist Raft key state: {e}")))?;

        tx.commit().await.map_err(|e| io_err(&format!("Cannot commit Raft persistence transaction: {e}")))
    }
}

fn key_state_to_str(state: ZenohKeyState) -> &'static str {
    match state {
        ZenohKeyState::Generated => "generated",
        ZenohKeyState::Syncing => "syncing",
        ZenohKeyState::InUse => "in_use",
        ZenohKeyState::DeletedOrUsed => "deleted_or_used",
    }
}

fn key_state_from_str(s: &str) -> Option<ZenohKeyState> {
    match s {
        "generated" => Some(ZenohKeyState::Generated),
        "syncing" => Some(ZenohKeyState::Syncing),
        "in_use" => Some(ZenohKeyState::InUse),
        "deleted_or_used" => Some(ZenohKeyState::DeletedOrUsed),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opens a fresh `RaftPersistence` over a uniquely-named SQLite file under `tests/tmp`,
    /// so tests can simulate a real restart by dropping the pool and reopening a new one
    /// against the same file (unlike `sqlite::memory:`, which cannot be reopened). A relative
    /// path is used (matching the repo's existing `sqlite://tests/tmp/...` convention, see
    /// `tests/data/test_kme_config_sqlite.json5`) because sqlx's `sqlite://` URL scheme does
    /// not correctly parse an absolute Windows path with a drive letter.
    async fn open_temp_sqlite_persistence(path: &str) -> RaftPersistence {
        sqlx::any::install_default_drivers();
        let db = sqlx::any::AnyPoolOptions::new()
            .connect_lazy(&format!("sqlite://{path}?mode=rwc"))
            .expect("valid sqlite URI");
        RaftPersistence::new(db, DbmsType::Sqlite).await.expect("tables created")
    }

    fn temp_sqlite_path(test_name: &str) -> String {
        std::fs::create_dir_all("tests/tmp").expect("tests/tmp exists");
        format!("tests/tmp/raft_persistence_test_{test_name}_{}.sqlite3", uuid::Uuid::new_v4())
    }

    #[tokio::test]
    async fn record_commit_and_load_all_key_states_roundtrip() {
        let path = temp_sqlite_path("roundtrip");
        let persistence = open_temp_sqlite_persistence(&path).await;

        persistence
            .record_commit("req-1", "key-1", ZenohKeyState::Generated, ZenohKeyState::Syncing, "kme-1", "kme-2")
            .await
            .expect("commit persisted");
        persistence
            .record_commit("req-2", "key-2", ZenohKeyState::Generated, ZenohKeyState::Syncing, "kme-1", "kme-2")
            .await
            .expect("commit persisted");

        let states = persistence.load_all_key_states().await.expect("states loaded");
        assert_eq!(states.get("key-1"), Some(&ZenohKeyState::Syncing));
        assert_eq!(states.get("key-2"), Some(&ZenohKeyState::Syncing));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn record_commit_upserts_the_current_state_of_the_same_key() {
        let path = temp_sqlite_path("upsert");
        let persistence = open_temp_sqlite_persistence(&path).await;

        persistence
            .record_commit("req-1", "key-1", ZenohKeyState::Generated, ZenohKeyState::Syncing, "kme-1", "kme-2")
            .await
            .expect("commit persisted");
        persistence
            .record_commit("req-2", "key-1", ZenohKeyState::Syncing, ZenohKeyState::InUse, "kme-1", "kme-2")
            .await
            .expect("commit persisted");

        let states = persistence.load_all_key_states().await.expect("states loaded");
        assert_eq!(states.len(), 1);
        assert_eq!(states.get("key-1"), Some(&ZenohKeyState::InUse));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn is_request_already_committed_detects_duplicates_and_unknown_ids() {
        let path = temp_sqlite_path("duplicates");
        let persistence = open_temp_sqlite_persistence(&path).await;

        persistence
            .record_commit("req-1", "key-1", ZenohKeyState::Generated, ZenohKeyState::Syncing, "kme-1", "kme-2")
            .await
            .expect("commit persisted");

        assert!(persistence.is_request_already_committed("req-1").await.expect("check succeeds"));
        assert!(!persistence.is_request_already_committed("never-seen").await.expect("check succeeds"));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn recording_the_same_request_id_twice_does_not_duplicate_history_or_fail() {
        let path = temp_sqlite_path("dedup");
        let persistence = open_temp_sqlite_persistence(&path).await;

        persistence
            .record_commit("req-1", "key-1", ZenohKeyState::Generated, ZenohKeyState::Syncing, "kme-1", "kme-2")
            .await
            .expect("commit persisted");
        // Same request_id delivered again (e.g. a retried replication message): must not
        // error out, and must not change the already-committed state.
        persistence
            .record_commit("req-1", "key-1", ZenohKeyState::Generated, ZenohKeyState::Syncing, "kme-1", "kme-2")
            .await
            .expect("duplicate commit is a harmless no-op");

        let states = persistence.load_all_key_states().await.expect("states loaded");
        assert_eq!(states.get("key-1"), Some(&ZenohKeyState::Syncing));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn persisted_state_survives_reopening_the_same_database_file() {
        let path = temp_sqlite_path("restart");
        let path_str = path.clone();

        {
            let persistence = open_temp_sqlite_persistence(&path_str).await;
            persistence
                .record_commit("req-1", "key-1", ZenohKeyState::Syncing, ZenohKeyState::InUse, "kme-1", "kme-2")
                .await
                .expect("commit persisted");
            // `persistence` (and its pool) is dropped here, simulating process shutdown.
        }

        // Fresh pool/instance against the same file, simulating a restart.
        let persistence_after_restart = open_temp_sqlite_persistence(&path_str).await;
        let states = persistence_after_restart.load_all_key_states().await.expect("states loaded after restart");
        assert_eq!(states.get("key-1"), Some(&ZenohKeyState::InUse));
        assert!(persistence_after_restart.is_request_already_committed("req-1").await.expect("check succeeds"));

        let _ = std::fs::remove_file(path);
    }
}
