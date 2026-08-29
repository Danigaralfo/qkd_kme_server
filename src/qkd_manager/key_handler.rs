//! QKD manager key handler, supposed to run in a separate thread

use crate::event_subscription::ImportantEventSubscriber;
use crate::export_important_logging_message;
use crate::prepare_sql_arguments;
use crate::qkd_manager::http_response_obj::{ResponseQkdKey, ResponseQkdKeysList};
use crate::qkd_manager::inter_kme_transport::{HttpsInterKmeTransport, InterKmeTransport};
use crate::qkd_manager::{router, PreInitQkdKeyWrapper, QkdManagerResponse, SAEInfo};
use crate::zenoh_transport::contract::ZenohKeyState;
use crate::zenoh_transport::raft::KeyLifecycleAuthorizer;
use crate::{ensure_prepared_statement_ok, MEMORY_SQLITE_DB_PATH};
use crate::{io_err, qkd_manager, KmeId, RequestedKeyCount, SaeClientCertSerial, SaeId};
use base64::{engine::general_purpose, Engine as _};
use futures::future::join_all;
use futures::{TryFutureExt, TryStreamExt};
use log::{error, info, warn};
use sqlx::any::{AnyArguments, AnyPoolOptions};
use sqlx::{Arguments, Execute, Executor, QueryBuilder, Row, Statement, Transaction};
use sqlx_core::any::Any;
use std::cmp::PartialEq;
use std::collections::HashSet;
use std::sync::Arc;
use std::{io, vec};
use sqlx_core::HashMap;
use tokio::sync::{Mutex, RwLock};
use uuid::Bytes;
use x509_parser::nom::AsBytes;

/// Supported database management systems
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum DbmsType {
    Sqlite,
    Postgres,
    MySQL,
}

impl std::fmt::Display for DbmsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbmsType::Sqlite => write!(f, "SQLite"),
            DbmsType::Postgres => write!(f, "PostgreSQL"),
            DbmsType::MySQL => write!(f, "MySQL"),
        }
    }
}

/// Describes the key handler that will check authentication and manage the QKD keys in the database in a separate thread
#[derive(Clone)]
pub(crate) struct KeyHandler {
    /// Connection to the sqlite database (in memory or on disk)
    db: sqlx::AnyPool,
    /// The type of database management system used
    dbms_type: DbmsType,
    /// The ID of this KME
    this_kme_id: KmeId,
    /// Router on classical network, used to connect to other KMEs over unsecure classical network
    qkd_router: Arc<RwLock<router::QkdRouter>>,
    /// Subscribers to important events, for demonstration purpose
    event_notification_subscribers: Arc<RwLock<Vec<Arc<dyn ImportantEventSubscriber>>>>,
    /// Optional nickname for this KME, used for debugging purposes (eg "Alice" or "Bob")
    nickname: Option<String>,
    /// These key ids are currently being activated, you cannot activate them in a concurrent request
    blocked_key_ids: Arc<Mutex<HashSet<i64>>>,
    /// Optional Raft coordinator consulted before accepting sensitive cross-KME key-state
    /// transitions (see [`Self::set_raft_authorizer`]); `None` means no Raft cluster is
    /// configured and transitions are accepted locally without consensus, as before Phase 5
    raft_authorizer: Arc<RwLock<Option<Arc<dyn KeyLifecycleAuthorizer>>>>,
    /// Transport used to activate keys on other KMEs (see [`Self::set_inter_kme_transport`]);
    /// defaults to classical HTTPS, unchanged from before this abstraction existed
    inter_kme_transport: Arc<RwLock<Arc<dyn InterKmeTransport>>>,
    /// In-memory `KmeId -> shared key directory` map for every KME this KME has a genuine QKD
    /// link with (see [`Self::add_qkd_link`]). Used only in `ZenohRaft` transport mode, to know
    /// where to write a relayed key's raw bytes so the peer's own file watcher picks it up as if
    /// it had come from a real QKD link (see [`crate::qkd_manager::inter_kme_transport::HttpsInterKmeTransport`]).
    qkd_link_directories: Arc<RwLock<std::collections::HashMap<KmeId, String>>>,
    /// Optional resolver computing the next hop toward a key's true final destination KME, for
    /// multi-hop relay across KMEs with no direct QKD link (see [`Self::set_key_routing_resolver`]);
    /// `None` means no relay is possible (classical HTTPS mode, or `ZenohRaft` before this is
    /// installed), matching today's behavior of requiring a direct link to `target_kme_id`.
    key_routing_resolver: Arc<RwLock<Option<Arc<dyn crate::zenoh_transport::routing::KeyRoutingResolver>>>>,
}

impl KeyHandler {

    /// Create a new key handler
    /// # Arguments
    /// * `db_uri` - Database URI (eg `sqlite://:memory:` or `sqlite://path/to/db.sqlite3`)
    /// * `this_kme_id` - The ID of this KME
    /// * `kme_nickname` - The nickname of this KME, for debugging purposes
    /// # Returns
    /// A new key handler
    /// # Errors
    /// If the sqlite database cannot be opened or if the tables cannot be created
    pub(super) async fn new(db_uri: &str, this_kme_id: KmeId, kme_nickname: Option<String>) -> Result<Self, io::Error> {
        const SQLITE_DATABASE_INIT_REQ: &'static str = include_str!("init_qkd_database_sqlite.sql");
        const POSTGRES_DATABASE_INIT_REQ: &'static str = include_str!("init_qkd_database_postgres.sql");
        const MYSQL_DATABASE_INIT_REQ: &'static str = include_str!("init_qkd_database_mysql.sql");
        const IN_MEMORY_SQLITE_URI: &'static str = "sqlite::memory:";

        let dbms_type = Self::get_dbms_type_from_uri(db_uri)?;

        info!("Detected database type: {}", dbms_type);

        let database_initialization_req = match dbms_type {
            DbmsType::Sqlite => SQLITE_DATABASE_INIT_REQ,
            DbmsType::Postgres => POSTGRES_DATABASE_INIT_REQ,
            DbmsType::MySQL => MYSQL_DATABASE_INIT_REQ,
        };

        sqlx::any::install_default_drivers();

        let in_memory_database = db_uri == MEMORY_SQLITE_DB_PATH;

        let dbpool = AnyPoolOptions::new();
        let dbpool = if in_memory_database {
            dbpool
                .max_connections(1) // In memory database works only with a single connection
                .idle_timeout(None)
                .max_lifetime(None)
                .connect(IN_MEMORY_SQLITE_URI)
                .await
        } else {
            dbpool.connect_lazy(db_uri) // Save costs on Cloud bill
        }.map_err(|e| {
                io::Error::new(io::ErrorKind::NotConnected, format!("Error opening database: {:?}", e))
            })?;

        let qkd_router = Arc::new(RwLock::new(router::QkdRouter::new()));
        let other_kme_connections_cache = Arc::new(RwLock::new(HashMap::new()));
        let qkd_link_directories = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let inter_kme_transport: Arc<dyn InterKmeTransport> = Arc::new(HttpsInterKmeTransport::new(qkd_router.clone(), other_kme_connections_cache, qkd_link_directories.clone()));

        let key_handler = Self {
            db: dbpool,
            dbms_type,
            this_kme_id,
            qkd_router,
            event_notification_subscribers: Arc::new(RwLock::new(vec![])),
            nickname: kme_nickname,
            blocked_key_ids: Arc::new(Mutex::new(HashSet::with_capacity(8 * crate::MAX_QKD_KEYS_PER_REQUEST))),
            raft_authorizer: Arc::new(RwLock::new(None)),
            inter_kme_transport: Arc::new(RwLock::new(inter_kme_transport)),
            qkd_link_directories,
            key_routing_resolver: Arc::new(RwLock::new(None)),
        };
        // Create the tables if they do not exist
        key_handler.db.execute(database_initialization_req).await.map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Error creating database tables: {:?}", e))
        })?;
        Ok(key_handler)
    }

    pub(crate) fn db_pool(&self) -> sqlx::AnyPool {
        self.db.clone()
    }

    /// The DBMS backing this KME's database, see [`Self::db_pool`].
    pub(crate) fn dbms_type(&self) -> DbmsType {
        self.dbms_type
    }

    fn get_dbms_type_from_uri(db_uri: &str) -> Result<DbmsType, io::Error> {
        if db_uri == MEMORY_SQLITE_DB_PATH {
            return Ok(DbmsType::Sqlite);
        };
        let parsed_uri = uriparse::URI::try_from(db_uri).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid database URI: {}", db_uri))
        })?;
        match parsed_uri.scheme().as_str() {
            "sqlite" => Ok(DbmsType::Sqlite),
            "postgres" | "postgresql" => Ok(DbmsType::Postgres),
            "mysql" => Ok(DbmsType::MySQL),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid database URI: {}", db_uri)))
        }
    }

    /// Add the classical network info of a KME to the router
    /// # Arguments
    /// * `kme_id` - The ID of the KME to add
    /// * `kme_addr` - The IP address and port of the KME, in the form "ip:port" or "domain:port"
    /// * `client_auth_certificate_path` - The path to the client authentication certificate to use when connecting to the KME
    /// * `client_auth_certificate_password` - The password for the client authentication certificate
    /// * `should_ignore_system_proxy_config` - Whether to ignore the system proxy configuration when connecting to the KME
    pub(crate) async fn add_kme_classical_net_info(&self, kme_id: KmeId, kme_addr: &str, client_auth_certificate_path: &str, client_auth_certificate_password: &str, should_ignore_system_proxy_config: bool) -> Result<QkdManagerResponse, QkdManagerResponse>  {
        match self.qkd_router.as_ref().write().await.add_kme_to_ip_domain_port_association(kme_id, &kme_addr, &client_auth_certificate_path, &client_auth_certificate_password, should_ignore_system_proxy_config) {
            Ok(_) => Ok(QkdManagerResponse::Ok),
            Err(e) => {
                error!("Error adding KME classical network info: {:?}", e);
                Err(QkdManagerResponse::Ko)
            }
        }
    }

    /// Add subscriber to important events logging, for demonstration purpose
    /// # Arguments
    /// * `subscriber` - The subscriber to add
    pub(crate) async fn add_important_event_subscriber(&self, subscriber: Arc<dyn ImportantEventSubscriber>) -> Result<(), io::Error> {
        self.event_notification_subscribers.write().await.push(subscriber);
        Ok(())
    }

    /// Set (or replace) the Raft coordinator consulted before accepting sensitive cross-KME
    /// key-state transitions (see `get_sae_keys` and `activate_key_uuids_sae`). Optional and
    /// backward-compatible: as long as this is never called, this KME behaves exactly as it did
    /// before Phase 5 (no consensus gating at all).
    /// # Arguments
    /// * `authorizer` - The Raft-backed authorizer to consult from now on
    pub(crate) async fn set_raft_authorizer(&self, authorizer: Arc<dyn KeyLifecycleAuthorizer>) {
        *self.raft_authorizer.write().await = Some(authorizer);
    }

    /// Set (or replace) the transport used to activate keys on other KMEs (see
    /// [`Self::activate_keys_on_other_kme`]). Defaults to classical HTTPS; calling this switches
    /// to whatever transport is passed (e.g. Zenoh+Raft).
    /// # Arguments
    /// * `transport` - The inter-KME transport to use from now on
    pub(crate) async fn set_inter_kme_transport(&self, transport: Arc<dyn InterKmeTransport>) {
        *self.inter_kme_transport.write().await = transport;
    }

    /// The transport currently installed to activate keys on other KMEs (defaults to classical
    /// HTTPS, see [`Self::new`]). Used by `zenoh_transport::runtime` to capture the default
    /// HTTPS transport before overwriting it with a hybrid classical/Zenoh transport in
    /// `ZenohRaft` mode (see [`Self::set_inter_kme_transport`]).
    pub(crate) async fn current_inter_kme_transport(&self) -> Arc<dyn InterKmeTransport> {
        self.inter_kme_transport.read().await.clone()
    }

    /// Set (or replace) the resolver used to compute the next hop toward a key's true final
    /// destination KME, for multi-hop relay across KMEs with no direct QKD link (see
    /// `get_sae_keys` and `relay_or_store_keys`). Optional and backward-compatible: as long as
    /// this is never called, this KME never relays (a direct link to `target_kme_id` is always
    /// required, matching behavior before this feature existed).
    /// # Arguments
    /// * `resolver` - The routing resolver to consult from now on
    pub(crate) async fn set_key_routing_resolver(&self, resolver: Arc<dyn crate::zenoh_transport::routing::KeyRoutingResolver>) {
        *self.key_routing_resolver.write().await = Some(resolver);
    }

    /// Shared, thread-safe `KmeId -> directory` map for every KME this KME has a genuine QKD
    /// link with (see [`Self::add_qkd_link`]), for `zenoh_transport::runtime` to build a hybrid
    /// classical/Zenoh transport that can tell, for a given next hop, whether a QKD link exists.
    pub(crate) fn qkd_link_directories(&self) -> Arc<RwLock<std::collections::HashMap<KmeId, String>>> {
        self.qkd_link_directories.clone()
    }

    /// Record that this KME has a genuine (real or simulated, via a shared raw key folder)
    /// direct QKD link with `other_kme_id`, durably in the database (idempotent: calling this
    /// again for an already-recorded `other_kme_id` is a no-op), and remember `directory` (the
    /// shared folder watched for that link) in memory for [`Self::qkd_link_directory`].
    /// # Arguments
    /// * `other_kme_id` - The other KME this KME has a direct QKD link with
    /// * `directory` - The shared raw key directory watched for that link
    pub(crate) async fn add_qkd_link(&self, other_kme_id: KmeId, directory: &str) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT_SQLITE_POSTGRES: &'static str = "INSERT INTO qkd_links (other_kme_id) VALUES ($1) ON CONFLICT (other_kme_id) DO NOTHING;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "INSERT IGNORE INTO qkd_links (other_kme_id) VALUES (?);";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT_SQLITE_POSTGRES,
        };

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement)?;
        let query_args = prepare_sql_arguments!(other_kme_id)?;
        stmt.query_with(query_args).execute(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        self.qkd_link_directories.write().await.insert(other_kme_id, directory.to_string());
        Ok(QkdManagerResponse::Ok)
    }

    /// Every KME this KME has a genuine direct QKD link with (see [`Self::add_qkd_link`]), for
    /// `zenoh_transport::runtime` to advertise over its Zenoh registry queryable so other KMEs
    /// can build the QKD-adjacency graph used for multi-hop relay routing.
    pub(crate) async fn list_qkd_linked_kme_ids(&self) -> Vec<KmeId> {
        const PREPARED_STATEMENT: &'static str = "SELECT other_kme_id FROM qkd_links;";

        let stmt = match ensure_prepared_statement_ok!(self.db, PREPARED_STATEMENT) {
            Ok(stmt) => stmt,
            Err(_) => return vec![],
        };
        let rows = match stmt.query().fetch_all(&self.db).await {
            Ok(rows) => rows,
            Err(e) => {
                error!("Error executing SQL statement: {:?}", e);
                return vec![];
            }
        };
        rows.iter().filter_map(|row| row.try_get::<KmeId, _>("other_kme_id").ok()).collect()
    }

    /// Add a new SAE ID to the database
    /// # Arguments
    /// * `sae_id` - The SAE ID to add
    /// * `kme_id` - The KME ID to associate with the SAE ID
    /// * `sae_certificate_serial` - The SAE certificate serial number, None if the SAE isn't supposed to authenticate to this KME
    pub(crate) async fn add_sae(&self, sae_id: SaeId, kme_id: KmeId, sae_certificate_serial: &Option<SaeClientCertSerial>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_INSERT_STATEMENT_KNOWN_CERT: &'static str = "INSERT INTO saes (sae_id, kme_id, sae_certificate_serial) VALUES ($1, $2, $3);";
        const PREPARED_INSERT_STATEMENT_KNOWN_CERT_MYSQL: &'static str = "INSERT INTO saes (sae_id, kme_id, sae_certificate_serial) VALUES (?, ?, ?);";
        const PREPARED_INSERT_STATEMENT_NO_CERT: &'static str = "INSERT INTO saes (sae_id, kme_id) VALUES ($1, $2);";
        const PREPARED_INSERT_STATEMENT_NO_CERT_MYSQL: &'static str = "INSERT INTO saes (sae_id, kme_id) VALUES (?, ?);";
        const PREPARED_UPDATE_STATEMENT_KNOWN_CERT: &'static str = "UPDATE saes SET kme_id = $1, sae_certificate_serial = $2 WHERE sae_id = $3;";
        const PREPARED_UPDATE_STATEMENT_KNOWN_CERT_MYSQL: &'static str = "UPDATE saes SET kme_id = ?, sae_certificate_serial = ? WHERE sae_id = ?;";
        const PREPARED_UPDATE_STATEMENT_NO_CERT: &'static str = "UPDATE saes SET kme_id = $1, sae_certificate_serial = NULL WHERE sae_id = $2;";
        const PREPARED_UPDATE_STATEMENT_NO_CERT_MYSQL: &'static str = "UPDATE saes SET kme_id = ?, sae_certificate_serial = NULL WHERE sae_id = ?;";

        let has_provided_certificate = sae_certificate_serial.is_some();
        let is_this_kme = kme_id == self.this_kme_id;
        // Has given certificate and doesn't belong to this KME, or doesn't have a certificate and belongs to this KME
        if has_provided_certificate != is_this_kme {
            return Err(QkdManagerResponse::InconsistentSaeData);
        }

        let (insert_statement, update_statement) = match self.dbms_type {
            DbmsType::MySQL => {
                match sae_certificate_serial {
                    Some(_) => (PREPARED_INSERT_STATEMENT_KNOWN_CERT_MYSQL, PREPARED_UPDATE_STATEMENT_KNOWN_CERT_MYSQL),
                    None => (PREPARED_INSERT_STATEMENT_NO_CERT_MYSQL, PREPARED_UPDATE_STATEMENT_NO_CERT_MYSQL),
                }
            },
            DbmsType::Postgres | DbmsType::Sqlite => {
                match sae_certificate_serial {
                    Some(_) => (PREPARED_INSERT_STATEMENT_KNOWN_CERT, PREPARED_UPDATE_STATEMENT_KNOWN_CERT),
                    None => (PREPARED_INSERT_STATEMENT_NO_CERT, PREPARED_UPDATE_STATEMENT_NO_CERT),
                }
            }
        };

        let mut query_args_update = prepare_sql_arguments!(kme_id)?;

        if sae_certificate_serial.is_some() {
            query_args_update.add(sae_certificate_serial.as_ref().unwrap().as_bytes()).map_err(|e| {
                error!("Error binding parameter to SQL statement: {}", e);
                QkdManagerResponse::Ko
            })?;
        }
        query_args_update.add(sae_id).map_err(|e| {
            error!("Error binding parameter to SQL statement: {}", e);
            QkdManagerResponse::Ko
        })?;

        let update_stmt = ensure_prepared_statement_ok!(self.db, update_statement)?;
        let update_query_affected_rows = update_stmt.query_with(query_args_update).execute(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?.rows_affected();

        if update_query_affected_rows > 1 {
            error!("Error: more than one row affected when updating SAE ID {}", sae_id);
            return Err(QkdManagerResponse::Ko);
        } else if update_query_affected_rows == 1 {
            // Successfully updated existing SAE ID
            return Ok(QkdManagerResponse::Ok);
        }

        let mut query_args_insert = prepare_sql_arguments!(sae_id, kme_id)?;

        if sae_certificate_serial.is_some() {
            query_args_insert.add(sae_certificate_serial.as_ref().unwrap().as_bytes()).map_err(|_| {
                error!("Error binding parameter to SQL statement");
                QkdManagerResponse::Ko
            })?;
        }

        let insert_stmt = ensure_prepared_statement_ok!(self.db, insert_statement)?;
        insert_stmt.query_with(query_args_insert).execute(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;
        Ok(QkdManagerResponse::Ok)
    }

    pub(crate) async fn add_preinit_qkd_key(&self, pre_init_key: PreInitQkdKeyWrapper) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "INSERT INTO uninit_keys (key_uuid, qkd_key, other_kme_id) VALUES ($1, $2, $3);";
        const PREPARED_STATEMENT_MYSQL: &'static str = "INSERT INTO uninit_keys (key_uuid, qkd_key, other_kme_id) VALUES (?, ?, ?);";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement)?;
        let uuid_bytes = Bytes::try_from(pre_init_key.key_uuid).map_err(|_| {
            error!("Error converting UUID to bytes");
            QkdManagerResponse::Ko
        })?;
        let uuid_str = uuid::Uuid::from_bytes(uuid_bytes).to_string();
        let query_args = prepare_sql_arguments!(uuid_str.as_str(), pre_init_key.key.as_bytes(), pre_init_key.other_kme_id)?;
        stmt.query_with(query_args).execute(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;
        Ok(QkdManagerResponse::Ok)
    }

    pub(crate) async fn add_multiple_preinit_qkd_keys(&self, pre_init_keys: Vec<PreInitQkdKeyWrapper>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "INSERT INTO uninit_keys (key_uuid, qkd_key, other_kme_id) "; // QueryBuilder will add the VALUES part

        let mut qb = QueryBuilder::new(PREPARED_STATEMENT);

        let pre_init_keys_transformed = pre_init_keys.iter().map(|pre_init_key| {
            let uuid_bytes = Bytes::try_from(pre_init_key.key_uuid).map_err(|_| {
                error!("Error converting UUID to bytes");
                QkdManagerResponse::Ko
            })?;
            let uuid_str = uuid::Uuid::from_bytes(uuid_bytes).to_string();
            Ok((uuid_str, pre_init_key.key.as_bytes(), pre_init_key.other_kme_id))
        }).collect::<Result<Vec<_>, QkdManagerResponse>>()?;

        qb.push_values(pre_init_keys_transformed.clone(), |mut b, (uuid_str, key_bytes, other_kme_id)| {
            b.push_bind(uuid_str)
                .push_bind(key_bytes)
                .push_bind(other_kme_id);
        });
        let mut query = qb.build();
        let query_sql = query.sql();
        let mut sql_modified_for_postgres = String::with_capacity(query_sql.len());

        if self.dbms_type == DbmsType::Postgres {
            let mut param_idx = 1;

            for ch in query_sql.chars() {
                if ch == '?' {
                    sql_modified_for_postgres.push_str(&format!("${}", param_idx));
                    param_idx += 1;
                } else {
                    sql_modified_for_postgres.push(ch);
                }
            }
            query = sqlx::query(&sql_modified_for_postgres);
            for (uuid_str, key_bytes, other_kme_id) in pre_init_keys_transformed {
                query = query.bind(uuid_str)
                    .bind(key_bytes)
                    .bind(other_kme_id);
            }
        }



        query.execute(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        Ok(QkdManagerResponse::Ok)
    }

    pub(crate) async fn get_sae_status(&self, origin_sae_certificate: &SaeClientCertSerial, target_sae_id: SaeId) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "SELECT COUNT(*) FROM uninit_keys WHERE other_kme_id = $1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "SELECT COUNT(*) FROM uninit_keys WHERE other_kme_id = ?;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let target_kme_id = self.get_kme_id_from_sae_id(target_sae_id).await.ok_or(QkdManagerResponse::NotFound)?;

        // Ensure the origin (master) SAE ID is valid, and get its SAE id
        let origin_sae_id = self.get_sae_id_from_certificate(origin_sae_certificate).await.ok_or(QkdManagerResponse::AuthenticationError)?;

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement)?;
        let query_args = prepare_sql_arguments!(target_kme_id)?;
        let key_count: i64 = stmt.query_scalar_with(query_args).fetch_one(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        let source_kme_id = self.this_kme_id; // This KME
        let stored_key_count = std::cmp::min(key_count as usize, crate::MAX_QKD_KEYS_PER_SAE);

        // Create key exchange status response object
        let response_qkd_key_status = qkd_manager::http_response_obj::ResponseQkdKeysStatus {
            source_KME_ID: source_kme_id.to_string(),
            target_KME_ID: target_kme_id.to_string(),
            master_SAE_ID: origin_sae_id.to_string(),
            slave_SAE_ID: target_sae_id.to_string(),
            key_size: crate::QKD_KEY_SIZE_BITS,
            stored_key_count,
            max_key_count: crate::MAX_QKD_KEYS_PER_SAE,
            max_key_per_request: crate::MAX_QKD_KEYS_PER_REQUEST,
            max_key_size: crate::QKD_MAX_KEY_SIZE_BITS,
            min_key_size: crate::QKD_MIN_KEY_SIZE_BITS,
            max_SAE_ID_count: crate::MAX_QKD_KEY_SAE_IDS,
        };

        Ok(QkdManagerResponse::Status(response_qkd_key_status))
    }

    pub(crate) async fn get_sae_keys(&self, origin_sae_certificate: &SaeClientCertSerial, target_sae_id: SaeId, key_count: RequestedKeyCount) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const FETCH_PREINIT_KEY_PREPARED_STATEMENT: &'static str = "SELECT id, key_uuid, qkd_key, other_kme_id FROM uninit_keys WHERE other_kme_id = ";

        let should_disable_database_randomization = match std::env::var(crate::DISABLE_KEY_RETRIEVAL_DATABASE_RANDOMIZATION_ENV_VARIABLE) {
            Ok(val) => val == crate::ACTIVATED_ENV_VARIABLE_VALUE,
            Err(_) => false,
        };

        let key_count = key_count.get();
        if key_count == 0 {
            return Ok(QkdManagerResponse::Keys(ResponseQkdKeysList {
                keys: vec![],
            }))
        }

        // Ensure the origin (master) SAE ID is valid, and get its SAE id
        let origin_sae_id = self.get_sae_id_from_certificate(origin_sae_certificate).await.ok_or(QkdManagerResponse::AuthenticationError)?;
        let origin_kme_id = self.this_kme_id;
        let target_kme_id = self.get_kme_id_from_sae_id(target_sae_id).await.ok_or(QkdManagerResponse::NotFound)?;

        // In `ZenohRaft` mode, when this KME has no direct QKD link with `target_kme_id`, key
        // material must be relayed hop-by-hop toward it instead of requiring a direct link (see
        // `crate::zenoh_transport::routing`): draw keys from the pool shared with the computed
        // next hop rather than `target_kme_id` itself. `None` (no resolver installed, i.e.
        // classical HTTPS mode, or the same-KME case) keeps today's behavior unchanged.
        let pool_kme_id = if origin_kme_id != target_kme_id {
            match self.key_routing_resolver.read().await.clone() {
                Some(resolver) => match resolver.next_hop(target_kme_id, &[]) {
                    Some(next_hop) => next_hop.kme_id,
                    None => {
                        warn!("No route to KME {} from KME {}", target_kme_id, origin_kme_id);
                        return Err(QkdManagerResponse::NotFound);
                    }
                },
                None => {
                    // No resolver installed: either genuinely classical HTTPS mode (expected), or
                    // `ZenohRaft` mode where `set_key_routing_resolver` hasn't run yet (this
                    // KME's Zenoh transport is still starting up, see `zenoh_transport::runtime`)
                    // - flag the latter loudly since it silently mimics "direct link" behavior.
                    if target_kme_id != origin_kme_id && !self.qkd_link_directories.read().await.contains_key(&target_kme_id) {
                        warn!("No key routing resolver installed and no direct QKD link with KME {}: this KME's Zenoh transport may still be starting up", target_kme_id);
                    }
                    target_kme_id
                }
            }
        } else {
            target_kme_id
        };

        export_important_logging_message!(&self, &format!("SAE {} requested a key to communicate with {}", origin_sae_id, target_sae_id));

        let mut fetched_preinit_keys: Vec<(i64, String, Vec<u8>)> = Vec::with_capacity(key_count);
        let mut key_ids_blocked_by_this_request: HashSet<i64> = HashSet::with_capacity(key_count);

        let mut fetch_preinit_qb = QueryBuilder::new(FETCH_PREINIT_KEY_PREPARED_STATEMENT);
        fetch_preinit_qb.push_bind(pool_kme_id);

        {
            let mut blocked_key_ids = self.blocked_key_ids.lock().await;

            if !blocked_key_ids.is_empty() {
                fetch_preinit_qb.push(" AND id NOT IN (");
                let mut separated = fetch_preinit_qb.separated(", ");
                for id in blocked_key_ids.iter() {
                    separated.push_bind(id.to_owned());
                }
                fetch_preinit_qb.push(")");
            }


            if !should_disable_database_randomization {
                fetch_preinit_qb.push(" ORDER BY ");
                fetch_preinit_qb.push(if self.dbms_type == DbmsType::MySQL { "RAND()" } else { "RANDOM()" });
            }

            fetch_preinit_qb.push(" LIMIT ");
            fetch_preinit_qb.push_bind(key_count as i64);

            let mut built_fetch_preinit_qb = fetch_preinit_qb.build();

            let query_sql = built_fetch_preinit_qb.sql();
            let mut sql_modified_for_postgres = String::with_capacity(query_sql.len());

            if self.dbms_type == DbmsType::Postgres {
                let mut param_idx = 1;

                for ch in query_sql.chars() {
                    if ch == '?' {
                        sql_modified_for_postgres.push_str(&format!("${}", param_idx));
                        param_idx += 1;
                    } else {
                        sql_modified_for_postgres.push(ch);
                    }
                }
                built_fetch_preinit_qb = sqlx::query(&sql_modified_for_postgres);
                built_fetch_preinit_qb = built_fetch_preinit_qb.bind(pool_kme_id);
                if !blocked_key_ids.is_empty() {
                    for id in blocked_key_ids.iter() {
                        built_fetch_preinit_qb = built_fetch_preinit_qb.bind(id.to_owned());
                    }
                }
                built_fetch_preinit_qb = built_fetch_preinit_qb.bind(key_count as i64);
            }

            let mut sql_execution_rows = built_fetch_preinit_qb.fetch(&self.db);

            while let Some(row) = sql_execution_rows.try_next().await.map_err(|e| {
                error!("Error executing SQL statement: {:?}", e);
                QkdManagerResponse::Ko
            })? {
                let id: i64 = row.try_get("id").map_err(|e| {
                    error!("Error reading SQL statement result: {}", e);
                    QkdManagerResponse::Ko
                })?;
                let key_uuid: String = row.try_get("key_uuid").map_err(|e| {
                    error!("Error reading SQL statement result: {}", e);
                    QkdManagerResponse::Ko
                })?;
                let key: Vec<u8> = row.try_get("qkd_key").map_err(|e| {
                    error!("Error reading SQL statement result: {}", e);
                    QkdManagerResponse::Ko
                })?;
                fetched_preinit_keys.push((id, key_uuid, key));
                if !blocked_key_ids.insert(id) {
                    error!("Error: key ID {} is already being activated, concurrent request?", id);
                    return Err(QkdManagerResponse::Ko);
                }
                key_ids_blocked_by_this_request.insert(id);
            }
        }

        if fetched_preinit_keys.len() == 0 && key_count != 0 {
            warn!("No key available for SAE {} to communicate with SAE {}", origin_sae_id, target_sae_id);
            return Err(QkdManagerResponse::NotFound);
        }

        if fetched_preinit_keys.len() < key_count {
            warn!("Only {} keys available for SAE {} to communicate with SAE {}, while {} were requested", fetched_preinit_keys.len(), origin_sae_id, target_sae_id, key_count);
        }

        if origin_kme_id != target_kme_id {
            // send key to other KME
            // We must ensure:
            // - other KME is authenticated (client certificate and operating system trust store)
            // - other SAE belongs to other KME (statically managed for now)
            let uuids_list = fetched_preinit_keys.iter().map(|(_, key_uuid, _)| key_uuid.clone()).collect::<Vec<_>>();
            let keys_with_material = fetched_preinit_keys.iter().map(|(_, key_uuid, key)| (key_uuid.clone(), key.clone())).collect::<Vec<_>>();

            // If a Raft coordinator is configured, this KME is the master (it holds the key and
            // initiates the exchange): ask the cluster to authorize starting the sync *before*
            // pushing anything over the classical inter-KME network.
            // Note: `target_kme_id` (a numeric `KmeId`) is used as a stand-in for the Zenoh
            // `slave_kme` node identifier here; there is no established mapping between the two
            // identifier spaces yet (see repo memory for details), which a later phase should resolve.
            if let Some(authorizer) = self.raft_authorizer.read().await.clone() {
                for key_uuid in &uuids_list {
                    authorizer.authorize_transition(key_uuid, &target_kme_id.to_string(), ZenohKeyState::Syncing).await.map_err(|e| {
                        error!("Raft cluster rejected Generated -> Syncing for key {}: {}", key_uuid, e);
                        QkdManagerResponse::RaftConsensusRejected
                    })?;
                }
            }

            info!("Sending {} key(s) to KME {} for SAEs {}/{} through the installed inter-KME transport", keys_with_material.len(), pool_kme_id, origin_sae_id, target_sae_id);
            self.activate_keys_on_other_kme(origin_sae_id, pool_kme_id, target_sae_id, keys_with_material, target_kme_id, vec![]).map_err(|qkd_manager_activation_error| {
                error!("Error activating key on other KME");
                qkd_manager_activation_error
            }).await?;
            export_important_logging_message!(&self, &format!("As SAE {} belongs to KME {}, activating it through inter KMEs network", target_sae_id, target_kme_id));

            // The remote KME accepted the activation: authorize moving to InUse now that both
            // sides are synced, before this KME commits its own local activation below.
            if let Some(authorizer) = self.raft_authorizer.read().await.clone() {
                for key_uuid in &uuids_list {
                    authorizer.authorize_transition(key_uuid, &target_kme_id.to_string(), ZenohKeyState::InUse).await.map_err(|e| {
                        error!("Raft cluster rejected Syncing -> InUse for key {}: {}", key_uuid, e);
                        QkdManagerResponse::RaftConsensusRejected
                    })?;
                }
            }
        }

        let mut transaction = self.db.begin().await.map_err(|e| {
            error!("Error starting SQL transaction: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        for (key_id, key_uuid, key) in &fetched_preinit_keys {
            self.delete_pre_init_key_with_id(*key_id, Some(&mut transaction)).await.map_err(|e| {
                error!("Error deleting pre-init key {}: {:?}", key_id, e);
                QkdManagerResponse::Ko
            })?;

            info!("Saving key {} in init keys", key_uuid);

            self.insert_activated_key(&key_uuid, &key, origin_sae_id, target_sae_id, Some(&mut transaction)).map_err(|e| {
                error!("Error inserting activated key: {:?}", e);
                QkdManagerResponse::Ko
            }).await?;
        }

        transaction.commit().await.map_err(|e| {
            error!("Error committing SQL transaction: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        {
            let mut blocked_key_ids = self.blocked_key_ids.lock().await;
            blocked_key_ids.retain(|id| !key_ids_blocked_by_this_request.contains(id));
        }

        let keys_response = fetched_preinit_keys.iter().map(|(_, key_uuid, key)| {
            // Encode the key in base64
            ResponseQkdKey {
                key_ID: key_uuid.clone(),
                key: general_purpose::STANDARD.encode(&key)
            }
        }).collect::<Vec<_>>();

        // Return a list of key objects
        Ok(QkdManagerResponse::Keys(ResponseQkdKeysList {
            keys: keys_response,
        }))
    }

    /// # Arguments
    /// * `final_target_kme_id` - The true final destination KME for this key material; equal to
    ///   `self.this_kme_id` in the classical, non-relay case (the only case possible outside
    ///   `ZenohRaft` mode)
    /// * `visited_kme_ids` - Every KME that already handled this key material before this one,
    ///   including the true origin, used to avoid routing loops if it must be relayed onward
    pub(crate) async fn activate_key_uuids_sae(&self, origin_sae_id: SaeId, target_sae_id: SaeId, key_uuids_list: Vec<String>, final_target_kme_id: KmeId, visited_kme_ids: Vec<KmeId>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const GET_PRE_INIT_KEY_PREPARED_STATEMENT: &'static str = "SELECT id, qkd_key, other_kme_id FROM uninit_keys WHERE key_uuid = $1 LIMIT 1;";
        const GET_PRE_INIT_KEY_PREPARED_STATEMENT_MYSQL: &'static str = "SELECT id, qkd_key, other_kme_id FROM uninit_keys WHERE key_uuid = ? LIMIT 1;";

        let get_pre_init_key_prepared_statement = match self.dbms_type {
            DbmsType::MySQL => GET_PRE_INIT_KEY_PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => GET_PRE_INIT_KEY_PREPARED_STATEMENT,
        };

        // If this activation was relayed (more than just the true origin's own hop already
        // visited), the immediate previous hop (last entry) may have just written the raw key
        // material into this KME's shared QKD-link directory for it (see
        // `HttpsInterKmeTransport::activate_key_on_remote_kme`) instead of it already sitting in
        // this KME's own pre-init pool. That sender relies on this KME's directory watcher to
        // pick the file up before this very request arrives, which is not guaranteed (file
        // system change notifications can be unreliable across some container/bind-mount
        // setups) - see the DB-miss fallback below.
        let immediate_sender_kme_id = (visited_kme_ids.len() > 1).then(|| visited_kme_ids[visited_kme_ids.len() - 1]);

        let retrieved_preinit_key_tuples_futures = key_uuids_list.iter().map(async |key_uuid| {
            let stmt = ensure_prepared_statement_ok!(self.db, get_pre_init_key_prepared_statement)?;
            let query_args = prepare_sql_arguments!(key_uuid.as_str())?;

            let sql_execution_row = stmt.query_with(query_args).fetch_optional(&self.db).await.map_err(|e| {
                error!("Error executing SQL statement: {:?}", e);
                QkdManagerResponse::Ko
            })?;

            let sql_execution_row = match sql_execution_row {
                Some(row) => row,
                None => {
                    // DB miss: if relayed, try reading the file directly instead of only
                    // trusting the watcher's timing (still covered by the sender's own retry
                    // loop for genuine races if the file isn't there yet either).
                    if let Some(sender_kme_id) = immediate_sender_kme_id {
                        if let Some(key) = self.try_recover_relayed_key_from_shared_folder(sender_kme_id, key_uuid).await {
                            return Ok((key_uuid.clone(), None, key));
                        }
                    }
                    return Err(QkdManagerResponse::NotFound);
                }
            };

            let key_id: i64 = sql_execution_row.try_get("id").map_err(|e| {
                error!("Error reading SQL statement result: {}", e);
                QkdManagerResponse::Ko
            })?;
            let key: Vec<u8> = sql_execution_row.try_get("qkd_key").map_err(|e| {
                error!("Error reading SQL statement result: {}", e);
                QkdManagerResponse::Ko
            })?;
            Ok((key_uuid.clone(), Some(key_id), key))
        });

        let retrieved_preinit_key_tuples: Vec<(String, Option<i64>, Vec<u8>)> = join_all(retrieved_preinit_key_tuples_futures).await.into_iter().collect::<Result<Vec<_>, _>>()?;

        // The Raft-Syncing gate (see `Self::relay_or_store_keys`) is checked there, only if this
        // KME turns out to be the final destination - an intermediate relay hop has no business
        // of its own in the cluster's consensus over a key it never stores.

        // Every matched pre-init key is now consumed (whether stored locally or relayed onward
        // below), same as before this feature: the classical protocol's shared-pool assumption
        // means this KME already holds byte-identical material under each uuid, and it must not
        // be reused for a different exchange.
        let mut keys = Vec::with_capacity(retrieved_preinit_key_tuples.len());
        {
            let mut transaction = self.db.begin().await.map_err(|e| {
                error!("Error starting SQL transaction: {:?}", e);
                QkdManagerResponse::Ko
            })?;
            for (key_uuid, key_id, key) in retrieved_preinit_key_tuples {
                // No DB row to delete for keys recovered directly from a relayed file below -
                // the file itself was already consumed instead.
                if let Some(key_id) = key_id {
                    self.delete_pre_init_key_with_id(key_id, Some(&mut transaction)).await.map_err(|e| {
                        error!("Error deleting pre-init key {}: {:?}", key_id, e);
                        QkdManagerResponse::Ko
                    })?;
                }
                keys.push((key_uuid, key));
            }
            transaction.commit().await.map_err(|e| {
                error!("Error committing SQL transaction: {:?}", e);
                QkdManagerResponse::Ko
            })?;
        }

        self.relay_or_store_keys(origin_sae_id, target_sae_id, keys, final_target_kme_id, visited_kme_ids).await
    }

    /// Fallback for [`Self::activate_key_uuids_sae`]'s DB miss: reads and consumes a relayed
    /// key's raw bytes directly from `sender_kme_id`'s shared QKD-link directory by its
    /// deterministic filename, bypassing this KME's directory watcher entirely. Returns `None`
    /// (never an error) if the file is missing, unreadable, or the wrong size, so the caller
    /// falls through to its normal not-found handling.
    async fn try_recover_relayed_key_from_shared_folder(&self, sender_kme_id: KmeId, key_uuid: &str) -> Option<Vec<u8>> {
        let directory = self.qkd_link_directories.read().await.get(&sender_kme_id).cloned()?;
        let file_path = std::path::Path::new(&directory).join(format!("relay_{}.cor", key_uuid));
        let key = std::fs::read(&file_path).ok()?;
        if key.len() != crate::QKD_KEY_SIZE_BYTES {
            error!("Relayed key file {} has unexpected size {} (expected {})", file_path.display(), key.len(), crate::QKD_KEY_SIZE_BYTES);
            return None;
        }
        if let Err(e) = std::fs::remove_file(&file_path) {
            warn!("Error deleting consumed relayed key file {}: {}", file_path.display(), e);
        }
        info!("Recovered relayed key {} directly from shared folder (directory watcher had not picked it up in time)", key_uuid);
        Some(key)
    }

    /// Store `keys` locally if this KME is `final_target_kme_id`, or relay them onward toward it
    /// otherwise (`ZenohRaft` transport mode only - see `crate::zenoh_transport::routing`),
    /// shared by both [`Self::activate_key_uuids_sae`] (classical HTTPS receiver) and
    /// [`Self::store_synced_keys_from_remote`] (Zenoh receiver).
    async fn relay_or_store_keys(&self, origin_sae_id: SaeId, target_sae_id: SaeId, keys: Vec<(String, Vec<u8>)>, final_target_kme_id: KmeId, visited_kme_ids: Vec<KmeId>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        if final_target_kme_id == self.this_kme_id {
            // Read-only Raft check: this KME is the true final destination, so only agree to
            // store the key(s) locally once Raft confirms *this cluster* already committed the
            // master's Syncing proposal for each of them. Never checked on an intermediate relay
            // hop above (see the early return below) - only the final destination's own state
            // transition matters, and non-member bridging KMEs may not track cluster state at all.
            if let Some(authorizer) = self.raft_authorizer.read().await.clone() {
                for (key_uuid, _) in &keys {
                    if authorizer.current_state(key_uuid) != Some(ZenohKeyState::Syncing) {
                        error!("Raft cluster has not committed key {} to Syncing; refusing to store it locally", key_uuid);
                        return Err(QkdManagerResponse::RaftConsensusRejected);
                    }
                }
            }

            let mut transaction = self.db.begin().await.map_err(|e| {
                error!("Error starting SQL transaction: {:?}", e);
                QkdManagerResponse::Ko
            })?;

            for (key_uuid, key) in &keys {
                self.insert_activated_key(key_uuid, key, origin_sae_id, target_sae_id, Some(&mut transaction)).map_err(|e| {
                    error!("Error inserting activated key: {:?}", e);
                    QkdManagerResponse::Ko
                }).await?;
                info!("Key {} activated between saes {} and {}", key_uuid, origin_sae_id, target_sae_id);
            }

            transaction.commit().await.map_err(|e| {
                error!("Error committing SQL transaction: {:?}", e);
                QkdManagerResponse::Ko
            })?;

            return Ok(QkdManagerResponse::Ok);
        }

        // Not the final destination: relay onward through the installed routing resolver
        // (installed only in `ZenohRaft` mode - see `Self::set_key_routing_resolver`).
        let resolver = self.key_routing_resolver.read().await.clone().ok_or_else(|| {
            error!("Cannot relay key(s) toward KME {}: no routing resolver installed", final_target_kme_id);
            QkdManagerResponse::MissingRemoteKmeConfiguration
        })?;
        let next_hop = resolver.next_hop(final_target_kme_id, &visited_kme_ids).ok_or_else(|| {
            error!("No route to KME {} while relaying (already visited: {:?})", final_target_kme_id, visited_kme_ids);
            QkdManagerResponse::NotFound
        })?;
        info!("Relaying {} key(s) toward final KME {} via next hop KME {}", keys.len(), final_target_kme_id, next_hop.kme_id);
        self.activate_keys_on_other_kme(origin_sae_id, next_hop.kme_id, target_sae_id, keys, final_target_kme_id, visited_kme_ids).await?;
        Ok(QkdManagerResponse::Ok)
    }

    /// From a remote KME, over the Zenoh transport only: store key material pushed directly on
    /// the `ext_keys` plane, once this cluster's own Raft view already shows the key as
    /// `Syncing`, if this KME is the true final destination - or relay it onward otherwise (see
    /// [`Self::relay_or_store_keys`]). Unlike [`Self::activate_key_uuids_sae`] (classical HTTPS
    /// `/keys/activate` route), this never reads `uninit_keys`: the key bytes arrive over the
    /// wire instead of being looked up from a locally pre-shared pool, so there is no pre-init
    /// row to consume.
    /// # Arguments
    /// * `final_target_kme_id` - The true final destination KME for this key material
    /// * `visited_kme_ids` - Every KME that already handled this key material before this one,
    ///   including the true origin, used to avoid routing loops if it must be relayed onward
    pub(crate) async fn store_synced_keys_from_remote(&self, origin_sae_id: SaeId, target_sae_id: SaeId, keys: Vec<(String, Vec<u8>)>, final_target_kme_id: KmeId, visited_kme_ids: Vec<KmeId>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        // The Raft-Syncing gate (see `Self::relay_or_store_keys`) is checked there, only if this
        // KME turns out to be the final destination - an intermediate relay hop (possibly not
        // even a Raft cluster member, e.g. a Raft-client-only bridging KME) has no business of
        // its own in the cluster's consensus over a key it never stores.
        self.relay_or_store_keys(origin_sae_id, target_sae_id, keys, final_target_kme_id, visited_kme_ids).await
    }

    /// Ask `other_kme_id` (the immediate next hop, which may or may not be
    /// `final_target_kme_id` itself - see `crate::zenoh_transport::routing`) to make `keys`
    /// available for the (`caller_master_sae_id`, `other_sae_id`) SAE pair, through the
    /// currently installed [`InterKmeTransport`].
    /// # Arguments
    /// * `final_target_kme_id` - The true final destination KME for this key material
    /// * `visited_kme_ids` - Every KME that already handled this key material before this one;
    ///   this KME's own id is appended before the call, so the callee always observes itself as
    ///   the last visited hop
    async fn activate_keys_on_other_kme(&self, caller_master_sae_id: SaeId, other_kme_id: KmeId, other_sae_id: SaeId, keys: Vec<(String, Vec<u8>)>, final_target_kme_id: KmeId, mut visited_kme_ids: Vec<KmeId>) -> Result<(), QkdManagerResponse> {
        visited_kme_ids.push(self.this_kme_id);
        let transport = self.inter_kme_transport.read().await.clone();
        transport.activate_key_on_remote_kme(caller_master_sae_id, other_kme_id, other_sae_id, keys, final_target_kme_id, visited_kme_ids).await
    }

    async fn insert_activated_key(&self, key_uuid: &str, key: &[u8], origin_sae_id: SaeId, target_sae_id: SaeId, transaction: Option<&mut Transaction<'_, Any>>)-> Result<QkdManagerResponse, QkdManagerResponse> {
        const INSERT_INIT_KEY_PREPARED_STATEMENT: &'static str = "INSERT INTO activated_keys (key_uuid, qkd_key, origin_sae_id, target_sae_id) VALUES ($1, $2, $3, $4);";
        const INSERT_INIT_KEY_PREPARED_STATEMENT_MYSQL: &'static str = "INSERT INTO activated_keys (key_uuid, qkd_key, origin_sae_id, target_sae_id) VALUES (?, ?, ?, ?);";

        let insert_init_key_prepared_statement = match self.dbms_type {
            DbmsType::MySQL => INSERT_INIT_KEY_PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => INSERT_INIT_KEY_PREPARED_STATEMENT,
        };

        let mut internal_transaction = None; // to keep the transaction alive if we create it
        let transaction = match transaction {
            Some(tx) =>  tx,
            None => {
                internal_transaction = Some(self.db.begin().await.map_err(|e| {
                    error!("Error starting transaction: {:?}", e);
                    QkdManagerResponse::Ko
                })?);
                internal_transaction.as_mut().unwrap()
            },
        };

        let stmt = ensure_prepared_statement_ok!(&mut **transaction, insert_init_key_prepared_statement)?;
        let query_args = prepare_sql_arguments!(key_uuid, key, origin_sae_id, target_sae_id)?;
        stmt.query_with(query_args).execute(&mut **transaction).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;
        if let Some(tx) = internal_transaction {
            tx.commit().await.map_err(|e| {
                error!("Error committing transaction: {:?}", e);
                QkdManagerResponse::Ko
            })?;
        }
        export_important_logging_message!(&self, &format!("Key {} activated between SAEs {} and {}", key_uuid, origin_sae_id, target_sae_id));
        Ok(QkdManagerResponse::Ok)
    }

    /// Delete a pre-init key from the pre-init keys database
    /// Called when master SAE requested the key: it becomes an init key
    /// So that the same key isn't requested again by a master SAE
    /// # Arguments
    /// * `key_id` - The ID of the pre init key to delete
    /// * `transaction` - An optional transaction to use for db requests, if None a new transaction will be created
    /// # Returns
    /// Ok if the key was deleted, an error otherwise
    async fn delete_pre_init_key_with_id(&self, key_id: i64, transaction: Option<&mut Transaction<'_, Any>>) -> Result<(), io::Error> {
        const PREPARED_STATEMENT: &'static str = "DELETE FROM uninit_keys WHERE id = $1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "DELETE FROM uninit_keys WHERE id = ?;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let mut internal_transaction = None; // to keep the transaction alive if we create it
        let transaction = match transaction {
            Some(tx) => tx,
            None => {
                internal_transaction = Some(self.db.begin().await.map_err(|e| {
                    io_err(format!("Error starting transaction: {:?}", e).as_str())
                })?);
                internal_transaction.as_mut().unwrap()
            },
        };

        let stmt = ensure_prepared_statement_ok!(&mut **transaction, prepared_statement).map_err(|e| {
            io_err(format!("Error preparing SQL statement: {:?}", e).as_str())
        })?;
        let query_args = prepare_sql_arguments!(key_id).map_err(|e| {
            io_err(format!("Error binding key ID: {:?}", e).as_str())
        })?;
        stmt.query_with(query_args).execute(&mut **transaction).await.map_err(|e| {
            io_err(format!("Error executing SQL statement, maybe key ID not found in pre init keys database?: {:?}", e).as_str())
        })?;
        if let Some(tx) = internal_transaction {
            tx.commit().await.map_err(|e| {
                io_err(format!("Error committing transaction: {:?}", e).as_str())
            })?;
        }
        Ok(())
    }

    pub(crate) async fn get_sae_keys_with_ids(&self, current_sae_certificate: &SaeClientCertSerial, origin_sae_id: SaeId, keys_uuids: Vec<String>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "SELECT key_uuid, qkd_key FROM activated_keys WHERE target_sae_id = $1 AND origin_sae_id = $2 AND key_uuid = $3 LIMIT 1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "SELECT key_uuid, qkd_key FROM activated_keys WHERE target_sae_id = ? AND origin_sae_id = ? AND key_uuid = ? LIMIT 1;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        // Ensure the caller (slave) SAE ID is valid and authenticated, and get its SAE id
        let current_sae_id = self.get_sae_id_from_certificate(current_sae_certificate).await.ok_or(QkdManagerResponse::AuthenticationError)?;

        // For each key UUID, retrieve the key from the database if it exists and is applicable to the caller SAE ID
        let keys_futures = keys_uuids.iter().map(async |key_uuid| {
            let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement)?;
            let query_args = prepare_sql_arguments!(current_sae_id, origin_sae_id, key_uuid.as_str())?;

            let sql_execution_row = stmt.query_with(query_args).fetch_optional(&self.db).await.map_err(|e| {
                error!("Error executing SQL statement: {:?}", e);
                QkdManagerResponse::Ko
            })?;

            // Only 1 key should be returned by UUID
            let sql_execution_row = match sql_execution_row {
                Some(row) => row,
                None => {
                    return Err(QkdManagerResponse::NotFound);
                }
            };

            let key_uuid: String = sql_execution_row.try_get("key_uuid").map_err(|e| {
                error!("Error reading SQL statement result: {}", e);
                QkdManagerResponse::Ko
            })?;
            let key: Vec<u8> = sql_execution_row.try_get("qkd_key").map_err(|e| {
                error!("Error reading SQL statement result: {}", e);
                QkdManagerResponse::Ko
            })?;

            export_important_logging_message!(&self, &format!("SAE {} requested key {} (from {})", current_sae_id, key_uuid, origin_sae_id));

            // Encode the key in base64
            Ok(ResponseQkdKey {
                key_ID: key_uuid,
                key: general_purpose::STANDARD.encode(&key),
            })
        });

        let keys = join_all(keys_futures).await.into_iter().collect::<Result<Vec<_>, _>>()?;

        // Return a list of key objects
        Ok(QkdManagerResponse::Keys(ResponseQkdKeysList {
            keys,
        }))
    }

    /// Void (permanently delete) one or multiple already-activated keys (shall be called by the master SAE).
    ///
    /// The key material is erased and unrecoverable: only the Raft cluster's commit history (see
    /// `zenoh_transport::persistence`) records that the key ever existed and was voided. Once
    /// voided, the key can no longer be retrieved by `enc_keys`/`dec_keys` (its row is simply gone).
    /// # Arguments
    /// * `origin_sae_certificate` - The client certificate serial of the caller (master) SAE
    /// * `target_sae_id` - The ID of the target (slave) SAE the keys were shared with
    /// * `keys_uuids` - The UUIDs of the keys to void
    pub(crate) async fn void_sae_keys(&self, origin_sae_certificate: &SaeClientCertSerial, target_sae_id: SaeId, keys_uuids: Vec<String>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const CHECK_ACTIVATED_KEY_EXISTS_STATEMENT: &'static str = "SELECT 1 FROM activated_keys WHERE key_uuid = $1 AND origin_sae_id = $2 AND target_sae_id = $3 LIMIT 1;";
        const CHECK_ACTIVATED_KEY_EXISTS_STATEMENT_MYSQL: &'static str = "SELECT 1 FROM activated_keys WHERE key_uuid = ? AND origin_sae_id = ? AND target_sae_id = ? LIMIT 1;";

        if keys_uuids.is_empty() {
            return Ok(QkdManagerResponse::Ok);
        }

        let check_activated_key_exists_statement = match self.dbms_type {
            DbmsType::MySQL => CHECK_ACTIVATED_KEY_EXISTS_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => CHECK_ACTIVATED_KEY_EXISTS_STATEMENT,
        };

        let origin_sae_id = self.get_sae_id_from_certificate(origin_sae_certificate).await.ok_or(QkdManagerResponse::AuthenticationError)?;
        let origin_kme_id = self.this_kme_id;
        let target_kme_id = self.get_kme_id_from_sae_id(target_sae_id).await.ok_or(QkdManagerResponse::NotFound)?;

        // Ensure every requested key really belongs to this (master, slave) SAE pair on this KME, before touching Raft consensus or notifying a remote KME
        for key_uuid in &keys_uuids {
            let stmt = ensure_prepared_statement_ok!(self.db, check_activated_key_exists_statement)?;
            let query_args = prepare_sql_arguments!(key_uuid.as_str(), origin_sae_id, target_sae_id)?;
            let found: Option<i64> = stmt.query_scalar_with(query_args).fetch_optional(&self.db).await.map_err(|e| {
                error!("Error executing SQL statement: {:?}", e);
                QkdManagerResponse::Ko
            })?;
            if found.is_none() {
                return Err(QkdManagerResponse::NotFound);
            }
        }

        export_important_logging_message!(&self, &format!("SAE {} requested to void {} key(s) shared with {}", origin_sae_id, keys_uuids.len(), target_sae_id));

        if origin_kme_id != target_kme_id {
            // Ask the Raft cluster to authorize the InUse -> DeletedOrUsed transition before erasing
            // anything: the leader only accepts this transition if it currently sees the key as
            // InUse (see `zenoh_transport::raft::is_valid_transition`), so a key that is not
            // actually in use yet (or already voided) is rejected here without further action.
            if let Some(authorizer) = self.raft_authorizer.read().await.clone() {
                for key_uuid in &keys_uuids {
                    authorizer.authorize_transition(key_uuid, &target_kme_id.to_string(), ZenohKeyState::DeletedOrUsed).await.map_err(|e| {
                        error!("Raft cluster rejected InUse -> DeletedOrUsed for key {}: {}", key_uuid, e);
                        QkdManagerResponse::RaftConsensusRejected
                    })?;
                }
            }

            self.void_keys_on_other_kme(target_kme_id, keys_uuids.clone()).map_err(|qkd_manager_void_error| {
                error!("Error voiding keys on other KME");
                qkd_manager_void_error
            }).await?;
            export_important_logging_message!(&self, &format!("As SAE {} belongs to KME {}, voiding key(s) through inter KMEs network", target_sae_id, target_kme_id));
        }

        let mut transaction = self.db.begin().await.map_err(|e| {
            error!("Error starting SQL transaction: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        for key_uuid in &keys_uuids {
            self.delete_activated_key_by_uuid(key_uuid, Some(&mut transaction)).await.map_err(|e| {
                error!("Error deleting activated key {}: {:?}", key_uuid, e);
                QkdManagerResponse::Ko
            })?;
        }

        transaction.commit().await.map_err(|e| {
            error!("Error committing SQL transaction: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        export_important_logging_message!(&self, &format!("Key(s) {} voided between SAEs {} and {}", keys_uuids.join(", "), origin_sae_id, target_sae_id));

        Ok(QkdManagerResponse::Ok)
    }

    /// Void (permanently delete) already-activated keys on this KME, on behalf of a remote KME's
    /// master SAE that already had its own `void_sae_keys` call authorized by the Raft cluster
    /// (see [`Self::void_sae_keys`]). Reached over `InterKmeTransport` (classical HTTPS or Zenoh).
    /// # Arguments
    /// * `key_uuids_list` - The UUIDs of the keys to void
    pub(crate) async fn void_key_uuids_sae(&self, key_uuids_list: Vec<String>) -> Result<QkdManagerResponse, QkdManagerResponse> {
        // Read-only check: only agree to erase key material locally once Raft confirms *this
        // cluster* already committed the DeletedOrUsed transition for each key - mirrors the
        // read-only check `activate_key_uuids_sae` does for Syncing.
        if let Some(authorizer) = self.raft_authorizer.read().await.clone() {
            for key_uuid in &key_uuids_list {
                if authorizer.current_state(key_uuid) != Some(ZenohKeyState::DeletedOrUsed) {
                    error!("Raft cluster has not committed key {} to DeletedOrUsed; refusing to void it locally", key_uuid);
                    return Err(QkdManagerResponse::RaftConsensusRejected);
                }
            }
        }

        let mut transaction = self.db.begin().await.map_err(|e| {
            error!("Error starting SQL transaction: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        for key_uuid in &key_uuids_list {
            self.delete_activated_key_by_uuid(key_uuid, Some(&mut transaction)).await.map_err(|e| {
                error!("Error deleting activated key {}: {:?}", key_uuid, e);
                QkdManagerResponse::Ko
            })?;
        }

        transaction.commit().await.map_err(|e| {
            error!("Error committing SQL transaction: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        info!("Key(s) {:?} voided on this KME following a remote void request", key_uuids_list);
        Ok(QkdManagerResponse::Ok)
    }

    /// Permanently delete an activated key's material from the local database. There is no
    /// recovery: only the Raft cluster's own commit history keeps track of the fact this key
    /// existed and was voided (see `zenoh_transport::persistence`).
    /// # Arguments
    /// * `key_uuid` - The UUID of the key to delete
    /// * `transaction` - An optional transaction to use for db requests, if None a new transaction will be created
    async fn delete_activated_key_by_uuid(&self, key_uuid: &str, transaction: Option<&mut Transaction<'_, Any>>) -> Result<(), io::Error> {
        const PREPARED_STATEMENT: &'static str = "DELETE FROM activated_keys WHERE key_uuid = $1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "DELETE FROM activated_keys WHERE key_uuid = ?;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let mut internal_transaction = None; // to keep the transaction alive if we create it
        let transaction = match transaction {
            Some(tx) => tx,
            None => {
                internal_transaction = Some(self.db.begin().await.map_err(|e| {
                    io_err(format!("Error starting transaction: {:?}", e).as_str())
                })?);
                internal_transaction.as_mut().unwrap()
            },
        };

        let stmt = ensure_prepared_statement_ok!(&mut **transaction, prepared_statement).map_err(|e| {
            io_err(format!("Error preparing SQL statement: {:?}", e).as_str())
        })?;
        let query_args = prepare_sql_arguments!(key_uuid).map_err(|e| {
            io_err(format!("Error binding key UUID: {:?}", e).as_str())
        })?;
        stmt.query_with(query_args).execute(&mut **transaction).await.map_err(|e| {
            io_err(format!("Error executing SQL statement, maybe key UUID not found in activated keys database?: {:?}", e).as_str())
        })?;
        if let Some(tx) = internal_transaction {
            tx.commit().await.map_err(|e| {
                io_err(format!("Error committing transaction: {:?}", e).as_str())
            })?;
        }
        Ok(())
    }

    /// Notify another KME, over whichever `InterKmeTransport` is configured, to void the same keys locally.
    async fn void_keys_on_other_kme(&self, other_kme_id: KmeId, key_uuids: Vec<String>) -> Result<(), QkdManagerResponse> {
        let transport = self.inter_kme_transport.read().await.clone();
        transport.void_keys_on_remote_kme(other_kme_id, key_uuids).await
    }

    /// Get the SAE ID from associated client certificate serial number
    /// # Arguments
    /// * `sae_certificate` - The client certificate serial number
    /// # Returns
    /// The SAE ID if the certificate serial number is found in the database, None otherwise
    async fn get_sae_id_from_certificate(&self, sae_certificate: &SaeClientCertSerial) -> Option<SaeId> {
        const PREPARED_STATEMENT: &'static str = "SELECT sae_id FROM saes WHERE sae_certificate_serial = $1 LIMIT 1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "SELECT sae_id FROM saes WHERE sae_certificate_serial = ? LIMIT 1;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement).ok()?;
        let query_args = prepare_sql_arguments!(sae_certificate.as_bytes()).ok()?;
        let sql_execution_row = stmt.query_with(query_args).fetch_optional(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            ()
        }).ok()?;
        let sql_execution_row = match sql_execution_row {
            Some(row) => row,
            None => {
                info!("SAE certificate not found in database");
                return None;
            }
        };
        let sae_id: SaeId = sql_execution_row.try_get("sae_id").map_err(|e| {
            error!("Error reading SQL statement result: {}", e);
            ()
        }).ok()?;
        Some(sae_id)
    }

    /// Get the KME ID from associated SAE ID
    /// # Arguments
    /// * `sae_id` - The SAE ID
    /// # Returns
    /// The KME ID if the SAE ID is found in the database, None otherwise
    pub(crate) async fn get_kme_id_from_sae_id(&self, sae_id: SaeId) -> Option<KmeId> {
        const PREPARED_STATEMENT: &'static str = "SELECT kme_id FROM saes WHERE sae_id = $1 LIMIT 1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "SELECT kme_id FROM saes WHERE sae_id = ? LIMIT 1;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement).ok()?;
        let query_args = prepare_sql_arguments!(sae_id).ok()?;
        let sql_execution_row = stmt.query_with(query_args).fetch_optional(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            ()
        }).ok()?;
        let sql_execution_row = match sql_execution_row {
            Some(row) => row,
            None => {
                info!("KME ID not found in database");
                return None;
            }
        };
        let kme_id: KmeId = sql_execution_row.try_get("kme_id").map_err(|e| {
            error!("Error reading SQL statement result: {}", e);
            ()
        }).ok()?;
        Some(kme_id)
    }

    /// List every SAE ID currently registered in the database as belonging to this KME.
    ///
    /// Used to serve this node's own Zenoh registry info (see
    /// `crate::zenoh_transport::runtime::ZenohTransport::spawn_own_registry_queryable`), so a
    /// newly-discovered KME's SAE ownership can be advertised to (and registered by) other KMEs
    /// without needing a static `saes` config entry anywhere else.
    /// # Returns
    /// The list of SAE IDs owned by this KME (may be empty), or an empty list on a database error.
    pub(crate) async fn get_own_sae_ids(&self) -> Vec<SaeId> {
        const PREPARED_STATEMENT: &'static str = "SELECT sae_id FROM saes WHERE kme_id = $1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "SELECT sae_id FROM saes WHERE kme_id = ?;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let Ok(stmt) = ensure_prepared_statement_ok!(self.db, prepared_statement) else {
            error!("Error preparing SQL statement to list own SAE IDs");
            return Vec::new();
        };
        let Ok(query_args) = prepare_sql_arguments!(self.this_kme_id) else {
            error!("Error binding parameter to list own SAE IDs");
            return Vec::new();
        };
        let rows = match stmt.query_with(query_args).fetch_all(&self.db).await {
            Ok(rows) => rows,
            Err(e) => {
                error!("Error executing SQL statement to list own SAE IDs: {:?}", e);
                return Vec::new();
            }
        };
        rows.iter().filter_map(|row| row.try_get::<SaeId, _>("sae_id").map_err(|e| {
            error!("Error reading SQL statement result: {}", e);
        }).ok()).collect()
    }

    /// Directly fetch SAE info from the certificate serial number, including the SAE ID and KME ID
    /// # Arguments
    /// * `sae_certificate` - The client SAE certificate serial number
    /// # Returns
    /// The SAE info, including KME ID, if the certificate serial number is found in the database, an error otherwise
    pub(crate) async fn get_sae_infos_from_certificate(&self, sae_certificate: &SaeClientCertSerial) -> Result<QkdManagerResponse, QkdManagerResponse> {
        const PREPARED_STATEMENT: &'static str = "SELECT sae_id, kme_id FROM saes WHERE sae_certificate_serial = $1 LIMIT 1;";
        const PREPARED_STATEMENT_MYSQL: &'static str = "SELECT sae_id, kme_id FROM saes WHERE sae_certificate_serial = ? LIMIT 1;";

        let prepared_statement = match self.dbms_type {
            DbmsType::MySQL => PREPARED_STATEMENT_MYSQL,
            DbmsType::Postgres | DbmsType::Sqlite => PREPARED_STATEMENT,
        };

        let stmt = ensure_prepared_statement_ok!(self.db, prepared_statement)?;
        let query_args = prepare_sql_arguments!(sae_certificate.as_bytes())?;
        let sql_execution_row = stmt.query_with(query_args).fetch_optional(&self.db).await.map_err(|e| {
            error!("Error executing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })?;

        let sql_execution_row = match sql_execution_row {
            Some(row) => row,
            None => {
                return Err(QkdManagerResponse::NotFound);
            }
        };

        let sae_id: i64 = sql_execution_row.try_get("sae_id").map_err(|e| {
            error!("Error reading SQL statement result: {}", e);
            QkdManagerResponse::Ko
        })?;
        let kme_id: i64 = sql_execution_row.try_get("kme_id").map_err(|e| {
            error!("Error reading SQL statement result: {}", e);
            QkdManagerResponse::Ko
        })?;

        Ok(QkdManagerResponse::SaeInfo(SAEInfo {
            sae_id,
            kme_id,
            sae_certificate_serial: sae_certificate.clone(),
        }))
    }
}

/// Check SQL statement preparation and return the statement
#[macro_export]
macro_rules! ensure_prepared_statement_ok {
    ($sql_connection:expr, $statement:expr) => {
        $sql_connection.prepare($statement).await.map_err(|e| {
            error!("Error preparing SQL statement: {:?}", e);
            QkdManagerResponse::Ko
        })
    }
}

/// Prepare SQL arguments for a prepared statement
/// # Arguments
/// * `$arg` - The arguments to bind to the prepared statement, in the order they should be bound
/// # Returns
/// The prepared arguments, or an error if binding failed
#[macro_export]
macro_rules! prepare_sql_arguments {
    ($( $arg:expr ),* $(,)? ) => {
        {
            let mut query_args = AnyArguments::default();
            let mut result: Result<_, QkdManagerResponse> = Ok(());
            $(
                if result.is_ok(){
                    if let Err(e) = query_args.add($arg) {
                        error!("Error binding parameter to SQL statement: {}", e);
                        result = Err(QkdManagerResponse::Ko);
                    }
                }
            )*
            match result {
                Ok(_) => Ok(query_args),
                Err(e) => Err(e)
            }
        }
    };
}

/// Notify all subscribers of an event
/// # Arguments
/// * `key_handler_reference` - The reference to the key handler, like `&self`
/// * `message` - The message to notify, as string slice
#[macro_export]
macro_rules! export_important_logging_message {
    ($key_handler_reference:expr, $message:expr) => {
        let displayed_producer = match $key_handler_reference.nickname {
            Some(ref nickname) => nickname.to_owned(),
            None => std::string::String::from(&format!("KME {}", $key_handler_reference.this_kme_id)),
        };
        let message = &format!("[{}] {}", displayed_producer, $message);
        info!("{}", $message);
        for subscriber in $key_handler_reference.event_notification_subscribers.read().await.iter() {
            let _ = subscriber.notify(message).await; // We ignore the result here
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::event_subscription::ImportantEventSubscriber;
    use crate::qkd_manager::http_response_obj::HttpResponseBody;
    use crate::qkd_manager::inter_kme_transport::InterKmeTransport;
    use crate::qkd_manager::QkdManagerResponse;
    use crate::zenoh_transport::contract::ZenohKeyState;
    use crate::zenoh_transport::raft::KeyLifecycleAuthorizer;
    use crate::{KmeId, RequestedKeyCount, SaeId};
    use std::future::Future;
    use std::io::Error;
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    const CLIENT_CERT_SERIAL_SIZE_BYTES: usize = 20;

    struct TestImportantEventSubscriber {
        events: RwLock<Vec<String>>,
    }
    impl TestImportantEventSubscriber {
        fn new() -> Self {
            Self {
                events: RwLock::new(Vec::new()),
            }
        }
    }
    impl ImportantEventSubscriber for TestImportantEventSubscriber {
        fn notify(&self, message: &str) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
            let message = message.to_string();
            Box::pin(async move {
                self.events
                    .write().await
                    .push(message);
                Ok(())
            })
        }
    }

    /// Fake [`KeyLifecycleAuthorizer`] for `key_handler.rs`'s own unit tests: lets the gating
    /// logic in `get_sae_keys`/`activate_key_uuids_sae` be exercised without a real Zenoh session.
    struct FakeRaftAuthorizer {
        accept: bool,
        current_states: Vec<(String, ZenohKeyState)>,
    }
    impl FakeRaftAuthorizer {
        fn accepting() -> Self {
            Self { accept: true, current_states: vec![] }
        }
        fn rejecting() -> Self {
            Self { accept: false, current_states: vec![] }
        }
        fn with_current_states(current_states: Vec<(String, ZenohKeyState)>) -> Self {
            Self { accept: true, current_states }
        }
    }
    impl KeyLifecycleAuthorizer for FakeRaftAuthorizer {
        fn authorize_transition<'a>(&'a self, key_id: &'a str, _slave_kme: &'a str, _requested_state: ZenohKeyState) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>> {
            let accept = self.accept;
            let key_id = key_id.to_string();
            Box::pin(async move {
                if accept {
                    Ok(())
                } else {
                    Err(Error::new(std::io::ErrorKind::Other, format!("Raft cluster rejected transition of key '{key_id}'")))
                }
            })
        }

        fn current_state(&self, key_id: &str) -> Option<ZenohKeyState> {
            self.current_states.iter().find(|(id, _)| id == key_id).map(|(_, state)| *state)
        }
    }

    /// Fake [`InterKmeTransport`] for `key_handler.rs`'s own unit tests: lets the delegation in
    /// `activate_keys_on_other_kme` be exercised (and its result asserted) without a real
    /// classical HTTPS client or Zenoh session.
    struct FakeInterKmeTransport {
        accept: bool,
    }
    impl FakeInterKmeTransport {
        fn accepting() -> Self {
            Self { accept: true }
        }
        fn rejecting() -> Self {
            Self { accept: false }
        }
    }
    impl InterKmeTransport for FakeInterKmeTransport {
        fn activate_key_on_remote_kme<'a>(&'a self, _caller_master_sae_id: SaeId, _other_kme_id: KmeId, _other_sae_id: SaeId, _keys: Vec<(String, Vec<u8>)>, _final_target_kme_id: KmeId, _visited_kme_ids: Vec<KmeId>) -> Pin<Box<dyn Future<Output = Result<(), QkdManagerResponse>> + Send + 'a>> {
            let accept = self.accept;
            Box::pin(async move {
                if accept {
                    Ok(())
                } else {
                    Err(QkdManagerResponse::RemoteKmeAcceptError)
                }
            })
        }

        fn void_keys_on_remote_kme<'a>(&'a self, _other_kme_id: KmeId, _key_uuids: Vec<String>) -> Pin<Box<dyn Future<Output = Result<(), QkdManagerResponse>> + Send + 'a>> {
            let accept = self.accept;
            Box::pin(async move {
                if accept {
                    Ok(())
                } else {
                    Err(QkdManagerResponse::RemoteKmeAcceptError)
                }
            })
        }
    }

    /// Fake [`KeyRoutingResolver`] for `key_handler.rs`'s own unit tests: always relays toward a
    /// fixed next hop, regardless of `final_target_kme_id`/`visited_kme_ids`.
    struct FakeKeyRoutingResolver {
        next_hop_kme_id: KmeId,
    }
    impl crate::zenoh_transport::routing::KeyRoutingResolver for FakeKeyRoutingResolver {
        fn next_hop(&self, _final_target_kme_id: KmeId, _visited_kme_ids: &[KmeId]) -> Option<crate::zenoh_transport::routing::NextHop> {
            Some(crate::zenoh_transport::routing::NextHop { kme_id: self.next_hop_kme_id, transport: crate::zenoh_transport::routing::HopTransport::Zenoh })
        }
    }

    #[tokio::test]
    async fn test_store_synced_keys_from_remote_relays_without_raft_gate_when_not_final_destination() {
        // This KME (id 3, e.g. B2 in the A-B1-B2-C topology) is only relaying toward KME 4: it
        // must never consult Raft state for a key transition it isn't a party to, even with no
        // committed state at all for it (which would reject if the gate wrongly applied here).
        let key_handler = super::KeyHandler::new(":memory:", 3, None).await.unwrap();
        key_handler.set_raft_authorizer(Arc::new(FakeRaftAuthorizer::with_current_states(vec![]))).await;
        key_handler.set_key_routing_resolver(Arc::new(FakeKeyRoutingResolver { next_hop_kme_id: 4 })).await;
        key_handler.set_inter_kme_transport(Arc::new(FakeInterKmeTransport::accepting())).await;

        let key_uuid = uuid::Uuid::from_bytes([9u8; 16]).to_string();
        let qkd_manager_response = key_handler.store_synced_keys_from_remote(1, 4, vec![(key_uuid, vec![9u8; crate::QKD_KEY_SIZE_BITS / 8])], 4, vec![1, 2, 3]).await;
        assert_eq!(qkd_manager_response.unwrap(), QkdManagerResponse::Ok);
    }

    #[tokio::test]
    async fn test_activate_key_uuids_sae_recovers_relayed_key_from_shared_folder_on_db_miss() {
        // This KME (id 3, e.g. B2) has no pre-init DB row at all for this uuid: it only exists as
        // a `relay_*.cor` file the immediate sender (KME 2, `visited_kme_ids`'s last entry) wrote
        // into the shared QKD-link directory, simulating the directory watcher not having picked
        // it up yet (e.g. unreliable fs change notifications across a container/bind mount).
        let key_handler = super::KeyHandler::new(":memory:", 3, None).await.unwrap();
        let dir = format!("tests/tmp/relay_fallback_test_{}", uuid::Uuid::new_v4());
        std::fs::create_dir_all(&dir).expect("test dir created");
        key_handler.add_qkd_link(2, &dir).await.unwrap();

        let key_uuid = uuid::Uuid::from_bytes([10u8; 16]).to_string();
        let key_bytes = [10u8; crate::QKD_KEY_SIZE_BITS / 8];
        let relay_file_path = format!("{}/relay_{}.cor", dir, key_uuid);
        std::fs::write(&relay_file_path, key_bytes).expect("relay file written");

        key_handler.set_key_routing_resolver(Arc::new(FakeKeyRoutingResolver { next_hop_kme_id: 4 })).await;
        key_handler.set_inter_kme_transport(Arc::new(FakeInterKmeTransport::accepting())).await;

        let qkd_manager_response = key_handler.activate_key_uuids_sae(1, 4, vec![key_uuid], 4, vec![1, 2]).await;
        assert_eq!(qkd_manager_response.unwrap(), QkdManagerResponse::Ok);
        assert!(!std::path::Path::new(&relay_file_path).exists(), "relay file should be consumed (deleted)");
    }

    #[tokio::test]
    async fn test_add_qkd_link_and_list_qkd_linked_kme_ids() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        assert_eq!(key_handler.list_qkd_linked_kme_ids().await, Vec::<KmeId>::new());

        key_handler.add_qkd_link(2, "raw_keys/kme-a-b1").await.unwrap();
        assert_eq!(key_handler.list_qkd_linked_kme_ids().await, vec![2]);
        assert_eq!(key_handler.qkd_link_directories().read().await.get(&2), Some(&"raw_keys/kme-a-b1".to_string()));

        // Idempotent: adding the same link again must not duplicate/fail.
        key_handler.add_qkd_link(2, "raw_keys/kme-a-b1").await.unwrap();
        assert_eq!(key_handler.list_qkd_linked_kme_ids().await, vec![2]);

        key_handler.add_qkd_link(3, "raw_keys/kme-a-b2").await.unwrap();
        let mut linked = key_handler.list_qkd_linked_kme_ids().await;
        linked.sort();
        assert_eq!(linked, vec![2, 3]);
    }

    #[tokio::test]
    async fn test_add_sae() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        let recv = key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        assert_eq!(recv, QkdManagerResponse::Ok);

        let recv = key_handler.add_sae(2, 1, &None).await.unwrap_err();
        assert_eq!(recv, QkdManagerResponse::InconsistentSaeData); // Must provide a client certificate if belongs to this SAE

        let recv = key_handler.add_sae(2, 2, &Some(sae_certificate_serial.clone())).await.unwrap_err();
        assert_eq!(recv, QkdManagerResponse::InconsistentSaeData); // Must not provide a client certificate if doesn't belong to this SAE

        let recv = key_handler.add_sae(2, 2, &None).await.unwrap();
        assert_eq!(recv, QkdManagerResponse::Ok);

        // Adding same SAE twice should not fail, it should just get ignored:
        let recv = key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        assert_eq!(recv, QkdManagerResponse::Ok);
        let recv = key_handler.add_sae(2, 2, &None).await.unwrap();
        assert_eq!(recv, QkdManagerResponse::Ok);
    }

    #[tokio::test]
    async fn test_get_sae_id_from_certificate() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_id = 1;
        let kme_id = 1;
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(sae_id, kme_id, &Some(sae_certificate_serial.clone())).await.unwrap();
        assert_eq!(key_handler.get_sae_id_from_certificate(&sae_certificate_serial).await.unwrap(), sae_id);

        let fake_sae_certificate_serial = vec![1u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        assert_eq!(key_handler.get_sae_id_from_certificate(&fake_sae_certificate_serial).await, None);
    }

    #[tokio::test]
    async fn test_add_preinit_key() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();
    }

    #[tokio::test]
    async fn test_add_multiple_preinit_qkd_keys() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let keys = vec![
            crate::qkd_manager::PreInitQkdKeyWrapper {
                other_kme_id: 1,
                key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
                key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
            },
            crate::qkd_manager::PreInitQkdKeyWrapper {
                other_kme_id: 2,
                key_uuid: *uuid::Uuid::from_bytes([1u8; 16]).as_bytes(),
                key: [1u8; crate::QKD_KEY_SIZE_BITS / 8],
            },
            crate::qkd_manager::PreInitQkdKeyWrapper {
                other_kme_id: 3,
                key_uuid: *uuid::Uuid::from_bytes([2u8; 16]).as_bytes(),
                key: [2u8; crate::QKD_KEY_SIZE_BITS / 8],
            },
        ];
        key_handler.add_multiple_preinit_qkd_keys(keys).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_sae_status() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_id = 1;
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(sae_id, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_status(&sae_certificate_serial, sae_id).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Status(_)));
        let response_status = match qkd_manager_response {
            QkdManagerResponse::Status(status) => status,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_status.to_json().unwrap().replace("\r", ""), "{\n  \"source_KME_ID\": \"1\",\n  \"target_KME_ID\": \"1\",\n  \"master_SAE_ID\": \"1\",\n  \"slave_SAE_ID\": \"1\",\n  \"key_size\": 256,\n  \"stored_key_count\": 0,\n  \"max_key_count\": 10,\n  \"max_key_per_request\": 10,\n  \"max_key_size\": 256,\n  \"min_key_size\": 256,\n  \"max_SAE_ID_count\": 0\n}");


        // add key for another KME id
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 2,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_status(&sae_certificate_serial, 2).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));

        key_handler.add_sae(2, 1, &Some(vec![1u8; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_status(&sae_certificate_serial, 2).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Status(_)));
        let response_status = match qkd_manager_response {
            QkdManagerResponse::Status(status) => status,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_status.to_json().unwrap(), "{\n  \"source_KME_ID\": \"1\",\n  \"target_KME_ID\": \"1\",\n  \"master_SAE_ID\": \"1\",\n  \"slave_SAE_ID\": \"2\",\n  \"key_size\": 256,\n  \"stored_key_count\": 0,\n  \"max_key_count\": 10,\n  \"max_key_per_request\": 10,\n  \"max_key_size\": 256,\n  \"min_key_size\": 256,\n  \"max_SAE_ID_count\": 0\n}");

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_status(&sae_certificate_serial, 2).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Status(_)));
        let response_status = match qkd_manager_response {
            QkdManagerResponse::Status(status) => status,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_status.to_json().unwrap(), "{\n  \"source_KME_ID\": \"1\",\n  \"target_KME_ID\": \"1\",\n  \"master_SAE_ID\": \"1\",\n  \"slave_SAE_ID\": \"2\",\n  \"key_size\": 256,\n  \"stored_key_count\": 1,\n  \"max_key_count\": 10,\n  \"max_key_per_request\": 10,\n  \"max_key_size\": 256,\n  \"min_key_size\": 256,\n  \"max_SAE_ID_count\": 0\n}");
    }

    #[tokio::test]
    async fn test_get_sae_keys() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_id = 1;
        let kme_id = 1;
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(sae_id, kme_id, &Some(sae_certificate_serial.clone())).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, sae_id, RequestedKeyCount::new(1).unwrap()).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([1u8; 16]).as_bytes(),
            key: [1u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([2u8; 16]).as_bytes(),
            key: [2u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([3u8; 16]).as_bytes(),
            key: [3u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, 2, RequestedKeyCount::new(1).unwrap()).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));

        key_handler.add_sae(2, kme_id, &Some(vec![1u8; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, 2, RequestedKeyCount::new(1).unwrap()).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Keys(_)));
        let response_keys = match qkd_manager_response {
            QkdManagerResponse::Keys(keys) => keys,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_keys.keys.len(), 1);


        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, 2, RequestedKeyCount::new(2).unwrap()).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Keys(_)));
        let response_keys = match qkd_manager_response {
            QkdManagerResponse::Keys(keys) => keys,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_keys.keys.len(), 2);

        // Not enough keys
        let qkd_manager_response = key_handler.get_sae_keys(
            &sae_certificate_serial,
            2,
            RequestedKeyCount::new(2).unwrap()
        ).await.unwrap();
        assert!(matches!(qkd_manager_response, QkdManagerResponse::Keys(_)));
        let response_keys = match qkd_manager_response {
            QkdManagerResponse::Keys(keys) => keys,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_keys.keys.len(), 1);
    }

    #[tokio::test]
    async fn test_get_sae_keys_raft_gate_rejects_before_remote_activation() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_sae(2, 2, &None).await.unwrap(); // SAE 2 belongs to KME 2: cross-KME, so no certificate here

        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 2,
            key_uuid: *uuid::Uuid::from_bytes([9u8; 16]).as_bytes(),
            key: [9u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        key_handler.set_raft_authorizer(Arc::new(FakeRaftAuthorizer::rejecting())).await;

        // The Raft gate must reject (and never reach `activate_keys_on_other_kme`, which would
        // otherwise fail with `MissingRemoteKmeConfiguration` since no classical net info is
        // registered for KME 2 in this test).
        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, 2, RequestedKeyCount::new(1).unwrap()).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::RaftConsensusRejected)));
    }

    #[tokio::test]
    async fn test_get_sae_keys_raft_gate_accepts_and_proceeds_to_remote_activation() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_sae(2, 2, &None).await.unwrap(); // SAE 2 belongs to KME 2: cross-KME, so no certificate here

        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 2,
            key_uuid: *uuid::Uuid::from_bytes([9u8; 16]).as_bytes(),
            key: [9u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        key_handler.set_raft_authorizer(Arc::new(FakeRaftAuthorizer::accepting())).await;

        // The Raft gate must accept and let execution reach `activate_keys_on_other_kme`, which
        // then fails on its own (no classical net info registered for KME 2 in this test) -
        // proving the gate is not what blocked the request.
        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, 2, RequestedKeyCount::new(1).unwrap()).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::MissingRemoteKmeConfiguration)));
    }

    #[tokio::test]
    async fn test_get_sae_keys_uses_the_installed_inter_kme_transport() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_sae(2, 2, &None).await.unwrap(); // SAE 2 belongs to KME 2: cross-KME, so no certificate here

        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 2,
            key_uuid: *uuid::Uuid::from_bytes([10u8; 16]).as_bytes(),
            key: [10u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        // No classical net info is registered for KME 2 at all, so this would fail with
        // `MissingRemoteKmeConfiguration` if the default HTTPS transport were still in use;
        // installing a fake transport instead must let the whole call succeed.
        key_handler.set_inter_kme_transport(Arc::new(FakeInterKmeTransport::accepting())).await;
        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, 2, RequestedKeyCount::new(1).unwrap()).await;
        assert!(matches!(qkd_manager_response, Ok(QkdManagerResponse::Keys(_))));
    }

    #[tokio::test]
    async fn test_get_sae_keys_propagates_the_installed_inter_kme_transport_rejection() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_sae(2, 2, &None).await.unwrap();

        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 2,
            key_uuid: *uuid::Uuid::from_bytes([11u8; 16]).as_bytes(),
            key: [11u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        key_handler.set_inter_kme_transport(Arc::new(FakeInterKmeTransport::rejecting())).await;
        let qkd_manager_response = key_handler.get_sae_keys(&sae_certificate_serial, 2, RequestedKeyCount::new(1).unwrap()).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::RemoteKmeAcceptError)));
    }

    #[tokio::test]
    async fn test_activate_key_uuids_sae_raft_gate_rejects_when_not_syncing() {
        let key_handler = super::KeyHandler::new(":memory:", 2, None).await.unwrap(); // this KME is the slave here
        let key_uuid = uuid::Uuid::from_bytes([7u8; 16]).to_string();
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([7u8; 16]).as_bytes(),
            key: [7u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        // No committed state at all for this key-id (`current_state` returns `None`): reject.
        key_handler.set_raft_authorizer(Arc::new(FakeRaftAuthorizer::with_current_states(vec![]))).await;

        let qkd_manager_response = key_handler.activate_key_uuids_sae(1, 2, vec![key_uuid], 2, vec![]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::RaftConsensusRejected)));
    }

    #[tokio::test]
    async fn test_activate_key_uuids_sae_raft_gate_accepts_when_syncing() {
        let key_handler = super::KeyHandler::new(":memory:", 2, None).await.unwrap(); // this KME is the slave here
        key_handler.add_sae(1, 1, &None).await.unwrap(); // origin SAE, belongs to the master KME
        key_handler.add_sae(2, 2, &Some(vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap(); // target SAE, belongs to this KME
        let key_uuid = uuid::Uuid::from_bytes([8u8; 16]).to_string();
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([8u8; 16]).as_bytes(),
            key: [8u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        key_handler.set_raft_authorizer(Arc::new(FakeRaftAuthorizer::with_current_states(vec![(key_uuid.clone(), ZenohKeyState::Syncing)]))).await;

        let qkd_manager_response = key_handler.activate_key_uuids_sae(1, 2, vec![key_uuid], 2, vec![]).await;
        assert_eq!(qkd_manager_response.unwrap(), QkdManagerResponse::Ok);
    }

    #[tokio::test]
    async fn test_get_sae_keys_with_ids() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_id = 1;
        let kme_id = 1;
        let sae_1_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        let sae_2_certificate_serial = vec![1u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(sae_id, kme_id, &Some(sae_1_certificate_serial.clone())).await.unwrap();
        key_handler.add_sae(2, kme_id, &Some(sae_2_certificate_serial.clone())).await.unwrap();
        let qkd_manager_response = key_handler.get_sae_keys_with_ids(&sae_1_certificate_serial, sae_id, vec!["00000000-0000-0000-0000-000000000000".to_string()]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));

        // add key
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        // SAE1 has to pre fetch the key first
        let qkd_manager_response = key_handler.get_sae_keys_with_ids(&sae_2_certificate_serial, 1, vec!["00000000-0000-0000-0000-000000000000".to_string()]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));

        assert!(matches!(key_handler.get_sae_keys(&sae_1_certificate_serial, 2, RequestedKeyCount::new(1).unwrap()).await.unwrap(), QkdManagerResponse::Keys(_)));
        let qkd_manager_response = key_handler.get_sae_keys_with_ids(&sae_2_certificate_serial, 1, vec!["00000000-0000-0000-0000-000000000000".to_string()]).await.unwrap();

        assert!(matches!(qkd_manager_response, QkdManagerResponse::Keys(_)));
        let response_keys = match qkd_manager_response {
            QkdManagerResponse::Keys(keys) => keys,
            _ => {
                panic!("Unexpected response");
            }
        };
        assert_eq!(response_keys.keys.len(), 1);
        assert_eq!(response_keys.keys[0].key_ID, "00000000-0000-0000-0000-000000000000");
        assert_eq!(response_keys.keys[0].key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

        // Revert origin and target SAE IDs
        let qkd_manager_response = key_handler.get_sae_keys_with_ids(&sae_1_certificate_serial, 2, vec!["00000000-0000-0000-0000-000000000000".to_string()]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));
    }

    #[tokio::test]
    async fn test_void_sae_keys_not_found() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_sae(2, 1, &Some(vec![1u8; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();

        let qkd_manager_response = key_handler.void_sae_keys(&sae_certificate_serial, 2, vec!["00000000-0000-0000-0000-000000000000".to_string()]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));
    }

    #[tokio::test]
    async fn test_void_sae_keys_same_kme_deletes_key() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_1_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        let sae_2_certificate_serial = vec![1u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_1_certificate_serial.clone())).await.unwrap();
        key_handler.add_sae(2, 1, &Some(sae_2_certificate_serial.clone())).await.unwrap();

        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([20u8; 16]).as_bytes(),
            key: [20u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();

        // Master (SAE1) activates the key for slave SAE2 (both belong to this same KME)
        assert!(matches!(key_handler.get_sae_keys(&sae_1_certificate_serial, 2, RequestedKeyCount::new(1).unwrap()).await.unwrap(), QkdManagerResponse::Keys(_)));

        let key_uuid = uuid::Uuid::from_bytes([20u8; 16]).to_string();

        // Slave (SAE2) can still retrieve it before voiding
        assert!(matches!(key_handler.get_sae_keys_with_ids(&sae_2_certificate_serial, 1, vec![key_uuid.clone()]).await.unwrap(), QkdManagerResponse::Keys(_)));

        // Master voids it
        let qkd_manager_response = key_handler.void_sae_keys(&sae_1_certificate_serial, 2, vec![key_uuid.clone()]).await;
        assert_eq!(qkd_manager_response.unwrap(), QkdManagerResponse::Ok);

        // The key is now gone: it cannot be retrieved anymore
        let qkd_manager_response = key_handler.get_sae_keys_with_ids(&sae_2_certificate_serial, 1, vec![key_uuid.clone()]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));

        // Voiding again must fail: the row is already gone
        let qkd_manager_response = key_handler.void_sae_keys(&sae_1_certificate_serial, 2, vec![key_uuid]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));
    }

    #[tokio::test]
    async fn test_void_sae_keys_raft_gate_rejects() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_sae(2, 2, &None).await.unwrap(); // SAE 2 belongs to KME 2: cross-KME

        let key_uuid = uuid::Uuid::from_bytes([21u8; 16]).to_string();
        // Directly insert the activated key row, as if a prior cross-KME activation had already completed
        key_handler.insert_activated_key(&key_uuid, &[21u8; crate::QKD_KEY_SIZE_BITS / 8], 1, 2, None).await.unwrap();

        key_handler.set_raft_authorizer(Arc::new(FakeRaftAuthorizer::rejecting())).await;

        // The Raft gate must reject (and never reach `void_keys_on_other_kme`, which would
        // otherwise fail with `MissingRemoteKmeConfiguration` since no classical net info is
        // registered for KME 2 in this test).
        let qkd_manager_response = key_handler.void_sae_keys(&sae_certificate_serial, 2, vec![key_uuid]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::RaftConsensusRejected)));
    }

    #[tokio::test]
    async fn test_void_sae_keys_raft_gate_accepts_and_notifies_remote() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_sae(2, 2, &None).await.unwrap();

        let key_uuid = uuid::Uuid::from_bytes([22u8; 16]).to_string();
        key_handler.insert_activated_key(&key_uuid, &[22u8; crate::QKD_KEY_SIZE_BITS / 8], 1, 2, None).await.unwrap();

        key_handler.set_raft_authorizer(Arc::new(FakeRaftAuthorizer::accepting())).await;
        key_handler.set_inter_kme_transport(Arc::new(FakeInterKmeTransport::accepting())).await;

        let qkd_manager_response = key_handler.void_sae_keys(&sae_certificate_serial, 2, vec![key_uuid.clone()]).await;
        assert_eq!(qkd_manager_response.unwrap(), QkdManagerResponse::Ok);

        // The row is now gone locally too
        let qkd_manager_response = key_handler.void_sae_keys(&sae_certificate_serial, 2, vec![key_uuid]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));
    }

    #[tokio::test]
    async fn test_void_sae_keys_propagates_remote_transport_rejection() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_sae(2, 2, &None).await.unwrap();

        let key_uuid = uuid::Uuid::from_bytes([23u8; 16]).to_string();
        key_handler.insert_activated_key(&key_uuid, &[23u8; crate::QKD_KEY_SIZE_BITS / 8], 1, 2, None).await.unwrap();

        key_handler.set_inter_kme_transport(Arc::new(FakeInterKmeTransport::rejecting())).await;

        let qkd_manager_response = key_handler.void_sae_keys(&sae_certificate_serial, 2, vec![key_uuid.clone()]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::RemoteKmeAcceptError)));

        // The local row must still be present: nothing was deleted since the remote KME rejected first
        let qkd_manager_response = key_handler.void_sae_keys(&sae_certificate_serial, 2, vec![key_uuid]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::RemoteKmeAcceptError)));
    }

    #[tokio::test]
    async fn test_void_key_uuids_sae_deletes_local_key() {
        let key_handler = super::KeyHandler::new(":memory:", 2, None).await.unwrap(); // this KME is the slave here
        let sae_2_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &None).await.unwrap();
        key_handler.add_sae(2, 2, &Some(sae_2_certificate_serial.clone())).await.unwrap();

        let key_uuid = uuid::Uuid::from_bytes([24u8; 16]).to_string();
        key_handler.insert_activated_key(&key_uuid, &[24u8; crate::QKD_KEY_SIZE_BITS / 8], 1, 2, None).await.unwrap();

        // No Raft authorizer configured: classical mode, void proceeds without any consensus check
        let qkd_manager_response = key_handler.void_key_uuids_sae(vec![key_uuid.clone()]).await;
        assert_eq!(qkd_manager_response.unwrap(), QkdManagerResponse::Ok);

        // The key is gone
        let qkd_manager_response = key_handler.get_sae_keys_with_ids(&sae_2_certificate_serial, 1, vec![key_uuid]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::NotFound)));
    }

    #[tokio::test]
    async fn test_void_key_uuids_sae_raft_gate_rejects_when_not_deleted_or_used() {
        let key_handler = super::KeyHandler::new(":memory:", 2, None).await.unwrap();
        key_handler.add_sae(1, 1, &None).await.unwrap();
        key_handler.add_sae(2, 2, &Some(vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let key_uuid = uuid::Uuid::from_bytes([25u8; 16]).to_string();
        key_handler.insert_activated_key(&key_uuid, &[25u8; crate::QKD_KEY_SIZE_BITS / 8], 1, 2, None).await.unwrap();

        // Raft cluster's local view for this key is InUse, not (yet) DeletedOrUsed: reject
        key_handler.set_raft_authorizer(Arc::new(FakeRaftAuthorizer::with_current_states(vec![(key_uuid.clone(), ZenohKeyState::InUse)]))).await;

        let qkd_manager_response = key_handler.void_key_uuids_sae(vec![key_uuid]).await;
        assert!(matches!(qkd_manager_response, Err(QkdManagerResponse::RaftConsensusRejected)));
    }

    #[tokio::test]
    async fn test_void_key_uuids_sae_raft_gate_accepts_when_deleted_or_used() {
        let key_handler = super::KeyHandler::new(":memory:", 2, None).await.unwrap();
        key_handler.add_sae(1, 1, &None).await.unwrap();
        key_handler.add_sae(2, 2, &Some(vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let key_uuid = uuid::Uuid::from_bytes([26u8; 16]).to_string();
        key_handler.insert_activated_key(&key_uuid, &[26u8; crate::QKD_KEY_SIZE_BITS / 8], 1, 2, None).await.unwrap();

        key_handler.set_raft_authorizer(Arc::new(FakeRaftAuthorizer::with_current_states(vec![(key_uuid.clone(), ZenohKeyState::DeletedOrUsed)]))).await;

        let qkd_manager_response = key_handler.void_key_uuids_sae(vec![key_uuid]).await;
        assert_eq!(qkd_manager_response.unwrap(), QkdManagerResponse::Ok);
    }

    #[tokio::test]
    async fn test_get_kme_id_from_sae() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_id = 1;
        let kme_id = 1;
        let sae_1_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(sae_id, kme_id, &Some(sae_1_certificate_serial)).await.unwrap();
        let kme_id = key_handler.get_kme_id_from_sae_id(sae_id).await.unwrap();
        assert_eq!(kme_id, 1);
        let kme_id = key_handler.get_kme_id_from_sae_id(2).await;
        assert!(matches!(kme_id, None));
    }

    #[tokio::test]
    async fn test_get_sae_infos_from_certificate() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let sae_id = 1;
        let kme_id = 1;

        let sae_info = key_handler.get_sae_infos_from_certificate(&vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES]).await;
        assert!(matches!(sae_info, Err(QkdManagerResponse::NotFound)));

        key_handler.add_sae(sae_id, kme_id, &Some(vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES])).await.unwrap();
        let sae_info = key_handler.get_sae_infos_from_certificate(&vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES]).await.unwrap();
        assert!(matches!(sae_info, QkdManagerResponse::SaeInfo(_)));
        assert_eq!(sae_info, QkdManagerResponse::SaeInfo(super::SAEInfo {
            sae_id,
            kme_id,
            sae_certificate_serial: vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES],
        }));
    }

    #[tokio::test]
    async fn test_delete_pre_init_key_with_id() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();
        let key = crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        };
        key_handler.add_preinit_qkd_key(key).await.unwrap();
        let key_id = 1; // As it's the first key, we can assume it's the ID
        key_handler.delete_pre_init_key_with_id(key_id, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_add_important_event_subscriber_without_nickname() {
        let key_handler = super::KeyHandler::new(":memory:", 1, None).await.unwrap();

        let subscriber = Arc::new(TestImportantEventSubscriber::new());
        let subscriber2 = Arc::new(TestImportantEventSubscriber::new());

        key_handler.event_notification_subscribers.write().await.push(Arc::clone(&subscriber) as Arc<dyn ImportantEventSubscriber>);
        key_handler.event_notification_subscribers.write().await.push(Arc::clone(&subscriber2) as Arc<dyn ImportantEventSubscriber>);
        assert_eq!(key_handler.event_notification_subscribers.read().await.len(), 2);
        assert_eq!(subscriber.events.read().await.len(), 0);
        assert_eq!(subscriber2.events.read().await.len(), 0);

        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_preinit_qkd_key(crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        }).await.unwrap();
        key_handler.get_sae_keys(&sae_certificate_serial, 1, RequestedKeyCount::new(1).unwrap()).await.unwrap();

        assert_eq!(subscriber.events.read().await.len(), 2);
        assert_eq!(subscriber2.events.read().await.len(), 2);
        assert_eq!(subscriber.events.read().await[0], "[KME 1] SAE 1 requested a key to communicate with 1");
        assert_eq!(subscriber.events.read().await[1], "[KME 1] Key 00000000-0000-0000-0000-000000000000 activated between SAEs 1 and 1");
        assert_eq!(subscriber2.events.read().await[0], "[KME 1] SAE 1 requested a key to communicate with 1");
        assert_eq!(subscriber2.events.read().await[1], "[KME 1] Key 00000000-0000-0000-0000-000000000000 activated between SAEs 1 and 1");
    }

    #[tokio::test]
    async fn test_add_important_event_subscriber_with_nickname() {
        let key_handler = super::KeyHandler::new(":memory:", 1, Some("Alice".to_string())).await.unwrap();

        let subscriber = Arc::new(TestImportantEventSubscriber::new());
        let subscriber2 = Arc::new(TestImportantEventSubscriber::new());

        key_handler.event_notification_subscribers.write().await.push(Arc::clone(&subscriber) as Arc<dyn ImportantEventSubscriber>);
        key_handler.event_notification_subscribers.write().await.push(Arc::clone(&subscriber2) as Arc<dyn ImportantEventSubscriber>);
        assert_eq!(key_handler.event_notification_subscribers.write().await.len(), 2);
        assert_eq!(subscriber.events.read().await.len(), 0);
        assert_eq!(subscriber2.events.read().await.len(), 0);

        let sae_certificate_serial = vec![0u8; CLIENT_CERT_SERIAL_SIZE_BYTES];
        key_handler.add_sae(1, 1, &Some(sae_certificate_serial.clone())).await.unwrap();
        key_handler.add_preinit_qkd_key(crate::qkd_manager::PreInitQkdKeyWrapper {
            other_kme_id: 1,
            key_uuid: *uuid::Uuid::from_bytes([0u8; 16]).as_bytes(),
            key: [0u8; crate::QKD_KEY_SIZE_BITS / 8],
        }).await.unwrap();
        key_handler.get_sae_keys(&sae_certificate_serial, 1, RequestedKeyCount::new(1).unwrap()).await.unwrap();

        assert_eq!(subscriber.events.read().await.len(), 2);
        assert_eq!(subscriber2.events.read().await.len(), 2);
        assert_eq!(subscriber.events.read().await[0], "[Alice] SAE 1 requested a key to communicate with 1");
        assert_eq!(subscriber.events.read().await[1], "[Alice] Key 00000000-0000-0000-0000-000000000000 activated between SAEs 1 and 1");
        assert_eq!(subscriber2.events.read().await[0], "[Alice] SAE 1 requested a key to communicate with 1");
        assert_eq!(subscriber2.events.read().await[1], "[Alice] Key 00000000-0000-0000-0000-000000000000 activated between SAEs 1 and 1");
    }
}