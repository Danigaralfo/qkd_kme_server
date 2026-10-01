//! Runtime for the Zenoh transport layer.
//!
//! This module only covers real node bootstrap: opening the Zenoh session,
//! serving this node's own version over the Storage/Query pattern, and
//! subscribing to this node's own contract topics. The real Raft-lite
//! consensus for key-state transitions (Phase 4) lives in `raft.rs`, so it
//! can evolve independently of this bootstrap code.

use crate::io_err;
use crate::qkd_manager::QkdManager;
use crate::KmeId;
use log::{error, info};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use super::contract::{ZenohEtsiVersionResponse, ZenohKmeRegistryInfo, ZenohTopicMap, ZENOH_CONTRACT_VERSION};
use super::inter_kme_transport::{self, HybridInterKmeTransport, ZenohInterKmeTransport};
use super::messages::ZenohEnvelope;
use super::persistence;
use super::raft;
use super::registry::KmeNodeRegistry;
use super::routing::ZenohKeyRouter;
use super::config::ZenohTransportConfig;
use zenoh::sample::{Sample, SampleKind};

/// Safety-net-only interval for a full wildcard registry re-poll (see
/// [`ZenohTransport::spawn_registry_discovery`]). New KMEs are normally registered immediately,
/// reacting to their Zenoh liveliness token appearing, so this only needs to catch a liveliness
/// event missed to a network hiccup - hence the long interval.
const REGISTRY_DISCOVERY_FALLBACK_INTERVAL: Duration = Duration::from_secs(300);

/// Entry point for the Zenoh transport runtime.
#[derive(Clone, Debug)]
pub struct ZenohTransport {
    config: ZenohTransportConfig,
}

impl ZenohTransport {
    /// Create a new runtime handle from the provided configuration.
    pub fn new(config: ZenohTransportConfig) -> Self {
        Self { config }
    }

    /// Start the transport layer: open the Zenoh session, serve this node's
    /// own version and subscribe to its own contract topics. `qkd_manager` is given a
    /// [`ZenohInterKmeTransport`] (installed via `set_inter_kme_transport`) and is used to
    /// service incoming key activation requests from other KMEs (see [`inter_kme_transport`]).
    pub async fn start(config: ZenohTransportConfig, qkd_manager: QkdManager) -> Result<(), io::Error> {
        let transport = Self::new(config);
        info!(
            "Starting Zenoh transport for node '{}' with role {:?}",
            transport.config.node_id,
            transport.config.role
        );
        transport.run(qkd_manager).await
    }

    fn build_session_config(&self) -> Result<zenoh::Config, io::Error> {
        // mTLS is mandatory for the Zenoh transport: refuse to start rather than silently
        // fall back to a plaintext link. Endpoints (`listen_endpoint`/`peers`/`router_endpoint`)
        // are expected to use the `tls/` locator scheme when this is configured (see the
        // shipped `config_kme*.json5` files for a working example).
        let tls = self.config.tls.as_ref().ok_or_else(|| {
            io_err(
                "Zenoh transport requires mTLS configuration (zenoh_transport.tls): refusing to \
                 start without it",
            )
        })?;

        let listen_endpoints_json = match &self.config.listen_endpoint {
            Some(endpoint) => serde_json::to_string(&vec![endpoint])
                .map_err(|e| io_err(&format!("Cannot serialize Zenoh listen endpoint: {e}")))?,
            None => String::from("[]"),
        };

        let mut connect_endpoints = self.config.peers.clone();
        if let Some(router_endpoint) = &self.config.router_endpoint {
            connect_endpoints.push(router_endpoint.clone());
        }
        let connect_endpoints_json = serde_json::to_string(&connect_endpoints)
            .map_err(|e| io_err(&format!("Cannot serialize Zenoh endpoints: {e}")))?;
        let mode_json = serde_json::to_string(self.config.role.as_zenoh_mode_str())
            .map_err(|e| io_err(&format!("Cannot serialize Zenoh mode: {e}")))?;

        let root_ca_certificate_json = serde_json::to_string(&tls.root_ca_certificate)
            .map_err(|e| io_err(&format!("Cannot serialize Zenoh TLS root CA certificate path: {e}")))?;
        // Same certificate/key presented for both roles: Zenoh's `transport.link.tls` still has
        // separate listen/connect fields, but this node only has one identity.
        let certificate_json = serde_json::to_string(&tls.certificate)
            .map_err(|e| io_err(&format!("Cannot serialize Zenoh TLS certificate path: {e}")))?;
        let private_key_json = serde_json::to_string(&tls.private_key)
            .map_err(|e| io_err(&format!("Cannot serialize Zenoh TLS private key path: {e}")))?;

        // Automatic peer discovery (see `ZenohScoutingConfig`): multicast scouting finds peers
        // on the same broadcast domain, gossip scouting (with `multihop: true`) propagates that
        // information further, hop-by-hop, through already-established links so a node reachable
        // only through one or more intermediate KMEs is still discovered - `peers` becomes an
        // optional bootstrap hint rather than a requirement for reachability. The scouting beacon
        // itself carries no payload data; the actual session/link is still negotiated over the
        // mTLS-secured `transport.link.tls` configured below, so this does not weaken mTLS.
        let multicast_interface_json = match &self.config.scouting.multicast_interface {
            Some(interface) => {
                let interface_json = serde_json::to_string(interface)
                    .map_err(|e| io_err(&format!("Cannot serialize Zenoh multicast interface: {e}")))?;
                format!(", interface: {interface_json}")
            }
            None => String::new(),
        };

        let config_json = format!(
            r#"{{
  mode: {mode_json},
  connect: {{ endpoints: {connect_endpoints_json} }},
  listen: {{ endpoints: {listen_endpoints_json} }},
  scouting: {{
    multicast: {{ enabled: true{multicast_interface_json} }},
    gossip: {{ enabled: true, multihop: true }}
  }},
  transport: {{
    link: {{
      tls: {{
        root_ca_certificate: {root_ca_certificate_json},
        listen_certificate: {certificate_json},
        listen_private_key: {private_key_json},
        connect_certificate: {certificate_json},
        connect_private_key: {private_key_json},
        enable_mtls: true
      }}
    }}
  }}
}}"#
        );

        zenoh::Config::from_json5(config_json.as_str())
            .map_err(|e| io_err(&format!("Cannot build Zenoh config: {e}")))
    }

    /// Initialize this Zenoh node: open the session, serve this node's own
    /// version over the Storage/Query pattern, subscribe to its own
    /// remaining contract topics, and hand off the session to the real
    /// Raft-lite consensus protocol (see `raft.rs`) before waiting for shutdown.
    async fn run(&self, qkd_manager: QkdManager) -> Result<(), io::Error> {
        let session_config = self.build_session_config()?;
        let session = zenoh::open(session_config)
            .await
            .map_err(|e| io_err(&format!("Cannot open Zenoh session: {e}")))?;

        self.spawn_own_version_queryable(&session).await?;
        self.spawn_own_subscribers(&session).await?;
        // Hot-plug support: serve this node's own KME/SAE identity over Zenoh, and react
        // immediately when another KME's Zenoh liveliness token appears (with a long-interval
        // wildcard poll kept as a safety net), so this node's live database learns about a
        // newly-joined KME's SAE ownership (and vice versa) without needing a static
        // `other_kmes`/`saes` config entry anywhere, and without waiting on a fixed poll delay.
        let kme_registry = KmeNodeRegistry::new(self.config.other_kme_node_ids.clone());
        // Self-seed this node's own entry immediately, so its own QKD adjacency is available to
        // routing decisions (see `crate::zenoh_transport::routing`) without waiting on a round
        // trip through discovery for what this node already knows about itself.
        kme_registry.upsert(qkd_manager.kme_id, self.config.node_id.clone(), qkd_manager.list_qkd_linked_kme_ids().await);

        // Install the hybrid classical/Zenoh transport and the multi-hop routing resolver as
        // early as possible - right after the session and registry are ready, and deliberately
        // BEFORE the slower setup below (registry queryable, liveliness, discovery, persistence,
        // Raft). The SAE-facing HTTPS server is started concurrently with this whole `run()` (see
        // `main.rs`), so any `enc_keys` request arriving while later steps are still in progress
        // must already see a real routing resolver installed - otherwise `KeyHandler::get_sae_keys`
        // silently falls back to treating the final-destination KME as directly reachable (no
        // resolver installed yet), pulling from the wrong local key pool and failing with "No key
        // available" even though a valid multi-hop route exists.
        let default_https_transport = qkd_manager.current_inter_kme_transport().await;
        let zenoh_transport = ZenohInterKmeTransport::new(self.config.clone(), session.clone(), kme_registry.clone());
        let hybrid_transport = HybridInterKmeTransport::new(default_https_transport, Arc::new(zenoh_transport), qkd_manager.qkd_link_directories());
        qkd_manager.set_inter_kme_transport(Arc::new(hybrid_transport)).await;
        qkd_manager.set_key_routing_resolver(Arc::new(ZenohKeyRouter::new(qkd_manager.kme_id, kme_registry.clone()))).await;

        self.spawn_own_registry_queryable(&session, &qkd_manager).await?;
        // Kept alive for the process lifetime: dropping it would undeclare our own presence.
        let own_liveliness_topic = ZenohTopicMap::kme_liveliness_topic(self.config.node_id.as_str());
        let _own_liveliness_token = session
            .liveliness()
            .declare_token(own_liveliness_topic.as_str())
            .await
            .map_err(|e| io_err(&format!("Cannot declare Zenoh liveliness token: {e}")))?;
        info!("Zenoh liveliness token declared on '{}': this node is now visible to other KMEs' registry discovery", own_liveliness_topic);
        self.spawn_registry_discovery(session.clone(), qkd_manager.clone(), kme_registry).await?;
        // Phase 7: durably persist Raft-lite key states/commits in this KME's own database
        // (reusing `qkd_manager`'s existing connection pool) so consensus survives a restart.
        let persistence = persistence::RaftPersistence::new(qkd_manager.db_pool(), qkd_manager.dbms_type()).await?;
        let key_states = raft::spawn(&self.config, &session, persistence).await?;

        // Real (non-demo) inter-KME wiring: service incoming key-sync requests, and make
        // outgoing ones (from qkd_manager's business logic) go out over Zenoh instead of
        // classical HTTPS.
        inter_kme_transport::spawn_key_sync_responder(self.config.node_id.clone(), session.clone(), qkd_manager.clone()).await?;
        inter_kme_transport::spawn_void_key_responder(self.config.node_id.clone(), session.clone(), qkd_manager.clone()).await?;
        // Gate real cross-KME key-state transitions on this same Raft cluster, so the state
        // machine built in Phase 5 is actually enforced for real SAE traffic.
        qkd_manager.set_raft_authorizer(Arc::new(raft::RaftKeyCoordinator::new(self.config.clone(), session.clone(), key_states))).await;

        info!(
            "Zenoh transport started for node '{}' on contract topics",
            self.config.node_id,
        );

        tokio::signal::ctrl_c()
            .await
            .map_err(|e| io_err(&format!("Zenoh transport interrupted: {e}")))?;
        Ok(())
    }

    /// Serve this node's own `/kmapi/version` topic as a Zenoh queryable.
    ///
    /// This implements the Storage/Query pattern required by the specification:
    /// the node "stores" its version info and answers queries directly, instead
    /// of publishing it.
    async fn spawn_own_version_queryable(&self, session: &zenoh::Session) -> Result<(), io::Error> {
        let topic = ZenohTopicMap::version_query_topic(self.config.node_id.as_str());
        let node_id = self.config.node_id.clone();
        let queryable = session
            .declare_queryable(topic.as_str())
            .await
            .map_err(|e| io_err(&format!("Cannot declare Zenoh queryable: {e}")))?;

        tokio::spawn(async move {
            while let Ok(query) = queryable.recv_async().await {
                let response = ZenohEtsiVersionResponse {
                    request_id: Uuid::new_v4().to_string(),
                    responder_kme: node_id.clone(),
                    api_version: String::from("v1"),
                    contract_version: String::from(ZENOH_CONTRACT_VERSION),
                };
                match serde_json::to_string(&response) {
                    Ok(payload) => {
                        info!("Zenoh version queryable '{}' <- query on '{topic}', replying: {payload}", node_id);
                        if let Err(e) = query.reply(topic.as_str(), payload.as_str()).await {
                            error!("Zenoh version queryable '{}' failed to reply on '{topic}': {e}", node_id);
                        }
                    }
                    Err(e) => error!("Zenoh version queryable '{}' cannot serialize response: {e}", node_id),
                }
            }
            error!("Zenoh version queryable '{}' loop ended unexpectedly", node_id);
        });

        Ok(())
    }

    /// Serve this node's own [`ZenohKmeRegistryInfo`] (numeric KME id, Zenoh node_id, and owned
    /// SAE ids) as a Zenoh queryable, mirroring [`Self::spawn_own_version_queryable`]'s
    /// Storage/Query pattern. Queried (on a wildcard selector) by every node's
    /// [`Self::spawn_registry_discovery`] task, including this node's own, so a KME hot-plugged
    /// into a running network is discoverable without any static config entry elsewhere.
    async fn spawn_own_registry_queryable(&self, session: &zenoh::Session, qkd_manager: &QkdManager) -> Result<(), io::Error> {
        let topic = ZenohTopicMap::kme_registry_info_topic(self.config.node_id.as_str());
        let node_id = self.config.node_id.clone();
        let kme_id = qkd_manager.kme_id;
        let qkd_manager = qkd_manager.clone();
        let queryable = session
            .declare_queryable(topic.as_str())
            .await
            .map_err(|e| io_err(&format!("Cannot declare Zenoh queryable: {e}")))?;

        tokio::spawn(async move {
            while let Ok(query) = queryable.recv_async().await {
                let response = ZenohKmeRegistryInfo {
                    kme_id,
                    node_id: node_id.clone(),
                    sae_ids: qkd_manager.own_sae_ids().await,
                    qkd_linked_kme_ids: qkd_manager.list_qkd_linked_kme_ids().await,
                };
                match serde_json::to_string(&response) {
                    Ok(payload) => {
                        info!("Zenoh registry queryable '{}' <- query on '{topic}', replying: {payload}", node_id);
                        if let Err(e) = query.reply(topic.as_str(), payload.as_str()).await {
                            error!("Zenoh registry queryable '{}' failed to reply on '{topic}': {e}", node_id);
                        }
                    }
                    Err(e) => error!("Zenoh registry queryable '{}' cannot serialize response: {e}", node_id),
                }
            }
            error!("Zenoh registry queryable '{}' loop ended unexpectedly", node_id);
        });

        Ok(())
    }

    /// Register newly-discovered KMEs as they actually join the network, instead of waiting on a
    /// fixed poll delay: subscribes to Zenoh liveliness changes on
    /// [`ZenohTopicMap::kme_liveliness_query_selector`] (with history, so already-reachable KMEs
    /// are also delivered immediately on subscribe) and, for every KME node that becomes
    /// reachable, queries its [`ZenohKmeRegistryInfo`] (see
    /// [`Self::spawn_own_registry_queryable`]) right away. A long-interval wildcard poll is kept
    /// running alongside it purely as a safety net for a liveliness event missed to a network
    /// hiccup - the network layer already knows when a node joins, so that's what drives
    /// registration, not this poll.
    ///
    /// Registration itself: any newly-discovered SAE ownership is added to this node's own
    /// database (via `QkdManager::add_sae`) and any newly-discovered `KmeId -> node_id` mapping
    /// is recorded into `kme_registry`. This is what makes hot-plugging work end-to-end: a KME
    /// does not need to appear in any other node's static `other_kmes`/`saes` config at all, it
    /// only needs to be reachable over Zenoh (scouting handles that automatically, see
    /// `ZenohScoutingConfig`).
    ///
    /// Trust note: a discovered SAE mapping is only ever ignored (not applied) when it collides
    /// with an SAE id already registered to *this* KME, so a remote node cannot overwrite this
    /// KME's own SAE ownership/certificate. Beyond that, remote KMEs' claims about which SAE ids
    /// they own are trusted at face value, consistently with mTLS peers being assumed to belong
    /// to the same operator's QKD network (there is no per-SAE cryptographic proof of ownership).
    async fn spawn_registry_discovery(&self, session: zenoh::Session, qkd_manager: QkdManager, kme_registry: KmeNodeRegistry) -> Result<(), io::Error> {
        let own_kme_id = qkd_manager.kme_id;
        let own_node_id = self.config.node_id.clone();

        let liveliness_subscriber = session
            .liveliness()
            .declare_subscriber(ZenohTopicMap::kme_liveliness_query_selector())
            .history(true)
            .await
            .map_err(|e| io_err(&format!("Cannot declare Zenoh liveliness subscriber: {e}")))?;
        info!(
            "Zenoh registry discovery started for node '{}': watching liveliness on '{}' (fallback poll every {:?})",
            own_node_id, ZenohTopicMap::kme_liveliness_query_selector(), REGISTRY_DISCOVERY_FALLBACK_INTERVAL
        );

        {
            let session = session.clone();
            let qkd_manager = qkd_manager.clone();
            let kme_registry = kme_registry.clone();
            let own_node_id = own_node_id.clone();
            tokio::spawn(async move {
                while let Ok(sample) = liveliness_subscriber.recv_async().await {
                    let key_expr: &str = sample.key_expr().as_ref();
                    let Some(remote_node_id) = key_expr.strip_prefix("kme/").and_then(|rest| rest.strip_suffix("/liveliness")) else {
                        continue;
                    };
                    if remote_node_id == own_node_id {
                        continue; // Our own liveliness token.
                    }
                    match sample.kind() {
                        SampleKind::Put => {
                            info!("Zenoh registry discovery: KME node '{}' just became reachable, registering it now", remote_node_id);
                            Self::query_and_register_registry_info(
                                &session,
                                ZenohTopicMap::kme_registry_info_topic(remote_node_id).as_str(),
                                own_kme_id,
                                own_node_id.as_str(),
                                &qkd_manager,
                                &kme_registry,
                            ).await;
                        }
                        SampleKind::Delete => {
                            info!("Zenoh registry discovery: KME node '{}' is no longer reachable", remote_node_id);
                        }
                    }
                }
                error!("Zenoh liveliness subscriber loop ended unexpectedly");
            });
        }

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(REGISTRY_DISCOVERY_FALLBACK_INTERVAL).await;
                Self::query_and_register_registry_info(
                    &session,
                    ZenohTopicMap::kme_registry_info_query_selector(),
                    own_kme_id,
                    own_node_id.as_str(),
                    &qkd_manager,
                    &kme_registry,
                ).await;
            }
        });

        Ok(())
    }

    /// Query `selector` for [`ZenohKmeRegistryInfo`] replies and register every one of them, see
    /// [`Self::spawn_registry_discovery`].
    async fn query_and_register_registry_info(
        session: &zenoh::Session,
        selector: &str,
        own_kme_id: KmeId,
        own_node_id: &str,
        qkd_manager: &QkdManager,
        kme_registry: &KmeNodeRegistry,
    ) {
        info!("Zenoh registry discovery '{}' -> querying '{selector}' for KME registry info", own_node_id);
        match session.get(selector).await {
            Ok(replies) => {
                let mut reply_count = 0usize;
                while let Ok(reply) = replies.recv_async().await {
                    match reply.result() {
                        Ok(sample) => {
                            reply_count += 1;
                            Self::handle_registry_discovery_reply(
                                sample,
                                own_kme_id,
                                own_node_id,
                                qkd_manager,
                                kme_registry,
                            ).await;
                        }
                        Err(e) => error!("Zenoh registry discovery: query reply on '{selector}' carried an error: {:?}", e),
                    }
                }
                info!("Zenoh registry discovery '{}' <- '{selector}' returned {reply_count} repl{}", own_node_id, if reply_count == 1 { "y" } else { "ies" });
            }
            Err(e) => error!("Zenoh registry discovery: failed to query '{selector}': {e}"),
        }
    }

    /// Handle a single reply to a registry discovery query, see
    /// [`Self::query_and_register_registry_info`].
    async fn handle_registry_discovery_reply(
        sample: &Sample,
        own_kme_id: KmeId,
        own_node_id: &str,
        qkd_manager: &QkdManager,
        kme_registry: &KmeNodeRegistry,
    ) {
        let payload = match sample.payload().try_to_string() {
            Ok(payload) => payload,
            Err(_) => {
                error!("Zenoh registry discovery: received non-UTF8 registry info payload");
                return;
            }
        };
        let info: ZenohKmeRegistryInfo = match serde_json::from_str(&payload) {
            Ok(info) => info,
            Err(e) => {
                error!("Zenoh registry discovery: cannot parse registry info payload: {e}");
                return;
            }
        };
        if info.node_id == own_node_id || info.kme_id == own_kme_id {
            return; // Our own reply to our own wildcard query.
        }

        if kme_registry.upsert(info.kme_id, info.node_id.clone(), info.qkd_linked_kme_ids.clone()) {
            info!(
                "Zenoh registry discovery: discovered KME {} (node '{}', {} SAE(s)); registering locally",
                info.kme_id, info.node_id, info.sae_ids.len()
            );
        }

        for sae_id in info.sae_ids {
            // Never let a remote announcement overwrite an SAE already known to belong to this
            // KME (see the trust note on `spawn_registry_discovery`).
            if let Some(existing) = qkd_manager.get_kme_id_from_sae_id(sae_id).await {
                if existing.kme_id == own_kme_id {
                    info!("Zenoh registry discovery: ignoring KME {}'s claim over SAE {}, already registered to this KME", info.kme_id, sae_id);
                    continue;
                }
            }
            match qkd_manager.add_sae(sae_id, info.kme_id, &None).await {
                Ok(_) => info!("Zenoh registry discovery: registered SAE {} as belonging to KME {} (node '{}')", sae_id, info.kme_id, info.node_id),
                Err(e) => error!("Zenoh registry discovery: failed to register SAE {} for KME {}: {:?}", sae_id, info.kme_id, e),
            }
        }
    }

    async fn spawn_own_subscribers(&self, session: &zenoh::Session) -> Result<(), io::Error> {
        let node_id = self.config.node_id.as_str();
        macro_rules! spawn_logger {
            ($label:literal, $topic:expr) => {{
                let topic = $topic;
                let subscriber = session
                    .declare_subscriber(topic.as_str())
                    .await
                    .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;
                tokio::spawn(async move {
                    while let Ok(sample) = subscriber.recv_async().await {
                        match sample.payload().try_to_string() {
                            Ok(payload) => info!("Zenoh {} <- received on '{topic}': {payload}", $label),
                            Err(_) => info!("Zenoh {} <- received non-UTF8 payload on '{topic}': {:?}", $label, sample.payload().to_bytes()),
                        }
                    }
                    error!("Zenoh {} subscriber loop ended unexpectedly", $label);
                });
            }};
        }

        // Only logged here, not handled by `raft.rs`: this is the leader's reply to a
        // client proposal made from this node (see `raft::propose_transition`), not a
        // message the Raft protocol itself needs to react to.
        spawn_logger!("raft_transition_decision", ZenohTopicMap::raft_transition_decision_topic(node_id));

        Ok(())
    }

    /// Publish an envelope to the transport.
    pub async fn publish(&self, envelope: ZenohEnvelope) -> Result<(), io::Error> {
        let session_config = self.build_session_config()?;
        let session = zenoh::open(session_config)
            .await
            .map_err(|e| io_err(&format!("Cannot open Zenoh session: {e}")))?;
        session
            .put(envelope.topic.as_str(), envelope.payload_json.as_str())
            .await
            .map_err(|e| io_err(&format!("Cannot publish Zenoh message: {e}")))
    }

    /// Subscribe to a transport topic and keep the subscription alive.
    pub async fn subscribe(&self, topic: &str) -> Result<(), io::Error> {
        let session_config = self.build_session_config()?;
        let session = zenoh::open(session_config)
            .await
            .map_err(|e| io_err(&format!("Cannot open Zenoh session: {e}")))?;
        let subscriber = session
            .declare_subscriber(topic)
            .await
            .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

        while let Ok(sample) = subscriber.recv_async().await {
            match sample.payload().try_to_string() {
                Ok(payload) => info!("Zenoh <- received on '{topic}': {payload}"),
                Err(_) => info!("Zenoh <- received non-UTF8 payload on '{topic}': {:?}", sample.payload().to_bytes()),
            }
        }

        Err(io_err("Zenoh subscription ended unexpectedly"))
    }
}