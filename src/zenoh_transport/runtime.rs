//! Runtime for the Zenoh transport layer.
//!
//! This module only covers real node bootstrap: opening the Zenoh session,
//! serving this node's own version over the Storage/Query pattern, and
//! subscribing to this node's own contract topics. The real Raft-lite
//! consensus for key-state transitions (Phase 4) lives in `raft.rs`, so it
//! can evolve independently of this bootstrap code.

use crate::io_err;
use crate::qkd_manager::QkdManager;
use log::{error, info};
use std::io;
use std::sync::Arc;
use uuid::Uuid;

use super::contract::{ZenohEtsiVersionResponse, ZenohTopicMap, ZENOH_CONTRACT_VERSION};
use super::inter_kme_transport::{self, ZenohInterKmeTransport};
use super::messages::ZenohEnvelope;
use super::raft;
use super::config::ZenohTransportConfig;

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

        let config_json = format!(
            r#"{{
  mode: {mode_json},
  connect: {{ endpoints: {connect_endpoints_json} }},
  listen: {{ endpoints: {listen_endpoints_json} }},
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
        let key_states = raft::spawn(&self.config, &session).await?;

        // Real (non-demo) inter-KME wiring: service incoming activation requests, and make
        // outgoing ones (from qkd_manager's business logic) go out over Zenoh instead of
        // classical HTTPS.
        inter_kme_transport::spawn_activate_key_responder(self.config.node_id.clone(), session.clone(), qkd_manager.clone()).await?;
        qkd_manager.set_inter_kme_transport(Arc::new(ZenohInterKmeTransport::new(self.config.clone(), session.clone()))).await;
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