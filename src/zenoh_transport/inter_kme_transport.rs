//! Real (non-demo) Zenoh-backed implementation of
//! [`crate::qkd_manager::inter_kme_transport::InterKmeTransport`], replacing the classical HTTPS
//! `/keys/activate` call with the same operation carried over Zenoh, once `transport_mode:
//! ZenohRaft` is configured (see [`ZenohInterKmeTransport::new`] and
//! [`crate::qkd_manager::QkdManager::set_inter_kme_transport`]).
//!
//! Unlike the `ext_keys` contract plane (see `contract.rs`), this carries no key material: both
//! KMEs already share raw QKD key material out of band, so [`super::contract::ZenohActivateKeyRequest`] only
//! carries the same metadata the classical route does.

use crate::io_err;
use crate::qkd_manager::inter_kme_transport::InterKmeTransport;
use crate::qkd_manager::{QkdManager, QkdManagerResponse};
use crate::{KmeId, SaeId};
use log::{error, info};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::Duration;
use uuid::Uuid;

use super::config::ZenohTransportConfig;
use super::contract::{ZenohActivateKeyAck, ZenohActivateKeyRequest, ZenohTopicMap};

/// How long the initiator waits for the remote KME to ack an activation request.
const ACTIVATE_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Sends key activation requests to other KMEs over Zenoh instead of classical HTTPS.
#[derive(Clone)]
pub struct ZenohInterKmeTransport {
    config: ZenohTransportConfig,
    session: zenoh::Session,
}

impl ZenohInterKmeTransport {
    /// Create a new Zenoh-backed inter-KME transport on top of an already-open session.
    pub fn new(config: ZenohTransportConfig, session: zenoh::Session) -> Self {
        Self { config, session }
    }
}

impl InterKmeTransport for ZenohInterKmeTransport {
    fn activate_key_on_remote_kme<'a>(
        &'a self,
        caller_master_sae_id: SaeId,
        other_kme_id: KmeId,
        other_sae_id: SaeId,
        key_uuids: Vec<String>,
    ) -> Pin<Box<dyn Future<Output = Result<(), QkdManagerResponse>> + Send + 'a>> {
        Box::pin(async move {
            let Some(slave_node_id) = self.config.other_kme_node_ids.get(&other_kme_id) else {
                error!("Zenoh inter-KME transport: no zenoh_node_id configured for other KME '{other_kme_id}'; add it to its `other_kmes` entry");
                return Err(QkdManagerResponse::RemoteKmeCommunicationError);
            };
            send_activate_request_and_await_ack(
                &self.session,
                self.config.node_id.as_str(),
                slave_node_id.as_str(),
                caller_master_sae_id,
                other_sae_id,
                key_uuids,
                ACTIVATE_ACK_TIMEOUT,
            ).await.map_err(|e| {
                error!("Zenoh inter-KME transport: activation request to '{}' failed: {e}", slave_node_id);
                QkdManagerResponse::RemoteKmeCommunicationError
            })
        })
    }
}

/// Master-side: publish an activation request to `remote_node_id` and block (up to `timeout`)
/// until it acks (accepted or rejected).
async fn send_activate_request_and_await_ack(
    session: &zenoh::Session,
    own_node_id: &str,
    remote_node_id: &str,
    origin_sae_id: SaeId,
    target_sae_id: SaeId,
    key_ids: Vec<String>,
    timeout: Duration,
) -> Result<(), io::Error> {
    // Subscribe to our own ack topic *before* publishing the request, so a fast responder can
    // never ack before we start listening for it.
    let ack_topic = ZenohTopicMap::activate_key_ack_topic(own_node_id);
    let subscriber = session
        .declare_subscriber(ack_topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    let request = ZenohActivateKeyRequest {
        request_id: Uuid::new_v4().to_string(),
        master_kme: own_node_id.to_string(),
        slave_kme: remote_node_id.to_string(),
        origin_sae_id,
        target_sae_id,
        key_ids,
    };
    let request_topic = ZenohTopicMap::activate_key_topic(remote_node_id);
    publish_json(session, request_topic.as_str(), &request).await?;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(io_err(&format!("Timed out waiting for activate ack for request '{}'", request.request_id)));
        }
        let sample = match tokio::time::timeout(remaining, subscriber.recv_async()).await {
            Ok(Ok(sample)) => sample,
            Ok(Err(_)) => return Err(io_err("Zenoh activate ack subscriber closed unexpectedly")),
            Err(_) => return Err(io_err(&format!("Timed out waiting for activate ack for request '{}'", request.request_id))),
        };
        match sample.payload().try_to_string() {
            Ok(payload) => match serde_json::from_str::<ZenohActivateKeyAck>(&payload) {
                Ok(ack) if ack.request_id != request.request_id => continue,
                Ok(ack) if ack.accepted => return Ok(()),
                Ok(ack) => return Err(io_err(&format!("Remote KME rejected activation: {}", ack.reason.unwrap_or_default()))),
                Err(e) => error!("Zenoh activate client '{}' <- cannot parse ack on '{ack_topic}': {e}", own_node_id),
            },
            Err(_) => info!("Zenoh activate client '{}' <- received non-UTF8 ack on '{ack_topic}'", own_node_id),
        }
    }
}

/// Slave-side: subscribe to this node's own activate-key topic and, on every request, actually
/// activate the keys through `qkd_manager` (the same call the classical `/keys/activate` HTTPS
/// route makes), then ack success or failure back to the requester.
pub(super) async fn spawn_activate_key_responder(node_id: String, session: zenoh::Session, qkd_manager: QkdManager) -> Result<(), io::Error> {
    let topic = ZenohTopicMap::activate_key_topic(node_id.as_str());
    let subscriber = session
        .declare_subscriber(topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    tokio::spawn(async move {
        while let Ok(sample) = subscriber.recv_async().await {
            match sample.payload().try_to_string() {
                Ok(payload) => match serde_json::from_str::<ZenohActivateKeyRequest>(&payload) {
                    Ok(request) => {
                        info!(
                            "Zenoh activate responder '{}': received activation request for {} key(s) from '{}' (request '{}')",
                            node_id, request.key_ids.len(), request.master_kme, request.request_id
                        );
                        let result = qkd_manager.activate_key_from_remote(request.origin_sae_id, request.target_sae_id, request.key_ids.clone()).await;
                        let ack = ZenohActivateKeyAck {
                            request_id: request.request_id.clone(),
                            accepted: result.is_ok(),
                            reason: result.err().map(|e| format!("{e:?}")),
                        };
                        let ack_topic = ZenohTopicMap::activate_key_ack_topic(request.master_kme.as_str());
                        if let Err(e) = publish_json(&session, ack_topic.as_str(), &ack).await {
                            error!("Zenoh activate responder '{}': failed to publish ack for '{}': {e}", node_id, request.request_id);
                        }
                    }
                    Err(e) => error!("Zenoh activate responder '{}' <- cannot parse request on '{topic}': {e}", node_id),
                },
                Err(_) => info!("Zenoh activate responder '{}' <- received non-UTF8 payload on '{topic}'", node_id),
            }
        }
        error!("Zenoh activate responder '{}' subscriber loop ended unexpectedly", node_id);
    });

    Ok(())
}

async fn publish_json<T: serde::Serialize>(session: &zenoh::Session, topic: &str, payload: &T) -> Result<(), io::Error> {
    let payload_json = serde_json::to_string(payload).map_err(|e| io_err(&format!("Cannot serialize payload: {e}")))?;
    session
        .put(topic, payload_json.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot publish payload: {e}")))
}
