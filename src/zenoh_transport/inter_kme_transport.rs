//! Real (non-demo) Zenoh-backed implementation of
//! [`crate::qkd_manager::inter_kme_transport::InterKmeTransport`], replacing the classical HTTPS
//! `/keys/activate` call with an actual push of the key material over Zenoh, once
//! `transport_mode: ZenohRaft` is configured (see [`ZenohInterKmeTransport::new`] and
//! [`crate::qkd_manager::QkdManager::set_inter_kme_transport`]).
//!
//! Unlike the classical HTTPS route (both KMEs there already share raw QKD key material out of
//! band, so it only ever sends key-ids), this transport publishes the real key bytes on the
//! ETSI-020 `ext_keys` plane ([`super::contract::ZenohEtsiExtKeysBatch`]): the slave KME stores
//! them directly on receipt instead of activating a pre-shared local pool entry.

use crate::io_err;
use crate::qkd_manager::inter_kme_transport::InterKmeTransport;
use crate::qkd_manager::{QkdManager, QkdManagerResponse};
use crate::{KmeId, SaeId};
use base64::{engine::general_purpose, Engine as _};
use log::{error, info};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::Duration;
use uuid::Uuid;

use super::config::ZenohTransportConfig;
use super::contract::{ZenohEtsiExtKeysAck, ZenohEtsiExtKeysBatch, ZenohEtsiExtKeysVoid, ZenohEtsiExtKeysVoidAck, ZenohEtsiKeyMaterial, ZenohTopicMap};
use super::registry::KmeNodeRegistry;

/// How long the initiator waits for the remote KME to ack a key-material sync request.
const SYNC_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the initiator waits for the remote KME to ack a void request.
const VOID_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Sends key material to other KMEs over Zenoh instead of classical HTTPS.
#[derive(Clone)]
pub struct ZenohInterKmeTransport {
    config: ZenohTransportConfig,
    session: zenoh::Session,
    /// Live `KmeId -> Zenoh node_id` registry, seeded from `config.other_kme_node_ids` and kept
    /// up to date at runtime as new KMEs are discovered over Zenoh (see
    /// `super::runtime::ZenohTransport::spawn_registry_discovery`), so a hot-plugged KME not
    /// present in `other_kmes[]` config can still be resolved and reached.
    kme_registry: KmeNodeRegistry,
}

impl ZenohInterKmeTransport {
    /// Create a new Zenoh-backed inter-KME transport on top of an already-open session.
    pub(crate) fn new(config: ZenohTransportConfig, session: zenoh::Session, kme_registry: KmeNodeRegistry) -> Self {
        Self { config, session, kme_registry }
    }
}

impl InterKmeTransport for ZenohInterKmeTransport {
    fn activate_key_on_remote_kme<'a>(
        &'a self,
        caller_master_sae_id: SaeId,
        other_kme_id: KmeId,
        other_sae_id: SaeId,
        keys: Vec<(String, Vec<u8>)>,
    ) -> Pin<Box<dyn Future<Output = Result<(), QkdManagerResponse>> + Send + 'a>> {
        Box::pin(async move {
            let Some(slave_node_id) = self.kme_registry.get(other_kme_id) else {
                error!("Zenoh inter-KME transport: no zenoh_node_id known for other KME '{other_kme_id}'; add it to its `other_kmes` entry, or wait for it to be discovered over Zenoh");
                return Err(QkdManagerResponse::RemoteKmeCommunicationError);
            };
            send_key_material_and_await_ack(
                &self.session,
                self.config.node_id.as_str(),
                slave_node_id.as_str(),
                caller_master_sae_id,
                other_sae_id,
                keys,
                SYNC_ACK_TIMEOUT,
            ).await.map_err(|e| {
                error!("Zenoh inter-KME transport: key sync request to '{}' failed: {e}", slave_node_id);
                QkdManagerResponse::RemoteKmeCommunicationError
            })
        })
    }

    fn void_keys_on_remote_kme<'a>(
        &'a self,
        other_kme_id: KmeId,
        key_uuids: Vec<String>,
    ) -> Pin<Box<dyn Future<Output = Result<(), QkdManagerResponse>> + Send + 'a>> {
        Box::pin(async move {
            let Some(slave_node_id) = self.kme_registry.get(other_kme_id) else {
                error!("Zenoh inter-KME transport: no zenoh_node_id known for other KME '{other_kme_id}'; add it to its `other_kmes` entry, or wait for it to be discovered over Zenoh");
                return Err(QkdManagerResponse::RemoteKmeCommunicationError);
            };
            send_void_request_and_await_ack(
                &self.session,
                self.config.node_id.as_str(),
                slave_node_id.as_str(),
                key_uuids,
                VOID_ACK_TIMEOUT,
            ).await.map_err(|e| {
                error!("Zenoh inter-KME transport: void request to '{}' failed: {e}", slave_node_id);
                QkdManagerResponse::RemoteKmeCommunicationError
            })
        })
    }
}

/// Master-side: publish the key material to `remote_node_id`'s `ext_keys` topic and block (up to
/// `timeout`) until it acks (accepted or rejected).
async fn send_key_material_and_await_ack(
    session: &zenoh::Session,
    own_node_id: &str,
    remote_node_id: &str,
    origin_sae_id: SaeId,
    target_sae_id: SaeId,
    keys: Vec<(String, Vec<u8>)>,
    timeout: Duration,
) -> Result<(), io::Error> {
    // Subscribe to our own ack topic *before* publishing the request, so a fast responder can
    // never ack before we start listening for it.
    let ack_topic = ZenohTopicMap::ext_keys_ack_topic(own_node_id);
    let subscriber = session
        .declare_subscriber(ack_topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    let request = ZenohEtsiExtKeysBatch {
        request_id: Uuid::new_v4().to_string(),
        master_kme: own_node_id.to_string(),
        slave_kme: remote_node_id.to_string(),
        origin_sae_id,
        target_sae_id,
        keys: keys.into_iter().map(|(key_id, key_bytes)| ZenohEtsiKeyMaterial {
            key_id,
            key_b64: general_purpose::STANDARD.encode(key_bytes),
        }).collect(),
    };
    let request_topic = ZenohTopicMap::ext_keys_topic(remote_node_id);
    info!(
        "Zenoh ext_keys client '{}' -> publishing {} key(s) to '{request_topic}' (request '{}')",
        own_node_id, request.keys.len(), request.request_id
    );
    publish_json(session, request_topic.as_str(), &request).await?;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(io_err(&format!("Timed out waiting for ext_keys ack for request '{}'", request.request_id)));
        }
        let sample = match tokio::time::timeout(remaining, subscriber.recv_async()).await {
            Ok(Ok(sample)) => sample,
            Ok(Err(_)) => return Err(io_err("Zenoh ext_keys ack subscriber closed unexpectedly")),
            Err(_) => return Err(io_err(&format!("Timed out waiting for ext_keys ack for request '{}'", request.request_id))),
        };
        match sample.payload().try_to_string() {
            Ok(payload) => match serde_json::from_str::<ZenohEtsiExtKeysAck>(&payload) {
                Ok(ack) if ack.request_id != request.request_id => continue,
                Ok(ack) if ack.accepted => {
                    info!("Zenoh ext_keys client '{}' <- request '{}' accepted by remote KME", own_node_id, ack.request_id);
                    return Ok(());
                }
                Ok(ack) => return Err(io_err(&format!("Remote KME rejected key sync: {}", ack.reason.unwrap_or_default()))),
                Err(e) => error!("Zenoh ext_keys client '{}' <- cannot parse ack on '{ack_topic}': {e}", own_node_id),
            },
            Err(_) => info!("Zenoh ext_keys client '{}' <- received non-UTF8 ack on '{ack_topic}'", own_node_id),
        }
    }
}

/// Slave-side: subscribe to this node's own `ext_keys` topic and, on every batch, store the
/// pushed key material directly through `qkd_manager` (Raft-gated - see
/// [`crate::qkd_manager::QkdManager::store_synced_keys_from_remote`]), then ack success or
/// failure back to the requester.
pub(super) async fn spawn_key_sync_responder(node_id: String, session: zenoh::Session, qkd_manager: QkdManager) -> Result<(), io::Error> {
    let topic = ZenohTopicMap::ext_keys_topic(node_id.as_str());
    let subscriber = session
        .declare_subscriber(topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    tokio::spawn(async move {
        while let Ok(sample) = subscriber.recv_async().await {
            match sample.payload().try_to_string() {
                Ok(payload) => match serde_json::from_str::<ZenohEtsiExtKeysBatch>(&payload) {
                    Ok(request) => {
                        info!(
                            "Zenoh ext_keys responder '{}': received {} key(s) from '{}' (request '{}')",
                            node_id, request.keys.len(), request.master_kme, request.request_id
                        );
                        let received_keys = request.keys.len();
                        let decoded_keys: Option<Vec<(String, Vec<u8>)>> = request.keys.iter()
                            .map(|k| general_purpose::STANDARD.decode(&k.key_b64).ok().map(|bytes| (k.key_id.clone(), bytes)))
                            .collect();
                        let result = match decoded_keys {
                            Some(keys) => qkd_manager.store_synced_keys_from_remote(request.origin_sae_id, request.target_sae_id, keys).await,
                            None => {
                                error!("Zenoh ext_keys responder '{}': malformed base64 key material in request '{}'", node_id, request.request_id);
                                Err(QkdManagerResponse::Ko)
                            }
                        };
                        let ack = ZenohEtsiExtKeysAck {
                            request_id: request.request_id.clone(),
                            received_keys,
                            accepted: result.is_ok(),
                            reason: result.err().map(|e| format!("{e:?}")),
                        };
                        let ack_topic = ZenohTopicMap::ext_keys_ack_topic(request.master_kme.as_str());
                        if let Err(e) = publish_json(&session, ack_topic.as_str(), &ack).await {
                            error!("Zenoh ext_keys responder '{}': failed to publish ack for '{}': {e}", node_id, request.request_id);
                        }
                    }
                    Err(e) => error!("Zenoh ext_keys responder '{}' <- cannot parse request on '{topic}': {e}", node_id),
                },
                Err(_) => info!("Zenoh ext_keys responder '{}' <- received non-UTF8 payload on '{topic}'", node_id),
            }
        }
        error!("Zenoh ext_keys responder '{}' subscriber loop ended unexpectedly", node_id);
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

/// Master-side: publish a void request to `remote_node_id` and block (up to `timeout`) until it
/// acks (accepted or rejected). Mirrors [`send_activate_request_and_await_ack`].
async fn send_void_request_and_await_ack(
    session: &zenoh::Session,
    own_node_id: &str,
    remote_node_id: &str,
    key_ids: Vec<String>,
    timeout: Duration,
) -> Result<(), io::Error> {
    // Subscribe to our own ack topic *before* publishing the request, so a fast responder can
    // never ack before we start listening for it.
    let ack_topic = ZenohTopicMap::ext_keys_void_ack_topic(own_node_id);
    let subscriber = session
        .declare_subscriber(ack_topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    let request = ZenohEtsiExtKeysVoid {
        request_id: Uuid::new_v4().to_string(),
        master_kme: own_node_id.to_string(),
        key_ids,
        reason: String::from("SAE requested key void"),
    };
    let request_topic = ZenohTopicMap::ext_keys_void_topic(remote_node_id);
    publish_json(session, request_topic.as_str(), &request).await?;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(io_err(&format!("Timed out waiting for void ack for request '{}'", request.request_id)));
        }
        let sample = match tokio::time::timeout(remaining, subscriber.recv_async()).await {
            Ok(Ok(sample)) => sample,
            Ok(Err(_)) => return Err(io_err("Zenoh void ack subscriber closed unexpectedly")),
            Err(_) => return Err(io_err(&format!("Timed out waiting for void ack for request '{}'", request.request_id))),
        };
        match sample.payload().try_to_string() {
            Ok(payload) => match serde_json::from_str::<ZenohEtsiExtKeysVoidAck>(&payload) {
                Ok(ack) if ack.request_id != request.request_id => continue,
                Ok(ack) if ack.accepted => {
                    info!("Zenoh void client '{}' <- request '{}' accepted by remote KME", own_node_id, ack.request_id);
                    return Ok(());
                }
                Ok(ack) => return Err(io_err(&format!("Remote KME rejected void request: {}", ack.reason.unwrap_or_default()))),
                Err(e) => error!("Zenoh void client '{}' <- cannot parse ack on '{ack_topic}': {e}", own_node_id),
            },
            Err(_) => info!("Zenoh void client '{}' <- received non-UTF8 ack on '{ack_topic}'", own_node_id),
        }
    }
}

/// Slave-side: subscribe to this node's own void topic and, on every request, actually void the
/// keys through `qkd_manager` (the same call the classical `/keys/void` HTTPS route makes), then
/// ack success or failure back to the requester. Mirrors [`spawn_key_sync_responder`].
pub(super) async fn spawn_void_key_responder(node_id: String, session: zenoh::Session, qkd_manager: QkdManager) -> Result<(), io::Error> {
    let topic = ZenohTopicMap::ext_keys_void_topic(node_id.as_str());
    let subscriber = session
        .declare_subscriber(topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    tokio::spawn(async move {
        while let Ok(sample) = subscriber.recv_async().await {
            match sample.payload().try_to_string() {
                Ok(payload) => match serde_json::from_str::<ZenohEtsiExtKeysVoid>(&payload) {
                    Ok(request) => {
                        info!(
                            "Zenoh void responder '{}': received void request for {} key(s) from '{}' (request '{}')",
                            node_id, request.key_ids.len(), request.master_kme, request.request_id
                        );
                        let result = qkd_manager.void_keys_from_remote(request.key_ids.clone()).await;
                        let ack = ZenohEtsiExtKeysVoidAck {
                            request_id: request.request_id.clone(),
                            accepted: result.is_ok(),
                            reason: result.err().map(|e| format!("{e:?}")),
                        };
                        let ack_topic = ZenohTopicMap::ext_keys_void_ack_topic(request.master_kme.as_str());
                        if let Err(e) = publish_json(&session, ack_topic.as_str(), &ack).await {
                            error!("Zenoh void responder '{}': failed to publish ack for '{}': {e}", node_id, request.request_id);
                        }
                    }
                    Err(e) => error!("Zenoh void responder '{}' <- cannot parse request on '{topic}': {e}", node_id),
                },
                Err(_) => info!("Zenoh void responder '{}' <- received non-UTF8 payload on '{topic}'", node_id),
            }
        }
        error!("Zenoh void responder '{}' subscriber loop ended unexpectedly", node_id);
    });

    Ok(())
}
