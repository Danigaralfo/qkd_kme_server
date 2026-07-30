//! This module is a validation aid that exercises the ETSI-020 plane of the
//! contract (`contract.rs`) end-to-end over a real Zenoh session, and drives
//! the real Raft-lite consensus in `raft.rs` through a full, realistic key
//! lifecycle:
//! 1. The initiator node generates a key locally (state `Generated`).
//! 2. It asks the Raft cluster for permission to start syncing it
//!    ([`raft::propose_transition_and_await_decision`], `Generated -> Syncing`).
//! 3. Once committed, it hands the key material to the remote node over the
//!    ETSI-020 plane (`ext_keys` topic) and waits for that node's ack.
//! 4. It asks the cluster for permission to mark the key in use
//!    (`Syncing -> InUse`).
//! 5. It "uses" the key (a no-op here), then asks the cluster for permission
//!    to mark it deleted/used (`InUse -> DeletedOrUsed`) and tells the remote
//!    node to void its copy (`ext_keys_void` topic).
//!
//! All Raft message exchange and state-transition validation is delegated to
//! `raft.rs` (via `propose_transition_and_await_decision`); this module only
//! owns the ETSI-020 send/ack/void round-trip and the sequencing of the demo
//! itself, since no other module drives that plane automatically yet.
//!
//! None of this is final business logic: real topic wiring must be driven
//! automatically by `QkdManager` (ETSI-020 requests), not by this hardcoded
//! probe. Keeping it in its own module (separate from `runtime.rs`, which
//! only bootstraps the real Zenoh node) means it can be discarded on its own
//! once that real wiring exists.

use crate::io_err;
use log::{error, info};
use std::io;
use std::time::Duration;
use uuid::Uuid;

use super::config::{ZenohProbeRole, ZenohTransportConfig};
use super::contract::{
    ZenohEtsiExtKeysAck, ZenohEtsiExtKeysBatch, ZenohEtsiExtKeysVoid, ZenohEtsiKeyMaterial,
    ZenohKeyState, ZenohRaftMessageKind, ZenohTopicMap,
};
use super::raft;

/// How often every node announces its own presence on its own Raft presence topic.
const PRESENCE_INTERVAL: Duration = Duration::from_secs(5);

/// How often the initiator runs a full key lifecycle demo pass, end to end.
///
/// This must comfortably exceed [`RAFT_DECISION_TIMEOUT`] and
/// [`ETSI_ACK_TIMEOUT`] combined (the demo makes three Raft round-trips and
/// one ETSI-020 round-trip per pass) so passes never overlap.
const LIFECYCLE_LOOP_INTERVAL: Duration = Duration::from_secs(30);

/// How long the demo waits for the Raft cluster to decide on a proposed transition.
const RAFT_DECISION_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the demo waits for the remote node to ack a published key batch.
const ETSI_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Start the probe behavior on top of an already-initialized Zenoh session.
///
/// Every node, regardless of role, subscribes to its own `ext_keys` and
/// `ext_keys_void` topics so it can act as the "slave" side of the ETSI-020
/// exchange for whichever node addresses it. If configured as `probe_role:
/// initiator` with a `probe_remote_node_id`, this node additionally runs the
/// full key lifecycle demo on a fixed interval toward the remote node. If
/// configured as `probe_role: responder` with a `probe_remote_node_id`, it
/// actively queries the remote (master) node's version topic once, since
/// `/kmapi/version` is never published to.
pub(super) async fn spawn(config: &ZenohTransportConfig, session: &zenoh::Session) -> Result<(), io::Error> {
    spawn_presence_publisher(config.node_id.clone(), session.clone());
    spawn_ext_keys_responder(config.node_id.clone(), session.clone()).await?;
    spawn_ext_keys_void_responder(config.node_id.clone(), session.clone()).await?;

    match (&config.probe_role, &config.probe_remote_node_id) {
        (ZenohProbeRole::Initiator, Some(remote_node_id)) => {
            info!(
                "Zenoh contract probe: node '{}' acting as initiator of the key lifecycle demo toward '{}'",
                config.node_id, remote_node_id
            );
            spawn_key_lifecycle_loop(config.clone(), session.clone(), remote_node_id.clone());
        }
        (ZenohProbeRole::Initiator, None) => {
            error!(
                "Zenoh contract probe: node '{}' is configured as initiator but has no probe_remote_node_id; staying passive",
                config.node_id
            );
        }
        (ZenohProbeRole::Responder, Some(remote_node_id)) => {
            info!(
                "Zenoh contract probe: node '{}' acting as responder, querying version from master '{}'",
                config.node_id, remote_node_id
            );
            query_remote_version(session, remote_node_id.as_str()).await?;
        }
        (ZenohProbeRole::Responder, None) => {
            info!(
                "Zenoh contract probe: node '{}' acting as responder, only serving/subscribing to its own topics",
                config.node_id
            );
        }
    }

    Ok(())
}

/// Spawn a background task that periodically announces this node's own
/// presence on its own Raft presence topic. Each node announces itself on
/// its own topic (as opposed to publishing onto a remote node's topic),
/// since presence is inherently something a node reports about itself.
fn spawn_presence_publisher(node_id: String, session: zenoh::Session) {
    let topic = ZenohTopicMap::raft_presence_topic(node_id.as_str());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PRESENCE_INTERVAL);
        loop {
            interval.tick().await;
            let payload = serde_json::json!({
                "kind": ZenohRaftMessageKind::Presence,
                "node_id": node_id,
                "plane": "raft",
            });
            if let Err(e) = publish_json(&session, topic.as_str(), &payload, "Zenoh raft presence").await {
                error!("Zenoh presence publisher '{}': failed to publish presence: {e}", node_id);
            }
        }
    });
}

/// Actively query a remote (master) node's `/kmapi/version` topic and log the reply.
async fn query_remote_version(session: &zenoh::Session, remote_node_id: &str) -> Result<(), io::Error> {
    let topic = ZenohTopicMap::version_query_topic(remote_node_id);
    info!("Zenoh version query -> querying '{topic}'");
    let replies = session
        .get(topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot query Zenoh version topic '{topic}': {e}")))?;

    while let Ok(reply) = replies.recv_async().await {
        match reply.result() {
            Ok(sample) => match sample.payload().try_to_string() {
                Ok(payload) => info!("Zenoh version query <- reply from '{topic}': {payload}"),
                Err(_) => info!("Zenoh version query <- non-UTF8 reply from '{topic}': {:?}", sample.payload().to_bytes()),
            },
            Err(e) => error!("Zenoh version query <- error reply from '{topic}': {e}"),
        }
    }

    Ok(())
}

/// Spawn a background task that repeatedly runs a full key lifecycle demo
/// pass toward `remote_node_id`, using a freshly generated key-id each time
/// (a key-id cannot be reused once it reaches the terminal `DeletedOrUsed`
/// state).
fn spawn_key_lifecycle_loop(config: ZenohTransportConfig, session: zenoh::Session, remote_node_id: String) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(LIFECYCLE_LOOP_INTERVAL);
        loop {
            interval.tick().await;
            if let Err(e) = run_key_lifecycle_demo(&config, &session, remote_node_id.as_str()).await {
                error!("Zenoh key lifecycle demo: node '{}' pass failed: {e}", config.node_id);
            }
        }
    });
}

/// Run one full pass of the Raft-gated ETSI-020 key lifecycle demo described
/// in this module's doc comment. All Raft consensus is delegated to
/// [`raft::propose_transition_and_await_decision`]; this function only owns
/// the ETSI-020 send/ack/void round-trip and the sequencing between steps.
async fn run_key_lifecycle_demo(config: &ZenohTransportConfig, session: &zenoh::Session, remote_node_id: &str) -> Result<(), io::Error> {
    let key_id = Uuid::new_v4().to_string();
    info!("Zenoh key lifecycle demo: node '{}' generated key '{}' (state Generated)", config.node_id, key_id);

    // Generated -> Syncing: ask the cluster for permission to start the exchange.
    let decision = raft::propose_transition_and_await_decision(
        config,
        session,
        key_id.as_str(),
        remote_node_id,
        ZenohKeyState::Generated,
        ZenohKeyState::Syncing,
        RAFT_DECISION_TIMEOUT,
    )
    .await?;
    if !decision.accepted {
        error!(
            "Zenoh key lifecycle demo: cluster rejected Generated -> Syncing for key '{}': {:?}",
            key_id, decision.reason
        );
        return Ok(());
    }
    info!("Zenoh key lifecycle demo: cluster committed key '{}' to Syncing", key_id);

    // Hand the key material to the remote node over the ETSI-020 plane and wait for its ack.
    send_ext_keys_and_await_ack(session, config.node_id.as_str(), remote_node_id, key_id.as_str(), ETSI_ACK_TIMEOUT).await?;
    info!("Zenoh key lifecycle demo: '{}' acknowledged receipt of key '{}'", remote_node_id, key_id);

    // Syncing -> InUse: ask the cluster for permission to start using the key.
    let decision = raft::propose_transition_and_await_decision(
        config,
        session,
        key_id.as_str(),
        remote_node_id,
        ZenohKeyState::Syncing,
        ZenohKeyState::InUse,
        RAFT_DECISION_TIMEOUT,
    )
    .await?;
    if !decision.accepted {
        error!(
            "Zenoh key lifecycle demo: cluster rejected Syncing -> InUse for key '{}': {:?}",
            key_id, decision.reason
        );
        return Ok(());
    }
    info!("Zenoh key lifecycle demo: cluster committed key '{}' to InUse; key would be used here", key_id);

    // InUse -> DeletedOrUsed: ask the cluster for permission to retire the key, then tell the
    // remote node to void its copy.
    let decision = raft::propose_transition_and_await_decision(
        config,
        session,
        key_id.as_str(),
        remote_node_id,
        ZenohKeyState::InUse,
        ZenohKeyState::DeletedOrUsed,
        RAFT_DECISION_TIMEOUT,
    )
    .await?;
    if !decision.accepted {
        error!(
            "Zenoh key lifecycle demo: cluster rejected InUse -> DeletedOrUsed for key '{}': {:?}",
            key_id, decision.reason
        );
        return Ok(());
    }
    let void = ZenohEtsiExtKeysVoid {
        request_id: Uuid::new_v4().to_string(),
        key_ids: vec![key_id.clone()],
        reason: String::from("key used, lifecycle demo complete"),
    };
    let void_topic = ZenohTopicMap::ext_keys_void_topic(remote_node_id);
    publish_json(session, void_topic.as_str(), &void, "Zenoh ext_keys void").await?;
    info!("Zenoh key lifecycle demo: key '{}' lifecycle complete (DeletedOrUsed)", key_id);

    Ok(())
}

/// Publish an ETSI-020 key batch carrying `key_id` to `remote_node_id` and
/// block (up to `timeout`) until that node acknowledges it.
async fn send_ext_keys_and_await_ack(
    session: &zenoh::Session,
    own_node_id: &str,
    remote_node_id: &str,
    key_id: &str,
    timeout: Duration,
) -> Result<(), io::Error> {
    // Subscribe to our own ack topic *before* publishing the batch, so a fast
    // responder can never ack before we start listening for it.
    let ack_topic = ZenohTopicMap::ext_keys_ack_topic(own_node_id);
    let subscriber = session
        .declare_subscriber(ack_topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    let batch = ZenohEtsiExtKeysBatch {
        request_id: Uuid::new_v4().to_string(),
        master_kme: own_node_id.to_string(),
        slave_kme: remote_node_id.to_string(),
        keys: vec![ZenohEtsiKeyMaterial {
            key_id: key_id.to_string(),
            key_b64: String::from("ZHVtbXkta2V5LW1hdGVyaWFs"),
        }],
    };
    let batch_topic = ZenohTopicMap::ext_keys_topic(remote_node_id);
    publish_json(session, batch_topic.as_str(), &batch, "Zenoh ext_keys batch").await?;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(io_err(&format!("Timed out waiting for ext_keys ack for request '{}'", batch.request_id)));
        }
        let sample = match tokio::time::timeout(remaining, subscriber.recv_async()).await {
            Ok(Ok(sample)) => sample,
            Ok(Err(_)) => return Err(io_err("Zenoh ext_keys ack subscriber closed unexpectedly")),
            Err(_) => return Err(io_err(&format!("Timed out waiting for ext_keys ack for request '{}'", batch.request_id))),
        };
        match sample.payload().try_to_string() {
            Ok(payload) => match serde_json::from_str::<ZenohEtsiExtKeysAck>(&payload) {
                Ok(ack) if ack.request_id == batch.request_id => return Ok(()),
                Ok(_unrelated_ack) => continue,
                Err(e) => error!("Zenoh ext_keys client '{}' <- cannot parse ack on '{ack_topic}': {e}", own_node_id),
            },
            Err(_) => info!("Zenoh ext_keys client '{}' <- received non-UTF8 ack on '{ack_topic}'", own_node_id),
        }
    }
}

/// Slave-side: subscribe to this node's own `ext_keys` topic and, on every
/// received batch, log receipt of the key material and ack it back to the
/// batch's `master_kme`.
async fn spawn_ext_keys_responder(node_id: String, session: zenoh::Session) -> Result<(), io::Error> {
    let topic = ZenohTopicMap::ext_keys_topic(node_id.as_str());
    let subscriber = session
        .declare_subscriber(topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    tokio::spawn(async move {
        while let Ok(sample) = subscriber.recv_async().await {
            match sample.payload().try_to_string() {
                Ok(payload) => match serde_json::from_str::<ZenohEtsiExtKeysBatch>(&payload) {
                    Ok(batch) => {
                        info!(
                            "Zenoh ext_keys responder '{}': received {} key(s) from '{}' (request '{}')",
                            node_id,
                            batch.keys.len(),
                            batch.master_kme,
                            batch.request_id
                        );
                        let ack = ZenohEtsiExtKeysAck {
                            request_id: batch.request_id.clone(),
                            received_keys: batch.keys.len(),
                        };
                        let ack_topic = ZenohTopicMap::ext_keys_ack_topic(batch.master_kme.as_str());
                        if let Err(e) = publish_json(&session, ack_topic.as_str(), &ack, "Zenoh ext_keys ack").await {
                            error!("Zenoh ext_keys responder '{}': failed to publish ack for '{}': {e}", node_id, batch.request_id);
                        }
                    }
                    Err(e) => error!("Zenoh ext_keys responder '{}' <- cannot parse batch on '{topic}': {e}", node_id),
                },
                Err(_) => info!("Zenoh ext_keys responder '{}' <- received non-UTF8 payload on '{topic}'", node_id),
            }
        }
        error!("Zenoh ext_keys responder '{}' subscriber loop ended unexpectedly", node_id);
    });

    Ok(())
}

/// Slave-side: subscribe to this node's own `ext_keys_void` topic and log
/// (simulating local deletion of) every key-id the master asks to void.
async fn spawn_ext_keys_void_responder(node_id: String, session: zenoh::Session) -> Result<(), io::Error> {
    let topic = ZenohTopicMap::ext_keys_void_topic(node_id.as_str());
    let subscriber = session
        .declare_subscriber(topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    tokio::spawn(async move {
        while let Ok(sample) = subscriber.recv_async().await {
            match sample.payload().try_to_string() {
                Ok(payload) => match serde_json::from_str::<ZenohEtsiExtKeysVoid>(&payload) {
                    Ok(void) => info!(
                        "Zenoh ext_keys_void responder '{}': voiding key(s) {:?} (reason: {})",
                        node_id, void.key_ids, void.reason
                    ),
                    Err(e) => error!("Zenoh ext_keys_void responder '{}' <- cannot parse void on '{topic}': {e}", node_id),
                },
                Err(_) => info!("Zenoh ext_keys_void responder '{}' <- received non-UTF8 payload on '{topic}'", node_id),
            }
        }
        error!("Zenoh ext_keys_void responder '{}' subscriber loop ended unexpectedly", node_id);
    });

    Ok(())
}

async fn publish_json<T>(session: &zenoh::Session, topic: &str, payload: &T, label: &str) -> Result<(), io::Error>
where
    T: serde::Serialize,
{
    let payload_json = serde_json::to_string(payload)
        .map_err(|e| io_err(&format!("Cannot serialize {label}: {e}")))?;
    info!("Zenoh {label} -> publishing on '{topic}': {payload_json}");
    session
        .put(topic, payload_json.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot publish {label}: {e}")))
}
