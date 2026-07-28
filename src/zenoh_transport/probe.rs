//! This module is entirely a validation aid: it exercises the
//! contract (`contract.rs`) end-to-end over a real Zenoh session so it can be
//! checked that message shapes and topics work as designed, and it reflects a
//! received state transition into a local placeholder value to validate the
//! event flow (initial state -> event emitted -> event recieved -> new state comitted).
//!
//! None of this is final business logic: real topic wiring must be driven
//! automatically by `QkdManager` (ETSI-020 requests) and, eventually, Raft
//! cluster membership, not by this hardcoded probe. Keeping it in its own
//! module (separate from `runtime.rs`, which only bootstraps the real Zenoh node)

use crate::io_err;
use log::{error, info};
use std::io;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use super::config::{ZenohProbeRole, ZenohTransportConfig};
use super::contract::{
    ZenohEtsiExtKeysAck, ZenohEtsiExtKeysBatch, ZenohEtsiExtKeysVoid, ZenohEtsiKeyMaterial,
    ZenohKeyState, ZenohRaftMessageKind, ZenohRaftStateUpdate, ZenohRaftTransitionDecision,
    ZenohRaftTransitionRequest, ZenohTopicMap,
};

/// Placeholder key-id used to simulate a single local key's state for the
/// event-flow validation. This will be replaced by real key-ids
/// coming from `QkdManager`'s key storage once this transport is wired to it.
const PLACEHOLDER_KEY_ID: &str = "2c0ac81f-1a2f-49a2-b881-f18a6d620b65";

/// Contract topics owned by a single node hostname, used to know where to
/// publish sample messages during the probe.
///
/// This grouping only exists to support the probe below: it is not the final
/// routing model, where topics will be resolved per-request from
/// `other_kmes` and Raft cluster membership instead of being enumerated
/// upfront for a single peer.
#[derive(Clone)]
struct ContractTopics {
    version: String,
    ext_keys: String,
    ext_keys_ack: String,
    ext_keys_void: String,
    raft_presence: String,
    raft_transition_request: String,
    raft_transition_decision: String,
    raft_state_update: String,
}

impl ContractTopics {
    fn for_node(node_id: &str) -> Self {
        Self {
            version: ZenohTopicMap::version_query_topic(node_id),
            ext_keys: ZenohTopicMap::ext_keys_topic(node_id),
            ext_keys_ack: ZenohTopicMap::ext_keys_ack_topic(node_id),
            ext_keys_void: ZenohTopicMap::ext_keys_void_topic(node_id),
            raft_presence: ZenohTopicMap::raft_presence_topic(node_id),
            raft_transition_request: ZenohTopicMap::raft_transition_request_topic(node_id),
            raft_transition_decision: ZenohTopicMap::raft_transition_decision_topic(node_id),
            raft_state_update: ZenohTopicMap::raft_state_update_topic(node_id),
        }
    }
}

/// Start the probe behavior on top of an already-initialized Zenoh session.
///
/// This always subscribes to this node's own `raft_state_update` topic to
/// reflect any received transition into a local placeholder key state. If
/// configured as `probe_role: initiator` with a `probe_remote_node_id`, it
/// additionally publishes one sample message per Pub/Sub contract topic on a
/// fixed interval toward the remote node's topics. If configured as
/// `probe_role: responder` with a `probe_remote_node_id`, it actively queries
/// the remote (master) node's version topic instead of waiting for a
/// publication, since `/kmapi/version` is never published to.
pub(super) async fn spawn(config: &ZenohTransportConfig, session: &zenoh::Session) -> Result<(), io::Error> {
    let local_key_state = Arc::new(Mutex::new(ZenohKeyState::Generated));
    spawn_raft_state_update_subscriber(config.node_id.clone(), session, local_key_state.clone()).await?;

    match (&config.probe_role, &config.probe_remote_node_id) {
        (ZenohProbeRole::Initiator, Some(remote_node_id)) => {
            info!(
                "Zenoh contract probe: node '{}' acting as initiator toward '{}'",
                config.node_id, remote_node_id
            );
            let remote_topics = ContractTopics::for_node(remote_node_id.as_str());
            spawn_periodic_probe_publisher(config.node_id.clone(), session.clone(), remote_topics, local_key_state);
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
            let remote_topics = ContractTopics::for_node(remote_node_id.as_str());
            query_remote_version(session, &remote_topics).await?;
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

/// Actively query a remote (master) node's `/kmapi/version` topic and log the reply.
async fn query_remote_version(session: &zenoh::Session, remote_topics: &ContractTopics) -> Result<(), io::Error> {
    let topic = remote_topics.version.as_str();
    info!("Zenoh version query -> querying '{topic}'");
    let replies = session
        .get(topic)
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

/// Subscribe to this node's own `raft_state_update` topic and reflect any
/// received transition into the local placeholder key state.
///
/// This validates event flow (event received -> new state comitted) 
/// with a single in-memory placeholder value: it is
/// not the final state store, which will read/write `QkdManager`'s real
/// key storage once this transport is wired to it.
async fn spawn_raft_state_update_subscriber(
    node_id: String,
    session: &zenoh::Session,
    local_key_state: Arc<Mutex<ZenohKeyState>>,
) -> Result<(), io::Error> {
    let topic = ZenohTopicMap::raft_state_update_topic(node_id.as_str());
    let subscriber = session
        .declare_subscriber(topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    tokio::spawn(async move {
        while let Ok(sample) = subscriber.recv_async().await {
            match sample.payload().try_to_string() {
                Ok(payload) => match serde_json::from_str::<ZenohRaftStateUpdate>(&payload) {
                    Ok(update) => {
                        let previous_state = {
                            let mut state = local_key_state.lock().unwrap();
                            let previous = *state;
                            *state = update.state;
                            previous
                        };
                        info!(
                            "Zenoh raft_state_update '{}' <- received on '{topic}' for key '{}': {:?} -> {:?} (committed: {})",
                            node_id, update.key_id, previous_state, update.state, update.committed
                        );
                    }
                    Err(e) => error!(
                        "Zenoh raft_state_update '{}' <- cannot parse payload on '{topic}': {e}",
                        node_id
                    ),
                },
                Err(_) => info!(
                    "Zenoh raft_state_update '{}' <- received non-UTF8 payload on '{topic}': {:?}",
                    node_id,
                    sample.payload().to_bytes()
                ),
            }
        }
        error!("Zenoh raft_state_update '{}' subscriber loop ended unexpectedly", node_id);
    });

    Ok(())
}

/// Spawn a background task that republishes the Pub/Sub probe messages on
/// a fixed interval toward `remote_topics`.
///
/// A single one-shot publish can race with Zenoh's peer/subscriber
/// discovery (the remote node may not have declared its subscribers yet
/// when the first sample is sent), so nothing would ever be observed on
/// the receiving side. Repeating the publish keeps the Pub/Sub topics
/// continuously visible in the logs on both nodes for as long as the
/// probe runs.
fn spawn_periodic_probe_publisher(
    node_id: String,
    session: zenoh::Session,
    remote_topics: ContractTopics,
    local_key_state: Arc<Mutex<ZenohKeyState>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            if let Err(e) = publish_probe_messages(node_id.as_str(), &session, &remote_topics, &local_key_state).await {
                error!("Zenoh contract probe: failed to publish probe messages: {e}");
            }
        }
    });
}

async fn publish_probe_messages(
    node_id: &str,
    session: &zenoh::Session,
    remote_topics: &ContractTopics,
    local_key_state: &Arc<Mutex<ZenohKeyState>>,
) -> Result<(), io::Error> {
    let ext_keys_batch = ZenohEtsiExtKeysBatch {
        request_id: Uuid::new_v4().to_string(),
        master_kme: node_id.to_string(),
        slave_kme: node_id.to_string(),
        keys: vec![ZenohEtsiKeyMaterial {
            key_id: Uuid::new_v4().to_string(),
            key_b64: String::from("ZHVtbXkta2V5LW1hdGVyaWFs"),
        }],
    };
    publish_json(session, remote_topics.ext_keys.as_str(), &ext_keys_batch, "Zenoh ext_keys batch").await?;

    let ext_keys_ack = ZenohEtsiExtKeysAck {
        request_id: ext_keys_batch.request_id.clone(),
        received_keys: ext_keys_batch.keys.len(),
    };
    publish_json(session, remote_topics.ext_keys_ack.as_str(), &ext_keys_ack, "Zenoh ext_keys ack").await?;

    let ext_keys_void = ZenohEtsiExtKeysVoid {
        request_id: Uuid::new_v4().to_string(),
        key_ids: vec![String::from("ZHVtbXkta2V5LW1hdGVyaWFs")],
        reason: String::from("probe"),
    };
    publish_json(session, remote_topics.ext_keys_void.as_str(), &ext_keys_void, "Zenoh ext_keys void").await?;

    let raft_presence_payload = serde_json::json!({
        "kind": ZenohRaftMessageKind::Presence,
        "node_id": node_id,
        "plane": "raft",
    });
    publish_json(session, remote_topics.raft_presence.as_str(), &raft_presence_payload, "Zenoh raft presence").await?;

    let raft_transition_request = ZenohRaftTransitionRequest {
        request_id: Uuid::new_v4().to_string(),
        key_id: Uuid::new_v4().to_string(),
        master_kme: node_id.to_string(),
        slave_kme: node_id.to_string(),
        current_state: ZenohKeyState::Generated,
        requested_state: ZenohKeyState::Syncing,
    };
    publish_json(session, remote_topics.raft_transition_request.as_str(), &raft_transition_request, "Zenoh raft transition request").await?;

    let raft_transition_decision = ZenohRaftTransitionDecision {
        request_id: raft_transition_request.request_id.clone(),
        accepted: true,
        reason: None,
    };
    publish_json(session, remote_topics.raft_transition_decision.as_str(), &raft_transition_decision, "Zenoh raft transition decision").await?;

    publish_local_state_transition(session, remote_topics, raft_transition_request.request_id, local_key_state).await?;

    Ok(())
}

/// Transition this node's local placeholder key state and publish the
/// resulting `ZenohRaftStateUpdate`.
///
/// This simulates "initial state -> event emitted" for a single
/// placeholder key: the placeholder will be replaced by a real
/// read/write against `QkdManager`'s key storage once this transport is
/// wired to it.
async fn publish_local_state_transition(
    session: &zenoh::Session,
    remote_topics: &ContractTopics,
    request_id: String,
    local_key_state: &Arc<Mutex<ZenohKeyState>>,
) -> Result<(), io::Error> {
    let new_state = {
        let mut state = local_key_state.lock().unwrap();
        let next_state = match *state {
            ZenohKeyState::Generated => ZenohKeyState::Syncing,
            ZenohKeyState::Syncing => ZenohKeyState::InUse,
            ZenohKeyState::InUse => ZenohKeyState::DeletedOrUsed,
            ZenohKeyState::DeletedOrUsed => ZenohKeyState::Generated,
        };
        *state = next_state;
        next_state
    };

    let state_update = ZenohRaftStateUpdate {
        request_id,
        key_id: String::from(PLACEHOLDER_KEY_ID),
        state: new_state,
        committed: true,
    };
    publish_json(session, remote_topics.raft_state_update.as_str(), &state_update, "Zenoh raft state update").await
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
