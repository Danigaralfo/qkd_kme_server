//! This module separates the two communication planes described by the
//! architecture specification docs\QKD_ZenohRaft_Architecture_Specification.pdf:
//! - Raft coordination messages, which carry state and decisions but no key material.
//! - ETSI-020 payloads carried over Zenoh, which may transport key material for
//!   synchronization between KMEs.
//!
//! It also defines a single, plane-agnostic error format (`ZenohErrorResponse`)
//! for protocol-level failures.

use serde::{Deserialize, Serialize};

/// Contract version used by all Zenoh payloads defined in this module.
pub const ZENOH_CONTRACT_VERSION: &str = "1.0";

/// Plane used by a Zenoh message.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZenohPlane {
    /// Raft coordination plane for key-state decisions.
    Raft,
    /// ETSI-020 transport plane for key exchange payloads.
    Etsi020,
}

/// Key state used by the Raft plane.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZenohKeyState {
    /// Key has just been generated.
    Generated,
    /// Key is currently being synchronized.
    Syncing,
    /// Key is being used by two peers.
    InUse,
    /// Key has already been deleted or used.
    DeletedOrUsed,
}

/// Raft coordination message kind.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZenohRaftMessageKind {
    /// A node advertises its presence or readiness.
    Presence,
    /// A client asks the leader to authorize a key-state transition.
    TransitionRequest,
    /// The leader accepts or rejects the requested transition.
    TransitionDecision,
    /// A committed state transition is propagated to followers.
    StateUpdate,
}

/// ETSI-020 message kind transported by Zenoh.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZenohEtsiMessageKind {
    /// Query for the API version endpoint.
    VersionQuery,
    /// Response carrying the version information for the API endpoint.
    VersionResponse,
    /// Publication of external keys toward the slave node topic.
    ExtKeys,
    /// Acknowledgement that external keys were received.
    ExtKeysAck,
    /// Notification that a (set of) key(s) has to be voided.
    ExtKeysVoid,
}

/// Machine-readable error code shared by both Zenoh planes.
///
/// This is distinct from domain-level business responses (e.g. a rejected
/// `ZenohRaftTransitionDecision` or a `ZenohEtsiExtKeysVoid` notification), which are
/// expected outcomes and not protocol-level failures.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZenohErrorCode {
    /// The received payload could not be parsed or was missing required fields.
    MalformedRequest,
    /// The referenced key-id is unknown to the responder.
    UnknownKey,
    /// The referenced node-id is unknown to the responder.
    UnknownNode,
    /// The request could not be served because the responder is not the current Raft leader.
    /// A reference to the current Raft leader is included in the error response.
    NotLeader,
    /// An unexpected internal error occurred while handling the request.
    Internal,
}

/// Generic, stable error response usable on any Zenoh contract topic.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohErrorResponse {
    /// Request identifier this error answers, when it could be recovered from the request.
    pub request_id: Option<String>,
    /// Plane on which the error occurred.
    pub plane: ZenohPlane,
    /// Machine-readable error code.
    pub code: ZenohErrorCode,
    /// Human-readable error message, not meant to be parsed by callers.
    pub message: String,
    /// Node-id of the most recent Raft leader known by the responder, mirroring
    /// the `leaderId` field of the `AppendEntries` RPC in the Raft paper.
    /// Only meaningful when `code` is `NotLeader`; `None` if the responder does not know the current leader.
    pub leader_hint: Option<String>,
}

/// Raft request to authorize a key state transition.
///
/// This is generic to any transition between two [`ZenohKeyState`] values
/// (e.g. `Generated` -> `Syncing`, `Syncing` -> `InUse`, `InUse` ->
/// `DeletedOrUsed`), not specific to the `Syncing` state. It is answered by a
/// [`ZenohRaftTransitionDecision`].
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohRaftTransitionRequest {
    /// Unique request identifier. UUIDv4 format.
    pub request_id: String,
    /// Identifier of the key whose state will change.
    pub key_id: String,
    /// Identifier of the node that owns or initiates the request.
    pub master_kme: String,
    /// Identifier of the remote node involved in the synchronization.
    pub slave_kme: String,
    /// State observed before the transition.
    pub current_state: ZenohKeyState,
    /// State being requested for the transition, e.g. `Syncing` when asking
    /// for permission to start an ETSI-020 key exchange between KMEs.
    pub requested_state: ZenohKeyState,
}

/// Raft decision returned by the leader for a [`ZenohRaftTransitionRequest`] to the requester client node.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohRaftTransitionDecision {
    /// Unique request identifier that this decision answers. UUIDv4 format.
    pub request_id: String,
    /// Whether the transition has been accepted.
    pub accepted: bool,
    /// Optional reason when the request is rejected.
    pub reason: Option<String>,
}

/// Raft state update emitted from the leader to its followers once a transition is committed.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohRaftStateUpdate {
    /// Unique request identifier that originated the state change. UUIDv4 format.
    pub request_id: String,
    /// Identifier of the key whose state changed.
    pub key_id: String,
    /// The committed key state.
    pub state: ZenohKeyState,
    /// Whether the update is already committed in the cluster.
    pub committed: bool,
}

/// Follower acknowledgement of a replicated [`ZenohRaftTransitionRequest`], sent back to the leader.
///
/// This flows in the opposite direction of [`ZenohRaftTransitionDecision`]
/// (follower -> leader instead of leader -> requester) and only conveys
/// whether the follower locally validated and accepted the replicated entry;
/// it is not itself the leader's final decision to the original requester.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohRaftReplicateAck {
    /// Request identifier of the transition being acknowledged. UUIDv4 format.
    pub request_id: String,
    /// Node-id of the follower issuing this acknowledgement.
    pub follower_kme: String,
    /// Whether the follower locally validated and accepted the replicated transition.
    pub accepted: bool,
}

/// External key material transported on the ETSI-020 Zenoh plane.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohEtsiKeyMaterial {
    /// Identifier of the key.
    pub key_id: String,
    /// Base64-encoded key material.
    pub key_b64: String,
}

/// Request sent on the Zenoh version query topic.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohEtsiVersionQuery {
    /// Unique request identifier. UUIDv4 format.
    pub request_id: String,
    /// Identifier of the KME asking for the version.
    pub requester_kme: String,
}

/// Response sent on the Zenoh version query topic.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohEtsiVersionResponse {
    /// Unique request identifier echoed from the query. UUIDv4 format.
    pub request_id: String,
    /// Identifier of the KME answering the query.
    pub responder_kme: String,
    /// API version exposed by the responder.
    pub api_version: String,
    /// Zenoh contract version exposed by the responder.
    pub contract_version: String,
}

/// ETSI-020 request for external keys.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohEtsiExtKeysRequest {
    /// Unique request identifier. UUIDv4 format.
    pub request_id: String,
    /// Master KME that initiates the exchange.
    pub master_kme: String,
    /// Slave KME that receives the key material.
    pub slave_kme: String,
    /// Number of keys requested in this exchange.
    pub key_count: usize,
}

/// ETSI-020 payload that carries the key material itself.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohEtsiExtKeysBatch {
    /// Unique request identifier. UUIDv4 format.
    pub request_id: String,
    /// Master KME that produced the keys.
    pub master_kme: String,
    /// Slave KME that receives the keys.
    pub slave_kme: String,
    /// Key material carried by the message.
    pub keys: Vec<ZenohEtsiKeyMaterial>,
}

/// ETSI-020 acknowledgement for a received key batch.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohEtsiExtKeysAck {
    /// Unique request identifier. UUIDv4 format.
    pub request_id: String,
    /// Number of keys acknowledged as received.
    pub received_keys: usize,
}

/// ETSI-020 notification that an set of keys need to be voided.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohEtsiExtKeysVoid {
    /// Unique request identifier. UUIDv4 format.
    pub request_id: String,
    /// Key-IDs to be voided
    pub key_ids: Vec<String>,
    /// Human-readable void reason.
    pub reason: String,
}

/// Zenoh topic builders aligned with the specification.
pub struct ZenohTopicMap;

impl ZenohTopicMap {
    /// Build the query topic for `/kmapi/version`.
    pub fn version_query_topic(master_node_hostname: &str) -> String {
        format!("{master_node_hostname}/kmapi/version")
    }

    /// Build the response topic for `/kmapi/version`.
    pub fn version_response_topic(master_node_hostname: &str) -> String {
        format!("{master_node_hostname}/kmapi/version")
    }

    /// Build the pub/sub topic for `/kmapi/v1/ext_keys`.
    pub fn ext_keys_topic(slave_node_hostname: &str) -> String {
        format!("{slave_node_hostname}/kmapi/ext_keys")
    }

    /// Build the acknowledgement topic for `/kmapi/v1/ext_keys/ack`.
    pub fn ext_keys_ack_topic(master_node_hostname: &str) -> String {
        format!("{master_node_hostname}/kmapi/ext_keys/ack")
    }

    /// Build the void topic for `/kmapi/v1/ext_keys/void`.
    pub fn ext_keys_void_topic(slave_node_hostname: &str) -> String {
        format!("{slave_node_hostname}/kmapi/ext_keys/void")
    }

    /// Build a topic for Raft presence announcements.
    pub fn raft_presence_topic(node_id: &str) -> String {
        format!("kme/{node_id}/raft/presence")
    }

    /// Build a topic for Raft transition requests.
    pub fn raft_transition_request_topic(node_id: &str) -> String {
        format!("kme/{node_id}/raft/state_transition/request")
    }

    /// Build a topic for Raft transition decisions.
    pub fn raft_transition_decision_topic(node_id: &str) -> String {
        format!("kme/{node_id}/raft/state_transition/decision")
    }

    /// Build a topic for Raft state updates.
    pub fn raft_state_update_topic(node_id: &str) -> String {
        format!("kme/{node_id}/raft/state/update")
    }

    /// Build the topic where followers acknowledge a replicated transition back to the leader.
    pub fn raft_replicate_ack_topic(leader_node_id: &str) -> String {
        format!("kme/{leader_node_id}/raft/state_transition/ack")
    }

    /// Build the topic used to report protocol-level errors for a node,
    /// shared by both the Raft and ETSI-020 planes.
    pub fn error_topic(node_id: &str) -> String {
        format!("kme/{node_id}/error")
    }
}

#[cfg(test)]
mod tests {
    use super::{ZenohErrorCode, ZenohErrorResponse, ZenohEtsiExtKeysRequest, ZenohEtsiVersionQuery, ZenohEtsiVersionResponse, ZenohPlane, ZenohRaftReplicateAck, ZenohTopicMap, ZENOH_CONTRACT_VERSION};

    #[test]
    fn topic_map_follows_specification() {
        assert_eq!(ZenohTopicMap::version_query_topic("kme-a"), "kme-a/kmapi/version");
        assert_eq!(ZenohTopicMap::version_response_topic("kme-a"), "kme-a/kmapi/version");
        assert_eq!(ZenohTopicMap::ext_keys_topic("kme-b"), "kme-b/kmapi/ext_keys");
        assert_eq!(ZenohTopicMap::ext_keys_ack_topic("kme-a"), "kme-a/kmapi/ext_keys/ack");
        assert_eq!(ZenohTopicMap::ext_keys_void_topic("kme-b"), "kme-b/kmapi/ext_keys/void");
        assert_eq!(ZenohTopicMap::raft_replicate_ack_topic("kme-a"), "kme/kme-a/raft/state_transition/ack");
    }

    #[test]
    fn raft_replicate_ack_serializes_follower_and_request_id() {
        let ack = ZenohRaftReplicateAck {
            request_id: String::from("req-4"),
            follower_kme: String::from("kme-b"),
            accepted: true,
        };

        let json = serde_json::to_string(&ack).unwrap();
        assert!(json.contains("req-4"));
        assert!(json.contains("kme-b"));
        assert!(json.contains("true"));
    }

    #[test]
    fn version_payloads_serializes_version_information() {
        let query = ZenohEtsiVersionQuery {
            request_id: String::from("req-version-1"),
            requester_kme: String::from("kme-a"),
        };
        let response = ZenohEtsiVersionResponse {
            request_id: String::from("req-version-1"),
            responder_kme: String::from("kme-b"),
            api_version: String::from("v1"),
            contract_version: String::from(ZENOH_CONTRACT_VERSION),
        };

        let query_json = serde_json::to_string(&query).unwrap();
        let response_json = serde_json::to_string(&response).unwrap();

        assert!(query_json.contains("req-version-1"));
        assert!(query_json.contains("kme-a"));
        assert!(response_json.contains("v1"));
        assert!(response_json.contains(ZENOH_CONTRACT_VERSION));
    }

    #[test]
    fn etsi_ext_keys_request_serializes_key_count() {
        let request = ZenohEtsiExtKeysRequest {
            request_id: String::from("req-2"),
            master_kme: String::from("kme-a"),
            slave_kme: String::from("kme-b"),
            key_count: 3,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("req-2"));
        assert!(json.contains("\"key_count\":3"));
    }

    #[test]
    fn error_response_is_stable_and_plane_agnostic() {
        assert_eq!(ZenohTopicMap::error_topic("kme-a"), "kme/kme-a/error");

        let raft_error = ZenohErrorResponse {
            request_id: Some(String::from("req-3")),
            plane: ZenohPlane::Raft,
            code: ZenohErrorCode::NotLeader,
            message: String::from("node is not the current Raft leader"),
            leader_hint: Some(String::from("kme-c")),
        };
        let etsi_error = ZenohErrorResponse {
            request_id: None,
            plane: ZenohPlane::Etsi020,
            code: ZenohErrorCode::UnknownKey,
            message: String::from("key-id not found"),
            leader_hint: None,
        };

        let raft_json = serde_json::to_string(&raft_error).unwrap();
        let etsi_json = serde_json::to_string(&etsi_error).unwrap();

        assert!(raft_json.contains("not_leader"));
        assert!(raft_json.contains("raft"));
        assert!(raft_json.contains("kme-c"));
        assert!(etsi_json.contains("unknown_key"));
        assert!(etsi_json.contains("etsi020"));
    }
}