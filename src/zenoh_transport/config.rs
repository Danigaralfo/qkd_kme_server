//! Configuration structures for the Zenoh transport skeleton.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::KmeId;

/// High-level configuration for the Zenoh transport layer.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohTransportConfig {
    /// Logical node identifier used by Zenoh participants.
    pub node_id: String,
    /// Optional local endpoint where the node will bind in the future.
    pub listen_endpoint: Option<String>,
    /// Known peers used for bootstrap in a mesh or router deployment.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Optional router endpoint if the node is configured to reach a central router.
    pub router_endpoint: Option<String>,
    /// Node role in the Zenoh topology.
    #[serde(default)]
    pub role: ZenohNodeRole,
    /// Raft cluster configuration used to replicate key-state transitions
    /// (Phase 4). See [`RaftConfig`] for details and current limitations.
    #[serde(default)]
    pub raft: RaftConfig,
    /// Maps each other KME's numeric [`KmeId`] to its Zenoh `node_id` hostname, so point-to-point
    /// topics (e.g. the `/kmapi/activate` inter-KME transport) can address the right peer.
    /// Not part of the JSON `zenoh_transport` block itself: built from `other_kmes[].zenoh_node_id`
    /// (see [`crate::config::Config::other_kme_zenoh_node_ids`]) and filled in after deserialization.
    #[serde(skip)]
    pub other_kme_node_ids: HashMap<KmeId, String>,
}

impl Default for ZenohTransportConfig {
    fn default() -> Self {
        Self {
            node_id: String::from("kme-node"),
            listen_endpoint: None,
            peers: Vec::new(),
            router_endpoint: None,
            role: ZenohNodeRole::Peer,
            raft: RaftConfig::default(),
            other_kme_node_ids: HashMap::new(),
        }
    }
}

/// Raft cluster configuration for key-state transition consensus (Phase 4).
///
/// Leader election is not implemented yet: `leader_id` is a static,
/// operator-configured leader shared by every node's configuration file.
/// This will be replaced by a real election protocol (`RequestVote`/terms)
/// in a later increment; until then, if the configured leader is
/// unreachable the cluster simply cannot commit new transitions.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RaftConfig {
    /// Node-ids of every member participating in the Raft cluster, including this node.
    #[serde(default)]
    pub cluster_members: Vec<String>,
    /// Node-id of the statically configured leader.
    ///
    /// Must be one of `cluster_members`. `None` means this node does not
    /// participate in Raft consensus.
    #[serde(default)]
    pub leader_id: Option<String>,
}

/// Role of the node inside the Zenoh topology.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZenohNodeRole {
    /// Direct peer-to-peer or mesh participant.
    Peer,
    /// Client attached to a router.
    Client,
    /// Router node.
    Router,
}

impl Default for ZenohNodeRole {
    fn default() -> Self {
        Self::Peer
    }
}

impl ZenohNodeRole {
    /// Return the Zenoh mode string expected by the configuration file.
    pub fn as_zenoh_mode_str(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Client => "client",
            Self::Router => "router",
        }
    }
}
