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
    /// Mutual TLS configuration for the Zenoh session's underlying links.
    ///
    /// mTLS is mandatory for the `zenoh_raft` transport mode: [`crate::zenoh_transport::runtime::ZenohTransport`]
    /// refuses to open a Zenoh session if this is not configured. It is kept optional at the type
    /// level (defaulting to `None` when absent from the JSON5 config) purely so this struct stays
    /// constructible via [`Default`] in tests; real deployments must always set it.
    #[serde(default)]
    pub tls: Option<ZenohTlsConfig>,
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
            tls: None,
            other_kme_node_ids: HashMap::new(),
        }
    }
}

/// Mutual TLS (mTLS) configuration for the Zenoh transport's underlying links.
///
/// A single certificate/key pair identifies this node, presented both when accepting inbound
/// Zenoh connections and when dialing out to a peer.
///
/// `root_ca_certificate` is used to validate the remote peer's certificate in both roles, so it
/// must be a CA (or CA bundle, i.e. a PEM file with multiple concatenated certificates) that can
/// verify whichever node certificate the peer presents.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohTlsConfig {
    /// Path to the CA certificate (or PEM bundle of multiple CA certificates) used to validate
    /// the remote peer's certificate.
    pub root_ca_certificate: String,
    /// Path to this node's own certificate, presented both when accepting incoming Zenoh
    /// connections and when dialing out to a peer.
    pub certificate: String,
    /// Path to this node's own private key for `certificate`.
    pub private_key: String,
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
