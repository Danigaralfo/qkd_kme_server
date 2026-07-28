//! Configuration structures for the Zenoh transport skeleton.

use serde::{Deserialize, Serialize};

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
    /// Hostname/node_id of a remote node used to run the contract probe.
    ///
    /// This field is a temporary testing aid to validate the contract defined in
    /// [`crate::zenoh_transport::contract`] between two real processes. It is not
    /// meant to survive once real ETSI/Raft business logic drives topic wiring
    /// automatically from `other_kmes` and cluster membership.
    #[serde(default)]
    pub probe_remote_node_id: Option<String>,
    /// Role played by this node in the contract probe.
    ///
    /// See [`ZenohTransportConfig::probe_remote_node_id`] for context: this only
    /// controls the temporary probe, not real message routing.
    #[serde(default)]
    pub probe_role: ZenohProbeRole,
}

impl Default for ZenohTransportConfig {
    fn default() -> Self {
        Self {
            node_id: String::from("kme-node"),
            listen_endpoint: None,
            peers: Vec::new(),
            router_endpoint: None,
            role: ZenohNodeRole::Peer,
            probe_remote_node_id: None,
            probe_role: ZenohProbeRole::Responder,
        }
    }
}

/// Role played by a node in the temporary contract probe.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZenohProbeRole {
    /// This node publishes sample contract messages toward `probe_remote_node_id`.
    Initiator,
    /// This node only subscribes to its own topics and waits for messages.
    Responder,
}

impl Default for ZenohProbeRole {
    fn default() -> Self {
        Self::Responder
    }
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
