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
    /// Known peers used as an optional bootstrap/fallback connection hint (e.g. to cross a
    /// network segment multicast scouting cannot reach). With [`ZenohScoutingConfig`] enabled
    /// (the default), nodes are *not* required to be listed here to be reachable: they are
    /// discovered automatically via Zenoh's own multicast/gossip scouting, and traffic to them
    /// is routed hop-by-hop through however many peers are actually connected - this list is no
    /// longer the mechanism that makes a node reachable, just an optional shortcut/bootstrap.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Optional router endpoint if the node is configured to reach a central router.
    pub router_endpoint: Option<String>,
    /// Node role in the Zenoh topology.
    #[serde(default)]
    pub role: ZenohNodeRole,
    /// Automatic peer discovery configuration (multicast + gossip scouting). See
    /// [`ZenohScoutingConfig`] for details; this replaces the need to statically list every
    /// other KME under `peers` for a node to be reachable.
    #[serde(default)]
    pub scouting: ZenohScoutingConfig,
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
            scouting: ZenohScoutingConfig::default(),
            raft: RaftConfig::default(),
            tls: None,
            other_kme_node_ids: HashMap::new(),
        }
    }
}

/// Automatic peer discovery configuration for the Zenoh transport.
///
/// Instead of requiring every KME to be listed in every other KME's `peers` config (a
/// pre-configured, fully-known topology), Zenoh's built-in scouting is used so a node joining
/// the network is discovered and connected to automatically:
/// - Multicast scouting discovers peers on the same broadcast domain (e.g. same Docker network
///   or LAN) with no configuration needed beyond this being enabled (the default).
/// - Gossip scouting propagates peer information through already-established links so nodes
///   that aren't on the same multicast domain (e.g. reached only through one or more
///   intermediate KMEs) are still discovered - this is what makes the topology-agnostic,
///   hop-by-hop reachability requirement work even when KMEs are *not* all interconnected
///   directly with each other. Actual message delivery hop-by-hop through however many peers are
///   connected is handled transparently by Zenoh's own routing, once any connected path exists;
///   no application-level relay logic is required.
///
/// Note: the multicast/gossip scouting beacon itself only advertises reachable locators (e.g.
/// `tls/host:port`); it does not carry payload data. The actual Zenoh session/link is still
/// negotiated through the configured `transport.link.tls` (mTLS remains mandatory and is
/// unaffected by enabling scouting).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohScoutingConfig {
    /// Network interface to send/listen for multicast scouting packets on (e.g. `"eth0"`).
    /// `None` lets Zenoh auto-select one, which is fine on a single-interface host but may need
    /// to be set explicitly in some container/multi-NIC network setups.
    #[serde(default)]
    pub multicast_interface: Option<String>,
}

impl Default for ZenohScoutingConfig {
    fn default() -> Self {
        Self {
            multicast_interface: None,
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
