//! Message envelopes for the Zenoh transport skeleton.

use serde::{Deserialize, Serialize};

/// Type of event the transport will carry.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZenohMessageKind {
    /// Discovery or bootstrap-related event.
    Discovery,
    /// State transition request or notification.
    StateChange,
    /// Request/response payload associated with QKD coordination.
    Coordination,
}

/// Generic envelope for transport messages.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZenohEnvelope {
    /// Logical topic where the message belongs.
    pub topic: String,
    /// Classification of the payload.
    pub kind: ZenohMessageKind,
    /// Opaque payload kept as JSON for now.
    pub payload_json: String,
}

impl ZenohEnvelope {
    /// Create a new envelope for a given topic, kind and payload.
    pub fn new(topic: impl Into<String>, kind: ZenohMessageKind, payload_json: impl Into<String>) -> Self {
        Self {
            topic: topic.into(),
            kind,
            payload_json: payload_json.into(),
        }
    }
}