//! Objects deserialized from HTTP request body

use serde::{Deserialize, Serialize};
use crate::{KmeId, SaeId};

/// Request from the slave SAE to get key(s) from UUIDs provided by the master SAE
#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct RequestKeyId {
    pub(crate) key_ID: String,
}

/// List of key IDs requested by the slave SAE
#[derive(Deserialize, Debug, Default)]
#[allow(non_snake_case)]
pub(crate) struct RequestListKeysIds {
    pub(crate) key_IDs: Vec<RequestKeyId>,
}

#[derive(Deserialize, Debug, Default)]
#[allow(non_snake_case)]
pub(crate) struct MasterKeyRequestObj {
    pub(crate) number: Option<usize>
}

/// From inter-KME network: a key has been requested on a remote KME for a specific target SAE
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct ActivateKeyRemoteKME {
    pub(crate) key_IDs_list: Vec<String>,
    /// Master SAE that requested the key
    pub(crate) origin_SAE_ID: SaeId,
    pub(crate) remote_SAE_ID: SaeId,
    /// Numeric id of the true final destination KME for this key material, which may differ
    /// from the immediate receiver of this HTTPS call when it is being relayed hop-by-hop across
    /// KMEs with no direct QKD link (`ZenohRaft` transport mode only, see
    /// `crate::zenoh_transport::routing`). Equal to the receiver's own KME id in the classical,
    /// non-relay case (the only case possible outside `ZenohRaft` mode).
    pub(crate) final_target_kme_id: KmeId,
    /// Numeric ids of every KME that has already handled this specific key material, including
    /// the true origin, in relay order, used to avoid routing loops when computing the next hop.
    pub(crate) visited_kme_ids: Vec<KmeId>,
}

/// From inter-KME network: a set of already-activated keys must be voided (permanently deleted) on this KME
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct VoidKeysRemoteKME {
    pub(crate) key_IDs_list: Vec<String>,
}