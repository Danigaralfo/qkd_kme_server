//! Dynamic, live-updatable registry of other KMEs known to this node (their Zenoh `node_id`),
//! keyed by numeric [`KmeId`].
//!
//! Seeded once at startup from static config (`other_kmes[].zenoh_node_id`, see
//! `crate::zenoh_transport::config::ZenohTransportConfig::other_kme_node_ids`), then kept up to
//! date at runtime as new KMEs are discovered over Zenoh (see
//! `crate::zenoh_transport::runtime::ZenohTransport::spawn_registry_discovery`), so a KME can be
//! hot-plugged into a running network without needing to appear in every other node's static
//! config at all.
//!
//! Cloning this type is cheap and shares the same underlying map (like
//! `crate::zenoh_transport::raft::KeyStates`), so every component that needs to resolve a
//! [`KmeId`] to a Zenoh `node_id` (currently only
//! `crate::zenoh_transport::inter_kme_transport::ZenohInterKmeTransport`) observes updates made
//! by the discovery task without needing to be reconstructed.

use crate::KmeId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A registered KME's Zenoh `node_id` and the KMEs it has a genuine (real or simulated) direct
/// QKD link with, see the module documentation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RegisteredKme {
    node_id: String,
    qkd_linked_kme_ids: Vec<KmeId>,
}

/// Shared, thread-safe `KmeId -> Zenoh node_id` map, see the module documentation.
#[derive(Clone, Default)]
pub(crate) struct KmeNodeRegistry(Arc<RwLock<HashMap<KmeId, RegisteredKme>>>);

impl KmeNodeRegistry {
    /// Create a new registry, seeded with the statically-configured `other_kmes[].zenoh_node_id`
    /// entries known at startup. QKD adjacency isn't known ahead of time for these, and is filled
    /// in later, either via `upsert` (self-seeding, see
    /// `crate::zenoh_transport::runtime::ZenohTransport::run`) or discovery.
    pub(crate) fn new(initial: HashMap<KmeId, String>) -> Self {
        let initial = initial.into_iter()
            .map(|(kme_id, node_id)| (kme_id, RegisteredKme { node_id, qkd_linked_kme_ids: vec![] }))
            .collect();
        Self(Arc::new(RwLock::new(initial)))
    }

    /// Resolve a [`KmeId`] to the Zenoh `node_id` currently known for it, if any.
    pub(crate) fn get(&self, kme_id: KmeId) -> Option<String> {
        self.0.read().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&kme_id).map(|entry| entry.node_id.clone())
    }

    /// Record (or refresh) a discovered KME's Zenoh `node_id` and the KMEs it has a genuine
    /// direct QKD link with (see [`crate::qkd_manager::QkdManager::list_qkd_linked_kme_ids`]).
    /// # Returns
    /// `true` if this is a new or changed `node_id` mapping (i.e. `kme_id` was not already known
    /// to map to `node_id`), `false` if it was already known unchanged, for callers that only
    /// want to log/react on first discovery. The QKD adjacency list is always refreshed
    /// regardless of this return value, since topology can change without `node_id` changing.
    pub(crate) fn upsert(&self, kme_id: KmeId, node_id: String, qkd_linked_kme_ids: Vec<KmeId>) -> bool {
        let mut map = self.0.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let is_new_or_changed = match map.get(&kme_id) {
            Some(existing) if existing.node_id == node_id => false,
            _ => true,
        };
        map.insert(kme_id, RegisteredKme { node_id, qkd_linked_kme_ids });
        is_new_or_changed
    }

    /// Snapshot of every currently-known KME's own direct QKD neighbors, for
    /// `crate::zenoh_transport::routing` to compute multi-hop relay routes.
    pub(crate) fn qkd_graph_snapshot(&self) -> HashMap<KmeId, Vec<KmeId>> {
        self.0.read().unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(kme_id, entry)| (*kme_id, entry.qkd_linked_kme_ids.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_from_initial_map_and_resolves() {
        let mut initial = HashMap::new();
        initial.insert(1, String::from("kme-1-zenoh"));
        let registry = KmeNodeRegistry::new(initial);
        assert_eq!(registry.get(1), Some(String::from("kme-1-zenoh")));
        assert_eq!(registry.get(2), None);
    }

    #[test]
    fn upsert_reports_new_and_unchanged_mappings() {
        let registry = KmeNodeRegistry::new(HashMap::new());
        assert!(registry.upsert(3, String::from("kme-3-zenoh"), vec![]));
        assert_eq!(registry.get(3), Some(String::from("kme-3-zenoh")));
        // Same mapping again: not a new discovery.
        assert!(!registry.upsert(3, String::from("kme-3-zenoh"), vec![]));
        // Changed mapping: reported as new/changed.
        assert!(registry.upsert(3, String::from("kme-3-zenoh-restarted"), vec![]));
        assert_eq!(registry.get(3), Some(String::from("kme-3-zenoh-restarted")));
    }

    #[test]
    fn cloning_shares_the_same_underlying_map() {
        let registry = KmeNodeRegistry::new(HashMap::new());
        let cloned = registry.clone();
        cloned.upsert(5, String::from("kme-5-zenoh"), vec![]);
        assert_eq!(registry.get(5), Some(String::from("kme-5-zenoh")));
    }

    #[test]
    fn qkd_graph_snapshot_reflects_every_registered_kme() {
        let registry = KmeNodeRegistry::new(HashMap::new());
        registry.upsert(1, String::from("kme-1"), vec![2]);
        registry.upsert(2, String::from("kme-2"), vec![1, 3]);
        let graph = registry.qkd_graph_snapshot();
        assert_eq!(graph.get(&1), Some(&vec![2]));
        assert_eq!(graph.get(&2), Some(&vec![1, 3]));
    }
}
