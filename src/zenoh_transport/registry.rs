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

/// Shared, thread-safe `KmeId -> Zenoh node_id` map, see the module documentation.
#[derive(Clone, Default)]
pub(crate) struct KmeNodeRegistry(Arc<RwLock<HashMap<KmeId, String>>>);

impl KmeNodeRegistry {
    /// Create a new registry, seeded with the statically-configured `other_kmes[].zenoh_node_id`
    /// entries known at startup.
    pub(crate) fn new(initial: HashMap<KmeId, String>) -> Self {
        Self(Arc::new(RwLock::new(initial)))
    }

    /// Resolve a [`KmeId`] to the Zenoh `node_id` currently known for it, if any.
    pub(crate) fn get(&self, kme_id: KmeId) -> Option<String> {
        self.0.read().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&kme_id).cloned()
    }

    /// Record (or refresh) a discovered KME's Zenoh `node_id`.
    /// # Returns
    /// `true` if this is a new or changed mapping (i.e. `kme_id` was not already known to map to
    /// `node_id`), `false` if it was already known unchanged, for callers that only want to
    /// log/react on first discovery.
    pub(crate) fn upsert(&self, kme_id: KmeId, node_id: String) -> bool {
        let mut map = self.0.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        match map.get(&kme_id) {
            Some(existing) if existing == &node_id => false,
            _ => {
                map.insert(kme_id, node_id);
                true
            }
        }
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
        assert!(registry.upsert(3, String::from("kme-3-zenoh")));
        assert_eq!(registry.get(3), Some(String::from("kme-3-zenoh")));
        // Same mapping again: not a new discovery.
        assert!(!registry.upsert(3, String::from("kme-3-zenoh")));
        // Changed mapping: reported as new/changed.
        assert!(registry.upsert(3, String::from("kme-3-zenoh-restarted")));
        assert_eq!(registry.get(3), Some(String::from("kme-3-zenoh-restarted")));
    }

    #[test]
    fn cloning_shares_the_same_underlying_map() {
        let registry = KmeNodeRegistry::new(HashMap::new());
        let cloned = registry.clone();
        cloned.upsert(5, String::from("kme-5-zenoh"));
        assert_eq!(registry.get(5), Some(String::from("kme-5-zenoh")));
    }
}
