//! Multi-hop key relay routing (`ZenohRaft` transport mode only).
//!
//! Lets key material reach a KME that has no direct (real or simulated) QKD link with the
//! origin, by relaying it hop-by-hop through intermediate KMEs: the classical HTTPS
//! `/keys/activate` protocol (see `crate::qkd_manager::inter_kme_transport::HttpsInterKmeTransport`)
//! is used for any hop where a genuine QKD link exists between the two KMEs involved, and Zenoh
//! (see `crate::zenoh_transport::inter_kme_transport::ZenohInterKmeTransport`) for any hop where
//! it doesn't - Zenoh's own scouting/gossip already delivers messages to any reachable node
//! directly, so a Zenoh "bridge" hop never needs more than one physical relay at this layer.
//!
//! [`compute_next_hop`] is a small greedy heuristic, not a globally-optimal path search: it
//! prefers walking this KME's own QKD links first (since that is how key material enters the
//! system in the first place - see [`crate::qkd_manager::key_handler::KeyHandler::get_sae_keys`]),
//! and only bridges over Zenoh once none of its own QKD links make progress. This is intentional
//! and sufficient for the small QKD-linked topologies this project targets; it is not guaranteed
//! to find the shortest possible route in a large or densely-connected network.

use std::collections::{HashMap, HashSet, VecDeque};
use crate::KmeId;

use super::registry::KmeNodeRegistry;

/// How a specific hop toward a key's final destination is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HopTransport {
    /// Reached via a genuine (real or simulated) direct QKD link: the classical HTTPS
    /// `/keys/activate` protocol is used, relying on both sides sharing byte-identical raw key
    /// material out of band (see `crate::qkd_manager::inter_kme_transport::HttpsInterKmeTransport`).
    QkdLink,
    /// No direct QKD link to this hop: key material is pushed directly over Zenoh (see
    /// `crate::zenoh_transport::inter_kme_transport::ZenohInterKmeTransport`).
    Zenoh,
}

/// The next KME a key should be handed to, and how.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NextHop {
    /// Numeric id of the next-hop KME.
    pub kme_id: KmeId,
    /// Transport to use for this specific hop.
    pub transport: HopTransport,
}

/// Resolves the next hop toward a key's true final destination KME, for multi-hop relay across
/// KMEs with no direct QKD link (installed only in `ZenohRaft` transport mode, see
/// `crate::qkd_manager::key_handler::KeyHandler::set_key_routing_resolver`).
pub trait KeyRoutingResolver: Send + Sync {
    /// Compute the next hop toward `final_target_kme_id`, excluding any KME already present in
    /// `visited_kme_ids` (to avoid routing loops).
    /// # Returns
    /// `None` if no route could be found (e.g. this KME is already the final destination).
    fn next_hop(&self, final_target_kme_id: KmeId, visited_kme_ids: &[KmeId]) -> Option<NextHop>;
}

/// [`KeyRoutingResolver`] backed by the live [`KmeNodeRegistry`], installed only in `ZenohRaft`
/// transport mode (see `crate::zenoh_transport::runtime::ZenohTransport::run`).
pub(crate) struct ZenohKeyRouter {
    own_kme_id: KmeId,
    registry: KmeNodeRegistry,
}

impl ZenohKeyRouter {
    /// Build a resolver for `own_kme_id`, backed by `registry`'s live QKD-adjacency snapshot.
    pub(crate) fn new(own_kme_id: KmeId, registry: KmeNodeRegistry) -> Self {
        Self { own_kme_id, registry }
    }
}

impl KeyRoutingResolver for ZenohKeyRouter {
    fn next_hop(&self, final_target_kme_id: KmeId, visited_kme_ids: &[KmeId]) -> Option<NextHop> {
        let graph = self.registry.qkd_graph_snapshot();
        let own_neighbors: HashSet<KmeId> = graph.get(&self.own_kme_id).cloned().unwrap_or_default().into_iter().collect();
        compute_next_hop(self.own_kme_id, &own_neighbors, final_target_kme_id, &graph, visited_kme_ids)
    }
}

/// Pure graph computation used by [`KeyRoutingResolver`] implementations, see the module
/// documentation for the routing strategy.
/// # Arguments
/// * `own_kme_id` - This KME's own id.
/// * `own_qkd_neighbors` - KMEs this KME has a direct QKD link with.
/// * `final_target_kme_id` - The true final destination.
/// * `qkd_graph` - Every currently-known KME's own direct QKD neighbors (see
///   [`KmeNodeRegistry::qkd_graph_snapshot`]).
/// * `visited_kme_ids` - KMEs already relayed through, excluded from consideration.
pub fn compute_next_hop(
    own_kme_id: KmeId,
    own_qkd_neighbors: &HashSet<KmeId>,
    final_target_kme_id: KmeId,
    qkd_graph: &HashMap<KmeId, Vec<KmeId>>,
    visited_kme_ids: &[KmeId],
) -> Option<NextHop> {
    if own_kme_id == final_target_kme_id {
        return None;
    }

    // Direct QKD link to the final target: done in one hop.
    if own_qkd_neighbors.contains(&final_target_kme_id) {
        return Some(NextHop { kme_id: final_target_kme_id, transport: HopTransport::QkdLink });
    }

    let excluded: HashSet<KmeId> = visited_kme_ids.iter().copied().collect();
    let target_component = qkd_component(final_target_kme_id, qkd_graph);

    // Already within the final target's own QKD-connected component: an all-QKD path exists.
    if target_component.contains(&own_kme_id) {
        if let Some(first_hop) = bfs_first_hop(own_kme_id, final_target_kme_id, qkd_graph, &excluded) {
            return Some(NextHop { kme_id: first_hop, transport: HopTransport::QkdLink });
        }
    }

    // Prefer walking any not-yet-visited QKD link of our own, to make use of existing (real or
    // simulated) QKD stock before resorting to a Zenoh bridge.
    if let Some(&next) = own_qkd_neighbors.iter().filter(|id| !excluded.contains(id)).min() {
        return Some(NextHop { kme_id: next, transport: HopTransport::QkdLink });
    }

    // Dead end on our own QKD links: bridge over Zenoh directly into the final target's own
    // QKD-connected component (or straight to it, if it has no QKD links at all). Zenoh's own
    // scouting/gossip delivers this in a single physical hop regardless of graph distance.
    let bridge = target_component.iter().copied().filter(|id| !excluded.contains(id) && *id != own_kme_id).min();
    match bridge {
        Some(bridge) => Some(NextHop { kme_id: bridge, transport: HopTransport::Zenoh }),
        None => Some(NextHop { kme_id: final_target_kme_id, transport: HopTransport::Zenoh }),
    }
}

/// Every KME reachable from `start` using only QKD-link edges (including `start` itself).
fn qkd_component(start: KmeId, qkd_graph: &HashMap<KmeId, Vec<KmeId>>) -> HashSet<KmeId> {
    let mut visited = HashSet::new();
    let mut stack = vec![start];
    visited.insert(start);
    while let Some(node) = stack.pop() {
        for &neighbor in qkd_graph.get(&node).into_iter().flatten() {
            if visited.insert(neighbor) {
                stack.push(neighbor);
            }
        }
    }
    visited
}

/// Breadth-first search for the first hop of a shortest all-QKD-link path from `start` to
/// `target` in `qkd_graph`, excluding any node in `excluded`.
fn bfs_first_hop(
    start: KmeId,
    target: KmeId,
    qkd_graph: &HashMap<KmeId, Vec<KmeId>>,
    excluded: &HashSet<KmeId>,
) -> Option<KmeId> {
    let mut visited: HashSet<KmeId> = HashSet::new();
    visited.insert(start);
    // Queue of (current_node, first_hop_taken_from_start).
    let mut queue: VecDeque<(KmeId, KmeId)> = VecDeque::new();
    for &neighbor in qkd_graph.get(&start).into_iter().flatten() {
        if excluded.contains(&neighbor) || neighbor == start {
            continue;
        }
        if neighbor == target {
            return Some(neighbor);
        }
        if visited.insert(neighbor) {
            queue.push_back((neighbor, neighbor));
        }
    }
    while let Some((current, first_hop)) = queue.pop_front() {
        for &neighbor in qkd_graph.get(&current).into_iter().flatten() {
            if excluded.contains(&neighbor) {
                continue;
            }
            if neighbor == target {
                return Some(first_hop);
            }
            if visited.insert(neighbor) {
                queue.push_back((neighbor, first_hop));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(edges: &[(KmeId, KmeId)]) -> HashMap<KmeId, Vec<KmeId>> {
        let mut g: HashMap<KmeId, Vec<KmeId>> = HashMap::new();
        for &(a, b) in edges {
            g.entry(a).or_default().push(b);
            g.entry(b).or_default().push(a);
        }
        g
    }

    #[test]
    fn direct_qkd_link_is_one_hop() {
        let neighbors: HashSet<KmeId> = [2].into_iter().collect();
        let g = graph(&[(1, 2)]);
        let hop = compute_next_hop(1, &neighbors, 2, &g, &[]).unwrap();
        assert_eq!(hop.kme_id, 2);
        assert_eq!(hop.transport, HopTransport::QkdLink);
    }

    #[test]
    fn same_kme_has_no_next_hop() {
        let neighbors = HashSet::new();
        let g = HashMap::new();
        assert!(compute_next_hop(1, &neighbors, 1, &g, &[]).is_none());
    }

    #[test]
    fn walks_own_qkd_link_before_bridging_over_zenoh() {
        // A(1)-B1(2) QKD, B2(3)-C(4) QKD, no B1-B2 link: A must reach C via
        // A->B1(qkd)->B2(zenoh)->C(qkd), matching the project's motivating example.
        let g = graph(&[(1, 2), (3, 4)]);

        let a_neighbors: HashSet<KmeId> = [2].into_iter().collect();
        let hop = compute_next_hop(1, &a_neighbors, 4, &g, &[]).unwrap();
        assert_eq!(hop.kme_id, 2);
        assert_eq!(hop.transport, HopTransport::QkdLink);

        let b1_neighbors: HashSet<KmeId> = [1].into_iter().collect();
        let hop = compute_next_hop(2, &b1_neighbors, 4, &g, &[1]).unwrap();
        assert_eq!(hop.kme_id, 3);
        assert_eq!(hop.transport, HopTransport::Zenoh);

        let b2_neighbors: HashSet<KmeId> = [4].into_iter().collect();
        let hop = compute_next_hop(3, &b2_neighbors, 4, &g, &[1, 2]).unwrap();
        assert_eq!(hop.kme_id, 4);
        assert_eq!(hop.transport, HopTransport::QkdLink);
    }

    #[test]
    fn prefers_qkd_bfs_path_within_shared_component() {
        // 1-2-3 all QKD-linked in a chain: from 1 to 3 the path goes through 2.
        let neighbors: HashSet<KmeId> = [2].into_iter().collect();
        let g = graph(&[(1, 2), (2, 3)]);
        let hop = compute_next_hop(1, &neighbors, 3, &g, &[]).unwrap();
        assert_eq!(hop.kme_id, 2);
        assert_eq!(hop.transport, HopTransport::QkdLink);
    }

    #[test]
    fn bridges_directly_when_target_has_no_qkd_links() {
        let neighbors: HashSet<KmeId> = HashSet::new();
        let g = HashMap::new();
        let hop = compute_next_hop(1, &neighbors, 5, &g, &[]).unwrap();
        assert_eq!(hop.kme_id, 5);
        assert_eq!(hop.transport, HopTransport::Zenoh);
    }
}
