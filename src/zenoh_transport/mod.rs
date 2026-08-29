//! Zenoh transport skeleton.
//!
//! This module keeps the transport boundary separate from the existing HTTPS stack.
//! The implementation is intentionally minimal for now: it defines the configuration
//! and message shapes that the future Zenoh-based transport will use.

pub mod config;
pub mod contract;
pub mod messages;
pub mod raft;
/// Real (non-demo) inter-KME transport over Zenoh, replacing the classical HTTPS
/// `/keys/activate` call when `transport_mode: ZenohRaft` is configured.
pub mod inter_kme_transport;
/// Durable persistence for Raft-lite state (Phase 7), so restarts do not lose consensus.
pub(crate) mod persistence;
/// Live, shared `KmeId -> Zenoh node_id` registry, updated at runtime as new KMEs are discovered
/// over Zenoh (hot-plug support), see `registry::KmeNodeRegistry`.
pub(crate) mod registry;
/// Multi-hop key relay routing (`ZenohRaft` transport mode only), see `routing::compute_next_hop`.
pub mod routing;
pub mod runtime;

pub use runtime::ZenohTransport;