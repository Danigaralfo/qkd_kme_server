//! Zenoh transport skeleton.
//!
//! This module keeps the transport boundary separate from the existing HTTPS stack.
//! The implementation is intentionally minimal for now: it defines the configuration
//! and message shapes that the future Zenoh-based transport will use.

pub mod config;
pub mod contract;
pub mod messages;
mod probe;
pub mod raft;
pub mod runtime;

pub use runtime::ZenohTransport;