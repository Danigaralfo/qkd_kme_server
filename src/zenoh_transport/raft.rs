//! Phase 4: Raft-lite consensus for key-state transitions, over Zenoh.
//!
//! This is a minimal Raft-inspired protocol scoped specifically to
//! authorizing and replicating [`ZenohKeyState`] transitions, reusing the
//! Phase 2 contract types (`ZenohRaftTransitionRequest`/`Decision`,
//! `ZenohRaftStateUpdate`, `ZenohRaftReplicateAck`) instead of a generic
//! replicated log. It defines three roles:
//! - Leader: validates whether a proposed transition is legal, replicates it
//!   to every follower, and only commits (and unblocks the external action)
//!   once a quorum of the cluster has acknowledged it.
//! - Follower: locally validates transitions replicated by the leader, acks
//!   them, and applies the resulting state once the leader broadcasts the
//!   commit.
//! - Client: [`propose_transition`] is the entry point future business logic
//!   (e.g. `QkdManager` handling an ETSI-020 request) will call to request a
//!   transition; it always addresses the configured leader directly.
//!
//! Current, intentional limitations of this increment:
//! - Leader election is not implemented: `raft.leader_id` is a static,
//!   operator-configured value (see [`super::config::RaftConfig`]). There are
//!   no terms and no `RequestVote` RPC yet.
//! - State is kept in memory only; nothing survives a restart (persistence
//!   is a later phase).
//! - There is no sender authentication: a follower trusts any
//!   `ZenohRaftTransitionRequest` received on its own topic as coming from
//!   the configured leader. This is acceptable only because the leader is
//!   static and well-known; it will need revisiting once elections make
//!   leadership dynamic.
//! - A follower that does not ack within [`RAFT_ACK_TIMEOUT`] causes the
//!   leader to give up on that single proposal (rejecting it to the
//!   requester); this is not a persistent "down" membership tracked across
//!   proposals, so a slow/unresponsive follower is retried again on its own
//!   merits for every subsequent proposal.
//!
//! Phase 5 adds [`KeyStates`] (a shared, continuously-updated view of the
//! last Raft-committed state per key-id, fed by both the leader's commit
//! path and the follower's state-update subscriber) and
//! [`KeyLifecycleAuthorizer`]/[`RaftKeyCoordinator`], the interface business
//! logic (`key_handler.rs`) uses to consult this module before accepting a
//! sensitive key-state transition.

use crate::io_err;
use crate::KmeId;
use log::{error, info};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::config::ZenohTransportConfig;
use super::contract::{
    ZenohKeyState, ZenohRaftReplicateAck, ZenohRaftStateUpdate, ZenohRaftTransitionDecision,
    ZenohRaftTransitionRequest, ZenohTopicMap,
};
use super::persistence::RaftPersistence;

/// How long the leader waits for a quorum of acks on a single proposal
/// before giving up on it and rejecting it to the requester.
const RAFT_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the leader retries replicating a still-pending proposal toward
/// followers that have not acked it yet, so a dropped message or a follower
/// that starts late does not stall the proposal until [`RAFT_ACK_TIMEOUT`].
const RAFT_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// How long [`RaftKeyCoordinator::authorize_transition`] waits for the
/// cluster's decision before giving up.
const KEY_LIFECYCLE_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Role this node plays in the Raft-lite protocol, derived from
/// [`super::config::RaftConfig::leader_id`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RaftRole {
    Leader,
    Follower,
}

/// Determine this node's role by comparing its `node_id` against the
/// statically configured `raft.leader_id`.
fn role_for(config: &ZenohTransportConfig) -> RaftRole {
    if config.raft.leader_id.as_deref() == Some(config.node_id.as_str()) {
        RaftRole::Leader
    } else {
        RaftRole::Follower
    }
}

/// Error returned by [`next_valid_state`] when `current` is a terminal state
/// with no legal next state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateError {
    /// `DeletedOrUsed` is terminal: a key in this state cannot transition
    /// further (a new key exchange starts with a brand new key-id instead).
    NoNextState(ZenohKeyState),
}

/// The only transition legal from a given [`ZenohKeyState`], per the ETSI-020
/// key lifecycle: generated -> syncing -> in use -> deleted/used. `DeletedOrUsed`
/// is terminal: once a key reaches it, no further transition is legal for that
/// key-id.
fn next_valid_state(current: ZenohKeyState) -> Result<ZenohKeyState, StateError> {
    match current {
        ZenohKeyState::Generated => Ok(ZenohKeyState::Syncing),
        ZenohKeyState::Syncing => Ok(ZenohKeyState::InUse),
        ZenohKeyState::InUse => Ok(ZenohKeyState::DeletedOrUsed),
        ZenohKeyState::DeletedOrUsed => Err(StateError::NoNextState(current)),
    }
}

/// Whether `requested` is the single legal next state after `current`.
///
/// Always `false` once `current` is `DeletedOrUsed`, since that state is terminal.
fn is_valid_transition(current: ZenohKeyState, requested: ZenohKeyState) -> bool {
    next_valid_state(current) == Ok(requested)
}

/// A leader's outstanding proposal awaiting quorum acknowledgement.
#[derive(Debug, Clone)]
struct PendingProposal {
    /// The original (or replicated) request, kept whole so it can be
    /// re-published verbatim to followers that have not acked yet.
    request: ZenohRaftTransitionRequest,
    acks: HashSet<String>,
    /// When this proposal was first recorded, used to detect proposals that
    /// have been waiting for quorum longer than [`RAFT_ACK_TIMEOUT`].
    proposed_at: Instant,
}

/// Result of a commit, returned by [`LeaderState::record_ack`] once quorum is reached.
#[derive(Debug, Clone)]
struct CommitOutcome {
    request_id: String,
    key_id: String,
    /// State observed before the transition, carried through so the durable persistence
    /// layer (see `crate::zenoh_transport::persistence`) can record a full audit entry
    /// without needing to look anything else up.
    from_state: ZenohKeyState,
    state: ZenohKeyState,
    requester_kme: String,
    slave_kme: String,
}

/// A proposal that failed to reach quorum before [`RAFT_ACK_TIMEOUT`] elapsed.
#[derive(Debug, Clone)]
struct TimedOutProposal {
    request_id: String,
    requester_kme: String,
    /// Cluster members (other than the leader itself) that never acked this
    /// proposal before it was given up on.
    missing_followers: Vec<String>,
}

/// Pure, synchronous leader-side consensus state: outstanding proposals and
/// last-committed state per key. Kept independent of any Zenoh I/O so its
/// logic (transition validation, quorum counting) can be unit-tested
/// directly.
#[derive(Debug, Default)]
struct LeaderState {
    /// Node-ids of every cluster member, including the leader itself.
    cluster_members: Vec<String>,
    /// Last committed state for each key-id known to the leader.
    committed_states: HashMap<String, ZenohKeyState>,
    /// Outstanding proposals awaiting quorum, keyed by request-id.
    pending: HashMap<String, PendingProposal>,
}

impl LeaderState {
    fn new(cluster_members: Vec<String>) -> Self {
        Self {
            cluster_members,
            committed_states: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Last committed state for `key_id`, defaulting to `Generated` for a key never seen before.
    fn current_state(&self, key_id: &str) -> ZenohKeyState {
        self.committed_states.get(key_id).copied().unwrap_or(ZenohKeyState::Generated)
    }

    /// Number of acknowledgements (including the leader's own implicit ack) required to commit.
    fn quorum_size(&self) -> usize {
        self.cluster_members.len() / 2 + 1
    }

    /// Validate and record a client's proposed transition.
    ///
    /// On success, the leader's own implicit ack is recorded immediately
    /// (mirroring Raft's leader always counting its own vote/ack). Returns
    /// `Err` with a human-readable reason if the transition is stale or illegal.
    fn propose(&mut self, self_node_id: &str, request: &ZenohRaftTransitionRequest) -> Result<(), String> {
        let current = self.current_state(&request.key_id);
        if current != request.current_state {
            return Err(format!(
                "stale current_state for key '{}': leader has {current:?}, request claims {:?}",
                request.key_id, request.current_state
            ));
        }
        if !is_valid_transition(current, request.requested_state) {
            return Err(format!(
                "illegal transition for key '{}': {current:?} -> {:?}",
                request.key_id, request.requested_state
            ));
        }

        let mut acks = HashSet::new();
        acks.insert(self_node_id.to_string());
        self.pending.insert(
            request.request_id.clone(),
            PendingProposal {
                request: request.clone(),
                acks,
                proposed_at: Instant::now(),
            },
        );
        Ok(())
    }

    /// Record a follower's acknowledgement for `request_id`. Returns
    /// `Some(CommitOutcome)` once this ack brings the proposal to quorum
    /// (removing it from `pending` and applying it to `committed_states`),
    /// or `None` if quorum is not yet reached, the ack rejects the proposal,
    /// or `request_id` is unknown (e.g. already committed, stale, or timed out).
    fn record_ack(&mut self, request_id: &str, follower_kme: &str, accepted: bool) -> Option<CommitOutcome> {
        if !accepted {
            return None;
        }
        let quorum = self.quorum_size();
        let proposal = self.pending.get_mut(request_id)?;
        proposal.acks.insert(follower_kme.to_string());
        if proposal.acks.len() < quorum {
            return None;
        }

        let proposal = self.pending.remove(request_id)?;
        self.committed_states.insert(proposal.request.key_id.clone(), proposal.request.requested_state);
        Some(CommitOutcome {
            request_id: request_id.to_string(),
            key_id: proposal.request.key_id,
            from_state: proposal.request.current_state,
            state: proposal.request.requested_state,
            requester_kme: proposal.request.master_kme,
            slave_kme: proposal.request.slave_kme,
        })
    }

    /// Remove and return every pending proposal that has been waiting for
    /// quorum for at least `timeout`, paired with the cluster members that
    /// never acked it. Called periodically so an unresponsive follower can
    /// never block a proposal (and its requester) forever.
    fn expire_stale_proposals(&mut self, timeout: Duration) -> Vec<TimedOutProposal> {
        let stale_ids: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, proposal)| proposal.proposed_at.elapsed() >= timeout)
            .map(|(request_id, _)| request_id.clone())
            .collect();

        stale_ids
            .into_iter()
            .filter_map(|request_id| {
                let proposal = self.pending.remove(&request_id)?;
                let missing_followers = self
                    .cluster_members
                    .iter()
                    .filter(|member| !proposal.acks.contains(*member))
                    .cloned()
                    .collect();
                Some(TimedOutProposal {
                    request_id,
                    requester_kme: proposal.request.master_kme,
                    missing_followers,
                })
            })
            .collect()
    }

    /// Every still-pending proposal, paired with the cluster members that
    /// have not acked it yet. Used to retry replication toward followers
    /// that may have missed the original message, without waiting for
    /// [`RAFT_ACK_TIMEOUT`] to discard the proposal outright.
    fn pending_retries(&self) -> Vec<(ZenohRaftTransitionRequest, Vec<String>)> {
        self.pending
            .values()
            .map(|proposal| {
                let missing_followers = self
                    .cluster_members
                    .iter()
                    .filter(|member| !proposal.acks.contains(*member))
                    .cloned()
                    .collect();
                (proposal.request.clone(), missing_followers)
            })
            .collect()
    }
}

/// In-memory, per-key committed state kept by a follower.
type KeyStateStore = Arc<Mutex<HashMap<String, ZenohKeyState>>>;

/// Shared, continuously-updated view of the last Raft-committed state for
/// each key-id, readable by business logic outside this module.
///
/// Fed by this node's own Raft role: on the leader by
/// [`spawn_leader_ack_subscriber`]'s commit path, on a follower by
/// [`spawn_follower_state_update_subscriber`]'s applied updates. A key with
/// no entry has not had any transition committed yet (implicitly `Generated`).
#[derive(Clone, Default)]
pub struct KeyStates(KeyStateStore);

impl KeyStates {
    /// A fresh, empty view (no key has a committed state yet).
    pub fn new() -> Self {
        Self::default()
    }

    /// Last Raft-committed state for `key_id`, or `None` if nothing has been
    /// committed for it yet.
    pub fn get(&self, key_id: &str) -> Option<ZenohKeyState> {
        self.0.lock().unwrap().get(key_id).copied()
    }

    /// Record the last Raft-committed state for `key_id`.
    fn set(&self, key_id: &str, state: ZenohKeyState) {
        self.0.lock().unwrap().insert(key_id.to_string(), state);
    }
}

/// Authorizes QKD key-state transitions against Raft consensus before
/// business logic (`key_handler.rs`) commits them locally.
///
/// Implemented by [`RaftKeyCoordinator`] for real deployments; test code can
/// provide a fake implementation instead of standing up a real Zenoh session.
pub trait KeyLifecycleAuthorizer: Send + Sync {
    /// Ask the Raft leader to authorize moving `key_id` to `requested_state`,
    /// addressed to `slave_kme` as the peer that will receive the key.
    /// Updates the coordinator's own view of `key_id`'s state on success.
    fn authorize_transition<'a>(
        &'a self,
        key_id: &'a str,
        slave_kme: &'a str,
        requested_state: ZenohKeyState,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + 'a>>;

    /// Last Raft-committed state for `key_id`, or `None` if nothing has been
    /// committed for it yet. A read-only check, unlike `authorize_transition`,
    /// for callers that only need to verify a state another node already
    /// committed (e.g. the slave side of a cross-KME activation).
    fn current_state(&self, key_id: &str) -> Option<ZenohKeyState>;
}

/// Bridges QKD business logic to this module's Raft-lite consensus: the
/// concrete, Zenoh-backed [`KeyLifecycleAuthorizer`].
#[derive(Clone)]
pub struct RaftKeyCoordinator {
    config: ZenohTransportConfig,
    session: zenoh::Session,
    key_states: KeyStates,
}

impl RaftKeyCoordinator {
    /// Build a coordinator over an already-running Raft node.
    /// # Arguments
    /// * `config` - This node's Zenoh transport configuration (used to reach the configured leader).
    /// * `session` - The already-open Zenoh session shared with the rest of the transport.
    /// * `key_states` - The shared committed-state view returned by [`spawn`].
    pub fn new(config: ZenohTransportConfig, session: zenoh::Session, key_states: KeyStates) -> Self {
        Self { config, session, key_states }
    }
}

impl KeyLifecycleAuthorizer for RaftKeyCoordinator {
    fn authorize_transition<'a>(
        &'a self,
        key_id: &'a str,
        slave_kme: &'a str,
        requested_state: ZenohKeyState,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let current_state = self.key_states.get(key_id).unwrap_or(ZenohKeyState::Generated);
            // Fast local rejection: never even ask the leader to reuse a terminated key-id.
            if current_state == ZenohKeyState::DeletedOrUsed {
                return Err(io_err(&format!("Key '{key_id}' is already deleted/used; it cannot be transitioned again")));
            }
            // `slave_kme` here is the numeric `KmeId` stringified by the caller (see
            // `key_handler.rs`); resolve it to the real Zenoh `node_id` (if known) so the state
            // update broadcast can actually reach it later, even if it's not a Raft cluster member
            // (e.g. a hot-plugged KME that only acts as a Raft client - see
            // `spawn_leader_ack_subscriber`).
            let resolved_slave_kme = slave_kme.parse::<KmeId>().ok()
                .and_then(|kme_id| self.config.other_kme_node_ids.get(&kme_id).cloned())
                .unwrap_or_else(|| slave_kme.to_string());
            let decision = propose_transition_and_await_decision(
                &self.config,
                &self.session,
                key_id,
                resolved_slave_kme.as_str(),
                current_state,
                requested_state,
                KEY_LIFECYCLE_AUTHORIZATION_TIMEOUT,
            )
            .await?;
            if !decision.accepted {
                return Err(io_err(&format!("Raft cluster rejected transition of key '{key_id}' to {requested_state:?}: {:?}", decision.reason)));
            }
            self.key_states.set(key_id, requested_state);
            Ok(())
        })
    }

    fn current_state(&self, key_id: &str) -> Option<ZenohKeyState> {
        self.key_states.get(key_id)
    }
}

/// Start the Raft-lite protocol on top of an already-initialized Zenoh
/// session, dispatching to the leader or follower behavior based on
/// `config.raft.leader_id`. Returns a [`KeyStates`] view that is kept
/// up to date with every commit this node observes (as leader or follower),
/// for business logic to consult via [`RaftKeyCoordinator`].
///
/// `persistence` (Phase 7) is used to restore this node's last committed key states before
/// any subscriber starts, and to durably record every future commit - see
/// `crate::zenoh_transport::persistence` for the rationale and what is/isn't persisted.
pub(super) async fn spawn(config: &ZenohTransportConfig, session: &zenoh::Session, persistence: RaftPersistence) -> Result<KeyStates, io::Error> {
    match role_for(config) {
        RaftRole::Leader => spawn_leader(config, session, persistence).await,
        RaftRole::Follower => spawn_follower(config, session, persistence).await,
    }
}

async fn spawn_leader(config: &ZenohTransportConfig, session: &zenoh::Session, persistence: RaftPersistence) -> Result<KeyStates, io::Error> {
    let node_id = config.node_id.clone();
    let followers: Vec<String> = config.raft.cluster_members.iter().filter(|member| *member != &node_id).cloned().collect();

    let restored_states = persistence.load_all_key_states().await?;
    info!(
        "Zenoh Raft: node '{}' restored {} persisted key state(s) from durable storage",
        node_id,
        restored_states.len()
    );
    let mut leader_state = LeaderState::new(config.raft.cluster_members.clone());
    leader_state.committed_states = restored_states.clone();
    let state = Arc::new(Mutex::new(leader_state));
    let key_states = KeyStates::new();
    for (key_id, key_state) in restored_states {
        key_states.set(key_id.as_str(), key_state);
    }

    info!(
        "Zenoh Raft: node '{}' starting as leader over cluster {:?} (quorum {})",
        node_id,
        config.raft.cluster_members,
        state.lock().unwrap().quorum_size()
    );

    spawn_leader_request_subscriber(node_id.clone(), session.clone(), followers.clone(), state.clone()).await?;
    spawn_leader_ack_subscriber(node_id.clone(), session.clone(), followers.clone(), state.clone(), key_states.clone(), persistence).await?;
    spawn_leader_retry_and_timeout_task(node_id, session.clone(), followers, state);
    Ok(key_states)
}

async fn spawn_follower(config: &ZenohTransportConfig, session: &zenoh::Session, persistence: RaftPersistence) -> Result<KeyStates, io::Error> {
    let node_id = config.node_id.clone();
    let leader_id = match config.raft.leader_id.clone() {
        Some(leader_id) => leader_id,
        None => {
            error!("Zenoh Raft: node '{}' has no configured raft.leader_id; cannot start as a follower", node_id);
            return Ok(KeyStates::new());
        }
    };
    info!("Zenoh Raft: node '{}' starting as follower of leader '{}'", node_id, leader_id);

    let restored_states = persistence.load_all_key_states().await?;
    info!(
        "Zenoh Raft: node '{}' restored {} persisted key state(s) from durable storage",
        node_id,
        restored_states.len()
    );
    let key_states = KeyStates::new();
    for (key_id, key_state) in restored_states {
        key_states.set(key_id.as_str(), key_state);
    }

    spawn_follower_request_subscriber(node_id.clone(), session.clone(), leader_id, key_states.clone(), persistence.clone()).await?;
    spawn_follower_state_update_subscriber(node_id, session.clone(), key_states.clone(), persistence).await?;
    Ok(key_states)
}

/// Leader-side background task: periodically gives up on proposals that
/// have not reached quorum within [`RAFT_ACK_TIMEOUT`] (rejecting them to
/// their requester and logging which followers never acked), and retries
/// replicating still-pending proposals toward followers that have not
/// acked yet. Runs for as long as this node is the leader, independently of
/// (and without blocking) the request/ack subscribers.
fn spawn_leader_retry_and_timeout_task(node_id: String, session: zenoh::Session, followers: Vec<String>, state: Arc<Mutex<LeaderState>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RAFT_RETRY_INTERVAL);
        loop {
            interval.tick().await;

            let timed_out = { state.lock().unwrap().expire_stale_proposals(RAFT_ACK_TIMEOUT) };
            for timeout in timed_out {
                error!(
                    "Zenoh Raft leader '{}': proposal '{}' timed out waiting for quorum after {:?}; followers never acked: {:?}",
                    node_id, timeout.request_id, RAFT_ACK_TIMEOUT, timeout.missing_followers
                );
                let decision = ZenohRaftTransitionDecision {
                    request_id: timeout.request_id.clone(),
                    accepted: false,
                    reason: Some(format!("timed out waiting for acks from: {:?}", timeout.missing_followers)),
                };
                let decision_topic = ZenohTopicMap::raft_transition_decision_topic(timeout.requester_kme.as_str());
                if let Err(e) = publish_json(&session, decision_topic.as_str(), &decision, "Zenoh Raft timeout decision").await {
                    error!("Zenoh Raft leader '{}': failed to publish timeout decision for '{}': {e}", node_id, timeout.request_id);
                }
            }

            let retries = { state.lock().unwrap().pending_retries() };
            for (request, missing_followers) in retries {
                for follower in &missing_followers {
                    if !followers.contains(follower) {
                        continue; // the leader's own implicit ack, not a real follower to retry toward
                    }
                    let follower_topic = ZenohTopicMap::raft_transition_request_topic(follower.as_str());
                    match publish_json(&session, follower_topic.as_str(), &request, "Zenoh Raft proposal retry").await {
                        Ok(()) => info!(
                            "Zenoh Raft leader '{}': retried proposal '{}' toward unresponsive follower '{}'",
                            node_id, request.request_id, follower
                        ),
                        Err(e) => error!(
                            "Zenoh Raft leader '{}': failed to retry proposal '{}' toward '{}': {e}",
                            node_id, request.request_id, follower
                        ),
                    }
                }
            }
        }
    });
}

/// Leader-side: subscribe to this node's own transition-request topic, where
/// clients propose transitions. Valid proposals are replicated to every
/// follower; invalid ones are rejected immediately with a `ZenohRaftTransitionDecision`.
async fn spawn_leader_request_subscriber(
    node_id: String,
    session: zenoh::Session,
    followers: Vec<String>,
    state: Arc<Mutex<LeaderState>>,
) -> Result<(), io::Error> {
    let topic = ZenohTopicMap::raft_transition_request_topic(node_id.as_str());
    let subscriber = session
        .declare_subscriber(topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    tokio::spawn(async move {
        while let Ok(sample) = subscriber.recv_async().await {
            match sample.payload().try_to_string() {    // If payload is not readable, discard and left
                Ok(payload) => match serde_json::from_str::<ZenohRaftTransitionRequest>(&payload) {
                    Ok(request) => {
                        let outcome = {
                            let mut state = state.lock().unwrap();
                            state.propose(node_id.as_str(), &request)
                        };
                        match outcome {
                            Ok(()) => {
                                info!(
                                    "Zenoh Raft leader '{}': accepted proposal '{}' for key '{}' ({:?} -> {:?}), replicating to {:?}",
                                    node_id, request.request_id, request.key_id, request.current_state, request.requested_state, followers
                                );
                                for follower in &followers {
                                    let follower_topic = ZenohTopicMap::raft_transition_request_topic(follower.as_str());
                                    if let Err(e) = publish_json(&session, follower_topic.as_str(), &request, "Zenoh Raft replicated proposal").await {
                                        error!("Zenoh Raft leader '{}': failed to replicate proposal '{}' to '{}': {e}", node_id, request.request_id, follower);
                                    }
                                }
                            }
                            Err(reason) => {
                                info!(
                                    "Zenoh Raft leader '{}': rejected proposal '{}' for key '{}': {reason}",
                                    node_id, request.request_id, request.key_id
                                );
                                let decision = ZenohRaftTransitionDecision {
                                    request_id: request.request_id.clone(),
                                    accepted: false,
                                    reason: Some(reason),
                                };
                                let decision_topic = ZenohTopicMap::raft_transition_decision_topic(request.master_kme.as_str());
                                if let Err(e) = publish_json(&session, decision_topic.as_str(), &decision, "Zenoh Raft decision").await {
                                    error!("Zenoh Raft leader '{}': failed to publish rejection for '{}': {e}", node_id, request.request_id);
                                }
                            }
                        }
                    }
                    Err(e) => error!("Zenoh Raft leader '{}' <- cannot parse proposal on '{topic}': {e}", node_id),
                },
                Err(_) => info!("Zenoh Raft leader '{}' <- received non-UTF8 proposal on '{topic}'", node_id),
            }
        }
        error!("Zenoh Raft leader '{}' proposal subscriber loop ended unexpectedly", node_id);
    });

    Ok(())
}

/// Leader-side: subscribe to this node's own replicate-ack topic, where
/// followers acknowledge replicated proposals. Once a proposal reaches
/// quorum, broadcast the commit to every follower and the acceptance
/// decision to the original requester.
async fn spawn_leader_ack_subscriber(
    node_id: String,
    session: zenoh::Session,
    followers: Vec<String>,
    state: Arc<Mutex<LeaderState>>,
    key_states: KeyStates,
    persistence: RaftPersistence,
) -> Result<(), io::Error> {
    let topic = ZenohTopicMap::raft_replicate_ack_topic(node_id.as_str());
    let subscriber = session
        .declare_subscriber(topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    tokio::spawn(async move {
        while let Ok(sample) = subscriber.recv_async().await {
            match sample.payload().try_to_string() {
                Ok(payload) => match serde_json::from_str::<ZenohRaftReplicateAck>(&payload) {
                    Ok(ack) => {
                        info!(
                            "Zenoh Raft leader '{}' <- received ack from follower '{}' for proposal '{}' (accepted={})",
                            node_id, ack.follower_kme, ack.request_id, ack.accepted
                        );
                        if !ack.accepted {
                            info!(
                                "Zenoh Raft leader '{}': follower '{}' rejected proposal '{}' locally",
                                node_id, ack.follower_kme, ack.request_id
                            );
                        }
                        let commit = {
                            let mut state = state.lock().unwrap();
                            state.record_ack(ack.request_id.as_str(), ack.follower_kme.as_str(), ack.accepted)
                        };
                        if let Some(commit) = commit {
                            info!(
                                "Zenoh Raft leader '{}': committed proposal '{}' for key '{}' -> {:?}",
                                node_id, commit.request_id, commit.key_id, commit.state
                            );
                            key_states.set(commit.key_id.as_str(), commit.state);
                            // Persist before broadcasting: on restart, this node must never forget
                            // a transition it has already told the rest of the cluster about.
                            if let Err(e) = persistence
                                .record_commit(
                                    commit.request_id.as_str(),
                                    commit.key_id.as_str(),
                                    commit.from_state,
                                    commit.state,
                                    commit.requester_kme.as_str(),
                                    commit.slave_kme.as_str(),
                                )
                                .await
                            {
                                error!("Zenoh Raft leader '{}': failed to durably persist commit '{}': {e}", node_id, commit.request_id);
                            }
                            let state_update = ZenohRaftStateUpdate {
                                request_id: commit.request_id.clone(),
                                key_id: commit.key_id.clone(),
                                from_state: commit.from_state,
                                state: commit.state,
                                master_kme: commit.requester_kme.clone(),
                                slave_kme: commit.slave_kme.clone(),
                                committed: true,
                            };
                            for follower in &followers {
                                let follower_topic = ZenohTopicMap::raft_state_update_topic(follower.as_str());
                                if let Err(e) = publish_json(&session, follower_topic.as_str(), &state_update, "Zenoh Raft state update").await {
                                    error!("Zenoh Raft leader '{}': failed to publish state update to '{}': {e}", node_id, follower);
                                }
                            }
                            // Always also reach the actual slave of this transaction, even if it's
                            // not a Raft cluster member (e.g. a hot-plugged KME acting only as a
                            // Raft client - see `RaftKeyCoordinator::authorize_transition`, which
                            // already resolved `slave_kme` to a real node_id): without this, that
                            // node's own local Raft gate (`current_state`) would never learn about
                            // the commit and would wrongly reject storing the synced key.
                            if commit.slave_kme != node_id && !followers.contains(&commit.slave_kme) {
                                let slave_topic = ZenohTopicMap::raft_state_update_topic(commit.slave_kme.as_str());
                                if let Err(e) = publish_json(&session, slave_topic.as_str(), &state_update, "Zenoh Raft state update").await {
                                    error!("Zenoh Raft leader '{}': failed to publish state update to slave '{}': {e}", node_id, commit.slave_kme);
                                }
                            }
                            let decision = ZenohRaftTransitionDecision {
                                request_id: commit.request_id,
                                accepted: true,
                                reason: None,
                            };
                            let decision_topic = ZenohTopicMap::raft_transition_decision_topic(commit.requester_kme.as_str());
                            if let Err(e) = publish_json(&session, decision_topic.as_str(), &decision, "Zenoh Raft decision").await {
                                error!("Zenoh Raft leader '{}': failed to publish acceptance decision: {e}", node_id);
                            }
                        }
                    }
                    Err(e) => error!("Zenoh Raft leader '{}' <- cannot parse ack on '{topic}': {e}", node_id),
                },
                Err(_) => info!("Zenoh Raft leader '{}' <- received non-UTF8 ack on '{topic}'", node_id),
            }
        }
        error!("Zenoh Raft leader '{}' ack subscriber loop ended unexpectedly", node_id);
    });

    Ok(())
}

/// Follower-side: subscribe to this node's own transition-request topic,
/// where the leader replicates proposals. Every received proposal is
/// validated locally and acknowledged back to the leader; it is not applied
/// yet (only the leader's later commit broadcast applies it).
async fn spawn_follower_request_subscriber(
    node_id: String,
    session: zenoh::Session,
    leader_id: String,
    local_states: KeyStates,
    persistence: RaftPersistence,
) -> Result<(), io::Error> {
    let topic = ZenohTopicMap::raft_transition_request_topic(node_id.as_str());
    let subscriber = session
        .declare_subscriber(topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    tokio::spawn(async move {
        while let Ok(sample) = subscriber.recv_async().await {
            match sample.payload().try_to_string() {
                Ok(payload) => match serde_json::from_str::<ZenohRaftTransitionRequest>(&payload) {
                    Ok(request) => {
                        // A request_id already durably committed means the leader is replaying a
                        // proposal this follower actually accepted before (its earlier ack was
                        // likely lost). This node's local state has since moved on past
                        // `request.current_state`, so re-validating against it would wrongly
                        // reject a proposal already applied - just re-ack it as accepted instead.
                        let already_committed = match persistence.is_request_already_committed(request.request_id.as_str()).await {
                            Ok(already_committed) => already_committed,
                            Err(e) => {
                                error!(
                                    "Zenoh Raft follower '{}': failed to check persisted history for '{}': {e}",
                                    node_id, request.request_id
                                );
                                false
                            }
                        };
                        let accepted = if already_committed {
                            true
                        } else {
                            let current = local_states.get(request.key_id.as_str()).unwrap_or(ZenohKeyState::Generated);
                            let accepted = current == request.current_state && is_valid_transition(current, request.requested_state);
                            if !accepted {
                                error!(
                                    "Zenoh Raft follower '{}': rejecting replicated proposal '{}' for key '{}' (local state {:?}, request claims {:?} -> {:?})",
                                    node_id, request.request_id, request.key_id, current, request.current_state, request.requested_state
                                );
                            }
                            accepted
                        };
                        let ack = ZenohRaftReplicateAck {
                            request_id: request.request_id.clone(),
                            follower_kme: node_id.clone(),
                            accepted,
                        };
                        let ack_topic = ZenohTopicMap::raft_replicate_ack_topic(leader_id.as_str());
                        if let Err(e) = publish_json(&session, ack_topic.as_str(), &ack, "Zenoh Raft ack").await {
                            error!("Zenoh Raft follower '{}': failed to publish ack for '{}': {e}", node_id, request.request_id);
                        }
                    }
                    Err(e) => error!("Zenoh Raft follower '{}' <- cannot parse proposal on '{topic}': {e}", node_id),
                },
                Err(_) => info!("Zenoh Raft follower '{}' <- received non-UTF8 proposal on '{topic}'", node_id),
            }
        }
        error!("Zenoh Raft follower '{}' proposal subscriber loop ended unexpectedly", node_id);
    });

    Ok(())
}

/// Follower-side: subscribe to this node's own state-update topic, where the
/// leader broadcasts commits. Only committed updates are applied to the
/// local key-state store; this is what gates any external action on the
/// follower until the leader has confirmed quorum.
async fn spawn_follower_state_update_subscriber(
    node_id: String,
    session: zenoh::Session,
    local_states: KeyStates,
    persistence: RaftPersistence,
) -> Result<(), io::Error> {
    let topic = ZenohTopicMap::raft_state_update_topic(node_id.as_str());
    let subscriber = session
        .declare_subscriber(topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    tokio::spawn(async move {
        while let Ok(sample) = subscriber.recv_async().await {
            match sample.payload().try_to_string() {
                Ok(payload) => match serde_json::from_str::<ZenohRaftStateUpdate>(&payload) {
                    Ok(update) => {
                        if update.committed {
                            local_states.set(update.key_id.as_str(), update.state);
                            if let Err(e) = persistence
                                .record_commit(
                                    update.request_id.as_str(),
                                    update.key_id.as_str(),
                                    update.from_state,
                                    update.state,
                                    update.master_kme.as_str(),
                                    update.slave_kme.as_str(),
                                )
                                .await
                            {
                                error!(
                                    "Zenoh Raft follower '{}': failed to durably persist commit '{}': {e}",
                                    node_id, update.request_id
                                );
                            }
                            info!(
                                "Zenoh Raft follower '{}': applied committed transition '{}' for key '{}' -> {:?}",
                                node_id, update.request_id, update.key_id, update.state
                            );
                        }
                    }
                    Err(e) => error!("Zenoh Raft follower '{}' <- cannot parse state update on '{topic}': {e}", node_id),
                },
                Err(_) => info!("Zenoh Raft follower '{}' <- received non-UTF8 state update on '{topic}'", node_id),
            }
        }
        error!("Zenoh Raft follower '{}' state update subscriber loop ended unexpectedly", node_id);
    });

    Ok(())
}

/// Act as a Raft client: propose a key-state transition to the configured leader.
///
/// `config.node_id` is always the `master_kme` (the requester, who holds the
/// key material); `slave_kme` identifies the remote peer that will receive
/// it. The two must never be the same node.
///
/// This is the entry point future business logic (e.g. `QkdManager` handling
/// an ETSI-020 request) will call. It always addresses the statically
/// configured leader directly; it does not implement request forwarding or
/// leader redirection, since leader election is not implemented yet.
pub async fn propose_transition(
    config: &ZenohTransportConfig,
    session: &zenoh::Session,
    key_id: &str,
    slave_kme: &str,
    current_state: ZenohKeyState,
    requested_state: ZenohKeyState,
) -> Result<(), io::Error> {
    let leader_id = config
        .raft
        .leader_id
        .as_deref()
        .ok_or_else(|| io_err("Cannot propose a Raft transition: no raft.leader_id configured"))?;

    let request = ZenohRaftTransitionRequest {
        request_id: Uuid::new_v4().to_string(),
        key_id: key_id.to_string(),
        master_kme: config.node_id.clone(),
        slave_kme: slave_kme.to_string(),
        current_state,
        requested_state,
    };
    let topic = ZenohTopicMap::raft_transition_request_topic(leader_id);
    publish_json(session, topic.as_str(), &request, "Zenoh Raft client proposal").await
}

/// Act as a Raft client and wait for the outcome: propose a key-state
/// transition to the configured leader, then block (up to `timeout`) until
/// this node's own `ZenohRaftTransitionDecision` for that proposal arrives.
///
/// `config.node_id` is always the `master_kme` (the requester, who holds the
/// key material); `slave_kme` identifies the remote peer that will receive
/// it. The two must never be the same node.
///
/// This is what a caller needs when the action gated by the transition (e.g.
/// publishing key material on the ETSI-020 plane) must not proceed until the
/// cluster has actually committed the change, rather than firing the
/// proposal and moving on like [`propose_transition`] does.
pub async fn propose_transition_and_await_decision(
    config: &ZenohTransportConfig,
    session: &zenoh::Session,
    key_id: &str,
    slave_kme: &str,
    current_state: ZenohKeyState,
    requested_state: ZenohKeyState,
    timeout: Duration,
) -> Result<ZenohRaftTransitionDecision, io::Error> {
    let leader_id = config
        .raft
        .leader_id
        .as_deref()
        .ok_or_else(|| io_err("Cannot propose a Raft transition: no raft.leader_id configured"))?;

    // Subscribe to our own decision topic *before* publishing the proposal,
    // so a fast leader (possibly this very node) can never answer before we
    // start listening for it.
    let decision_topic = ZenohTopicMap::raft_transition_decision_topic(config.node_id.as_str());
    let subscriber = session
        .declare_subscriber(decision_topic.as_str())
        .await
        .map_err(|e| io_err(&format!("Cannot declare Zenoh subscriber: {e}")))?;

    let request = ZenohRaftTransitionRequest {
        request_id: Uuid::new_v4().to_string(),
        key_id: key_id.to_string(),
        master_kme: config.node_id.clone(),
        slave_kme: slave_kme.to_string(),
        current_state,
        requested_state,
    };
    let request_topic = ZenohTopicMap::raft_transition_request_topic(leader_id);
    publish_json(session, request_topic.as_str(), &request, "Zenoh Raft client proposal").await?;

    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io_err(&format!("Timed out waiting for a Raft decision on request '{}'", request.request_id)));
        }
        let sample = match tokio::time::timeout(remaining, subscriber.recv_async()).await {
            Ok(Ok(sample)) => sample,
            Ok(Err(_)) => return Err(io_err("Zenoh Raft decision subscriber closed unexpectedly")),
            Err(_) => return Err(io_err(&format!("Timed out waiting for a Raft decision on request '{}'", request.request_id))),
        };
        match sample.payload().try_to_string() {
            Ok(payload) => match serde_json::from_str::<ZenohRaftTransitionDecision>(&payload) {
                Ok(decision) if decision.request_id == request.request_id => return Ok(decision),
                Ok(_unrelated_decision) => continue,
                Err(e) => error!("Zenoh Raft client '{}' <- cannot parse decision on '{decision_topic}': {e}", config.node_id),
            },
            Err(_) => info!("Zenoh Raft client '{}' <- received non-UTF8 decision on '{decision_topic}'", config.node_id),
        }
    }
}

async fn publish_json<T>(session: &zenoh::Session, topic: &str, payload: &T, label: &str) -> Result<(), io::Error>
where
    T: serde::Serialize,
{
    let payload_json = serde_json::to_string(payload).map_err(|e| io_err(&format!("Cannot serialize {label}: {e}")))?;
    info!("{label} -> publishing on '{topic}': {payload_json}");
    session.put(topic, payload_json.as_str()).await.map_err(|e| io_err(&format!("Cannot publish {label}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(key_id: &str, current: ZenohKeyState, requested: ZenohKeyState) -> ZenohRaftTransitionRequest {
        ZenohRaftTransitionRequest {
            request_id: Uuid::new_v4().to_string(),
            key_id: key_id.to_string(),
            master_kme: String::from("kme-client"),
            slave_kme: String::from("kme-client"),
            current_state: current,
            requested_state: requested,
        }
    }

    #[test]
    fn transition_table_only_allows_the_defined_chain() {
        assert!(is_valid_transition(ZenohKeyState::Generated, ZenohKeyState::Syncing));
        assert!(is_valid_transition(ZenohKeyState::Syncing, ZenohKeyState::InUse));
        assert!(is_valid_transition(ZenohKeyState::InUse, ZenohKeyState::DeletedOrUsed));

        assert!(!is_valid_transition(ZenohKeyState::Generated, ZenohKeyState::InUse));
        assert!(!is_valid_transition(ZenohKeyState::Syncing, ZenohKeyState::Generated));
    }

    #[test]
    fn deleted_or_used_is_a_terminal_state() {
        assert_eq!(next_valid_state(ZenohKeyState::DeletedOrUsed), Err(StateError::NoNextState(ZenohKeyState::DeletedOrUsed)));
        assert!(!is_valid_transition(ZenohKeyState::DeletedOrUsed, ZenohKeyState::Generated));
        assert!(!is_valid_transition(ZenohKeyState::DeletedOrUsed, ZenohKeyState::Syncing));
        assert!(!is_valid_transition(ZenohKeyState::DeletedOrUsed, ZenohKeyState::InUse));
        assert!(!is_valid_transition(ZenohKeyState::DeletedOrUsed, ZenohKeyState::DeletedOrUsed));
    }

    #[test]
    fn role_for_matches_configured_leader_id() {
        let mut config = ZenohTransportConfig {
            node_id: String::from("kme-1"),
            ..Default::default()
        };
        config.raft.leader_id = Some(String::from("kme-1"));
        assert_eq!(role_for(&config), RaftRole::Leader);

        config.raft.leader_id = Some(String::from("kme-2"));
        assert_eq!(role_for(&config), RaftRole::Follower);
    }

    #[test]
    fn leader_rejects_illegal_transition() {
        let mut state = LeaderState::new(vec![String::from("kme-1"), String::from("kme-2")]);
        let request = sample_request("key-1", ZenohKeyState::Generated, ZenohKeyState::InUse);
        assert!(state.propose("kme-1", &request).is_err());
    }

    #[test]
    fn leader_rejects_stale_current_state() {
        let mut state = LeaderState::new(vec![String::from("kme-1"), String::from("kme-2")]);
        // Leader believes key-1 is still Generated (default), but the request claims Syncing.
        let request = sample_request("key-1", ZenohKeyState::Syncing, ZenohKeyState::InUse);
        assert!(state.propose("kme-1", &request).is_err());
    }

    #[test]
    fn leader_rejects_any_transition_once_key_is_deleted_or_used() {
        let mut state = LeaderState::new(vec![String::from("kme-1"), String::from("kme-2")]);
        for (current, requested) in [
            (ZenohKeyState::Generated, ZenohKeyState::Syncing),
            (ZenohKeyState::Syncing, ZenohKeyState::InUse),
            (ZenohKeyState::InUse, ZenohKeyState::DeletedOrUsed),
        ] {
            let request = sample_request("key-1", current, requested);
            state.propose("kme-1", &request).unwrap();
            state.record_ack(&request.request_id, "kme-2", true).expect("quorum reached");
        }
        assert_eq!(state.current_state("key-1"), ZenohKeyState::DeletedOrUsed);

        // The key is now terminal: no further transition, including back to
        // Generated, is accepted for the same key-id.
        let next_attempt = sample_request("key-1", ZenohKeyState::DeletedOrUsed, ZenohKeyState::Generated);
        assert!(state.propose("kme-1", &next_attempt).is_err());
    }

    #[test]
    fn two_node_cluster_requires_both_leader_and_follower_ack() {
        let mut state = LeaderState::new(vec![String::from("kme-1"), String::from("kme-2")]);
        let request = sample_request("key-1", ZenohKeyState::Generated, ZenohKeyState::Syncing);
        state.propose("kme-1", &request).unwrap();

        assert_eq!(state.quorum_size(), 2);
        assert!(state.pending.contains_key(&request.request_id));

        let commit = state.record_ack(&request.request_id, "kme-2", true);
        let commit = commit.expect("quorum of 2 reached after the only follower acks");
        assert_eq!(commit.key_id, "key-1");
        assert_eq!(commit.state, ZenohKeyState::Syncing);
        assert_eq!(state.current_state("key-1"), ZenohKeyState::Syncing);
        assert!(!state.pending.contains_key(&request.request_id));
    }

    #[test]
    fn three_node_cluster_commits_at_majority_without_every_follower() {
        let mut state = LeaderState::new(vec![String::from("kme-1"), String::from("kme-2"), String::from("kme-3")]);
        let request = sample_request("key-1", ZenohKeyState::Generated, ZenohKeyState::Syncing);
        state.propose("kme-1", &request).unwrap();

        assert_eq!(state.quorum_size(), 2);
        // Leader's implicit self-ack already counts as 1; one follower ack reaches quorum.
        let commit = state.record_ack(&request.request_id, "kme-2", true);
        assert!(commit.is_some());
    }

    #[test]
    fn rejected_follower_ack_does_not_count_toward_quorum() {
        let mut state = LeaderState::new(vec![String::from("kme-1"), String::from("kme-2")]);
        let request = sample_request("key-1", ZenohKeyState::Generated, ZenohKeyState::Syncing);
        state.propose("kme-1", &request).unwrap();

        let commit = state.record_ack(&request.request_id, "kme-2", false);
        assert!(commit.is_none());
        assert!(state.pending.contains_key(&request.request_id));
    }

    #[test]
    fn ack_for_unknown_request_id_is_ignored() {
        let mut state = LeaderState::new(vec![String::from("kme-1"), String::from("kme-2")]);
        assert!(state.record_ack("does-not-exist", "kme-2", true).is_none());
    }

    #[test]
    fn expire_stale_proposals_after_timeout_rejects_and_reports_missing_followers() {
        let mut state = LeaderState::new(vec![String::from("kme-1"), String::from("kme-2"), String::from("kme-3")]);
        let request = sample_request("key-1", ZenohKeyState::Generated, ZenohKeyState::Syncing);
        state.propose("kme-1", &request).unwrap();

        // A zero timeout means "anything that has been pending at all", simulating time having passed.
        let mut timed_out = state.expire_stale_proposals(Duration::ZERO);
        assert_eq!(timed_out.len(), 1);
        let timed_out = timed_out.remove(0);
        assert_eq!(timed_out.request_id, request.request_id);
        assert_eq!(timed_out.requester_kme, "kme-client");
        let mut missing = timed_out.missing_followers;
        missing.sort();
        assert_eq!(missing, vec![String::from("kme-2"), String::from("kme-3")]);
        assert!(!state.pending.contains_key(&request.request_id));
    }

    #[test]
    fn expire_stale_proposals_keeps_proposals_within_the_timeout() {
        let mut state = LeaderState::new(vec![String::from("kme-1"), String::from("kme-2")]);
        let request = sample_request("key-1", ZenohKeyState::Generated, ZenohKeyState::Syncing);
        state.propose("kme-1", &request).unwrap();

        let timed_out = state.expire_stale_proposals(Duration::from_secs(3600));
        assert!(timed_out.is_empty());
        assert!(state.pending.contains_key(&request.request_id));
    }

    #[test]
    fn pending_retries_lists_only_followers_that_have_not_acked() {
        let mut state = LeaderState::new(vec![
            String::from("kme-1"),
            String::from("kme-2"),
            String::from("kme-3"),
            String::from("kme-4"),
        ]);
        let request = sample_request("key-1", ZenohKeyState::Generated, ZenohKeyState::Syncing);
        state.propose("kme-1", &request).unwrap();
        // Quorum for 4 members is 3; leader self-ack (1) + kme-2 (2) is not enough yet.
        assert_eq!(state.quorum_size(), 3);
        assert!(state.record_ack(&request.request_id, "kme-2", true).is_none());

        let retries = state.pending_retries();
        assert_eq!(retries.len(), 1);
        let (retried_request, mut missing) = retries[0].clone();
        assert_eq!(retried_request.request_id, request.request_id);
        missing.sort();
        assert_eq!(missing, vec![String::from("kme-3"), String::from("kme-4")]);
    }

    #[test]
    fn key_states_has_no_entry_for_a_key_never_set() {
        let key_states = KeyStates::new();
        assert_eq!(key_states.get("key-1"), None);
    }

    #[test]
    fn key_states_get_returns_the_last_set_value() {
        let key_states = KeyStates::new();
        key_states.set("key-1", ZenohKeyState::Syncing);
        assert_eq!(key_states.get("key-1"), Some(ZenohKeyState::Syncing));
        key_states.set("key-1", ZenohKeyState::InUse);
        assert_eq!(key_states.get("key-1"), Some(ZenohKeyState::InUse));
        assert_eq!(key_states.get("key-2"), None);
    }

    #[test]
    fn key_states_clones_share_the_same_underlying_state() {
        let key_states = KeyStates::new();
        let cloned = key_states.clone();
        key_states.set("key-1", ZenohKeyState::Generated);
        assert_eq!(cloned.get("key-1"), Some(ZenohKeyState::Generated));
    }
}
