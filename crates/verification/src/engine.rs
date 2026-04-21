//! VerificationEngine: orchestrates sessions and triggers verification.
//!
//! 2026-04-15 redesign: per-session role assignment replaces the old
//! process-wide `current_assignment`. Each session computes its own
//! Primary + Verifier via drand-seeded Fisher-Yates at `start_session`,
//! stores the result on the `AdminSession`, and reads the Verifier back
//! at verification time. This replaces the old three-role model
//! (Access / Witness / Verifier) whose `Witness` slot had zero runtime
//! behavior. See assignment.rs for the shuffle semantics.

use crate::assignment::{assign_replicas_with_drand, RoleAssignment};
use crate::entropy::DrandClient;
use crate::session::{AdminSession, SessionOperation, SessionState};
use crate::verifiers::VerifierRegistry;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uninc_common::nats_client::NatsClient;
use uuid::Uuid;

/// Result of verifying a session's operations against the Verifier replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// All checksums matched — the chain's claim is consistent with the
    /// replica's state.
    Passed,
    /// Checksums diverged — possible unauthorized modification or
    /// chain tampering.
    Failed { reason: String },
    /// Verification is deferred (waiting for replication lag to settle,
    /// or waiting for the next TTL-triggered verification pass).
    Pending,
}

/// Orchestrates transparency-log verification across admin sessions.
///
/// Tracks active admin sessions, computes a drand-seeded role assignment
/// per session (Primary pinned to `replicas[0]`, Verifier rotated via
/// Fisher-Yates over the non-primary replicas), records operations, and
/// schedules verification passes.
pub struct VerificationEngine {
    sessions: Arc<RwLock<HashMap<Uuid, AdminSession>>>,
    config: uninc_common::config::VerificationConfig,
    #[allow(dead_code)] // held for future triggers; nightly reads via engine.nats() if needed
    nats: Option<Arc<NatsClient>>,
    /// Per-protocol verifier registry. The verification task dispatches
    /// to the primitive's verifier via `verifiers.get(protocol)`.
    verifiers: Arc<VerifierRegistry>,
    /// Drand client for seeding per-session role assignments. v1 ships
    /// drand BLS verification (see `entropy::verify_drand_bls`) and the
    /// drand path is default-on in `assign_replicas_with_drand`. OS
    /// random is the fallback when every configured relay is unreachable
    /// or returns a round that fails BLS verification. `UNINC_DISABLE_DRAND`
    /// forces the fallback path for local development; MUST NOT be set
    /// in production.
    drand: Arc<DrandClient>,
    /// Session-end trigger for the scheduled verification task. Fires on
    /// every admin/suspicious session end via [`end_session`]. The
    /// scheduler races this against the periodic tick (default 4h), so a
    /// burst of admin work gets verified shortly after the last session
    /// closes rather than waiting the full period.
    session_end_notify: Arc<tokio::sync::Notify>,
}

impl VerificationEngine {
    /// Create a new verification engine with the given configuration.
    pub fn new(
        config: uninc_common::config::VerificationConfig,
        nats: Option<Arc<NatsClient>>,
    ) -> Self {
        info!(
            replica_count = config.replica_count,
            "verification engine initialized (two-role model: primary + verifier)"
        );
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
            nats,
            verifiers: Arc::new(VerifierRegistry::new()),
            drand: Arc::new(DrandClient::new()),
            session_end_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Hand out a reference to the session-end trigger. The scheduled
    /// verification task clones this Arc and awaits `notified()` in its
    /// select loop; `end_session` calls `notify_one()` on every admin
    /// session close.
    pub fn session_end_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.session_end_notify)
    }

    /// Attach a populated verifier registry. Call once at startup after
    /// the per-DB verifiers have been constructed.
    pub fn with_verifiers(mut self, registry: VerifierRegistry) -> Self {
        self.verifiers = Arc::new(registry);
        self
    }

    pub fn verifiers(&self) -> Arc<VerifierRegistry> {
        Arc::clone(&self.verifiers)
    }

    /// Register a new admin session for verification tracking. Computes
    /// a drand-seeded role assignment (Primary + Verifier) and stores it
    /// on the session record for the verification pass to read later.
    ///
    /// If the deployment has fewer than 2 replicas (e.g. Playground
    /// tier), the session is registered without an assignment and no
    /// verification will be scheduled for it — the trust story is
    /// honestly weaker at that tier.
    pub async fn start_session(&self, session_id: Uuid, admin_id: String) {
        let session = if self.config.replicas.len() >= 2 {
            let assignment = assign_replicas_with_drand(
                &self.drand,
                &session_id,
                chrono::Utc::now().timestamp_millis(),
                &self.config.replicas,
                None,
            )
            .await;
            info!(
                %session_id,
                %admin_id,
                primary = assignment.primary.id.as_str(),
                verifier = assignment.verifier.id.as_str(),
                ttl_secs = ?assignment
                    .expires_at
                    .duration_since(assignment.assigned_at)
                    .ok()
                    .map(|d| d.as_secs()),
                entropy = ?assignment.entropy,
                "verification session started with per-session assignment"
            );
            AdminSession::new_with_assignment(session_id, admin_id, &assignment)
        } else {
            warn!(
                %session_id,
                %admin_id,
                replica_count = self.config.replicas.len(),
                "verification session started WITHOUT role assignment — fewer than 2 replicas configured"
            );
            AdminSession::new(session_id, admin_id)
        };
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, session);
    }

    /// Record an operation in a session's log.
    ///
    /// If the session does not exist, the operation is logged as a warning
    /// and dropped (this can happen if the session was already ended).
    pub async fn record_operation(&self, session_id: &Uuid, operation: SessionOperation) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.add_operation(operation);
        } else {
            warn!(
                %session_id,
                "attempted to record operation for unknown session"
            );
        }
    }

    /// End a session. Marks it `Ended` and returns `Pending` — the
    /// actual verification pass runs on the TTL-triggered background
    /// task in `verification_task.rs`, which reads the session's
    /// assigned Verifier replica and compares state against the chain.
    pub async fn end_session(&self, session_id: &Uuid) -> VerificationResult {
        let mut sessions = self.sessions.write().await;

        let Some(session) = sessions.get_mut(session_id) else {
            warn!(%session_id, "attempted to end unknown session");
            return VerificationResult::Failed {
                reason: "session not found".into(),
            };
        };

        session.end();

        info!(
            %session_id,
            admin_id = %session.admin_id,
            op_count = session.operations.len(),
            duration_ms = session.duration_ms(),
            verifier = ?session.verifier.as_ref().map(|v| v.id.clone()),
            "session ended — verification pass will cover it on the next TTL tick"
        );

        // Kick the scheduled verification task. `notify_one` is
        // idempotent within the same "waiter present" window — if the
        // scheduler is already running a pass or hasn't yet reached the
        // select point, the notify is coalesced. That's the right
        // semantics: back-to-back session ends shouldn't queue N
        // verification runs; one prompt run after the burst is enough.
        self.session_end_notify.notify_one();

        VerificationResult::Pending
    }

    /// Get the number of currently tracked sessions (for monitoring).
    pub async fn active_session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|s| matches!(s.state, SessionState::Active))
            .count()
    }

    /// Get the total number of tracked sessions (active + ended + verified).
    pub async fn total_session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Borrow the sessions map for read-only iteration (used by the
    /// verification task to walk ended sessions).
    pub fn sessions(&self) -> Arc<RwLock<HashMap<Uuid, AdminSession>>> {
        Arc::clone(&self.sessions)
    }

    /// Get a reference to the engine's config.
    pub fn config(&self) -> &uninc_common::config::VerificationConfig {
        &self.config
    }

    /// Clone the drand client for use by the verification task.
    pub fn drand(&self) -> Arc<DrandClient> {
        Arc::clone(&self.drand)
    }
}

// Backwards-compat shims for call sites that still use the old
// process-wide `current_assignment` / `install_assignment` API. These
// are no-ops in the new per-session model and will be deleted once all
// callers have migrated.

impl VerificationEngine {
    /// Deprecated. The per-session model has no process-wide assignment.
    /// Always returns `None`. Call sites should read the Verifier off
    /// the `AdminSession` instead.
    #[deprecated(note = "use per-session AdminSession::verifier instead")]
    pub async fn current_assignment(&self) -> Option<RoleAssignment> {
        None
    }

    /// Deprecated. The per-session model computes its own assignments.
    /// This is a no-op kept for migration compatibility.
    #[deprecated(note = "per-session assignments are computed in start_session")]
    pub async fn install_assignment(&self, _assignment: RoleAssignment) {
        // no-op
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::ActionType;

    fn test_config() -> uninc_common::config::VerificationConfig {
        uninc_common::config::VerificationConfig {
            enabled: true,
            replica_count: 3,
            verifier_count: 1,
            replicas: vec![],
            assignment: Default::default(),
            timing: uninc_common::config::VerificationTimingConfig {
                verify_on_session_end: true,
                periodic_hours: 6,
                nightly_full_compare: true,
                nightly_compare_hour_utc: 2,
                replication_lag_buffer_ms: 5000,
            },
            batch: Default::default(),
            on_failure: Default::default(),
            observer_url: None,
            observer_read_secret: None,
        }
    }

    #[tokio::test]
    async fn start_and_end_session() {
        let engine = VerificationEngine::new(test_config(), None);
        let session_id = Uuid::new_v4();

        engine
            .start_session(session_id, "admin@co.com".into())
            .await;
        assert_eq!(engine.active_session_count().await, 1);

        let result = engine.end_session(&session_id).await;
        assert_eq!(result, VerificationResult::Pending);
        assert_eq!(engine.active_session_count().await, 0);
    }

    #[tokio::test]
    async fn record_operations() {
        let engine = VerificationEngine::new(test_config(), None);
        let session_id = Uuid::new_v4();

        engine.start_session(session_id, "admin".into()).await;
        engine
            .record_operation(
                &session_id,
                SessionOperation {
                    sql_or_command: "SELECT * FROM users".into(),
                    action: ActionType::Query,
                    resource: "users".into(),
                    affected_rows: Some(42),
                    timestamp: chrono::Utc::now().timestamp_millis(),
                },
            )
            .await;

        let result = engine.end_session(&session_id).await;
        assert_eq!(result, VerificationResult::Pending);
    }

    #[tokio::test]
    async fn end_unknown_session_returns_failed() {
        let engine = VerificationEngine::new(test_config(), None);
        let result = engine.end_session(&Uuid::new_v4()).await;
        assert!(matches!(result, VerificationResult::Failed { .. }));
    }

    #[tokio::test]
    async fn session_without_replicas_has_no_verifier() {
        let engine = VerificationEngine::new(test_config(), None);
        let session_id = Uuid::new_v4();
        engine.start_session(session_id, "admin".into()).await;
        let sessions = engine.sessions.read().await;
        let s = sessions.get(&session_id).unwrap();
        assert!(s.verifier.is_none());
    }

    #[tokio::test]
    async fn record_operation_for_unknown_session_is_safe() {
        let engine = VerificationEngine::new(test_config(), None);
        engine
            .record_operation(
                &Uuid::new_v4(),
                SessionOperation {
                    sql_or_command: "SELECT 1".into(),
                    action: ActionType::Query,
                    resource: "test".into(),
                    affected_rows: None,
                    timestamp: 0,
                },
            )
            .await;
    }

    #[tokio::test]
    async fn total_vs_active_count() {
        let engine = VerificationEngine::new(test_config(), None);
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();

        engine.start_session(s1, "admin1".into()).await;
        engine.start_session(s2, "admin2".into()).await;
        assert_eq!(engine.active_session_count().await, 2);
        assert_eq!(engine.total_session_count().await, 2);

        engine.end_session(&s1).await;
        assert_eq!(engine.active_session_count().await, 1);
        assert_eq!(engine.total_session_count().await, 2);
    }
}
