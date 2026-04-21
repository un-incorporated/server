//! AdminSession tracking: start, accumulate operations, end.
//!
//! Each session carries its own drand-seeded role assignment (Primary +
//! Verifier). The assignment is computed at session start via
//! `assign_replicas_with_drand` and stored on the session record so the
//! verification pass at session end (or at the next TTL trigger) can
//! read the exact Verifier replica to cross-check against the chain.

use crate::assignment::RoleAssignment;
use serde::{Deserialize, Serialize};
use uninc_common::config::ReplicaConfig;
use uuid::Uuid;

/// The type of action performed in an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    Query,
    Mutation,
    SchemaChange,
    Export,
    Other(String),
}

/// A single operation recorded during an admin session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOperation {
    /// The SQL statement or command that was executed.
    pub sql_or_command: String,
    /// The type of action.
    pub action: ActionType,
    /// The resource (table/collection/bucket) affected.
    pub resource: String,
    /// Number of rows affected, if applicable.
    pub affected_rows: Option<u64>,
    /// Unix timestamp in milliseconds when the operation was recorded.
    pub timestamp: i64,
}

/// Tracks the lifecycle state of an admin session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionState {
    Active,
    Ended { ended_at: i64 },
    Verified { result: bool },
}

/// Represents an admin's active or completed verification session.
///
/// Holds a non-serializable role assignment (Primary + Verifier) that was
/// drand-seeded at session start. The assignment is excluded from serde
/// because `RoleAssignment` contains `SystemTime` fields and is intended
/// for in-memory use only; persistence of session state would carry the
/// seed separately and re-derive the assignment from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSession {
    pub session_id: Uuid,
    pub admin_id: String,
    pub started_at: i64,
    pub operations: Vec<SessionOperation>,
    pub state: SessionState,

    /// The verifier replica assigned to this session via drand shuffle.
    /// Read at verification time to cross-check chain entries against
    /// replica state. `None` means verification was not yet scheduled or
    /// the deployment has fewer than 2 replicas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<ReplicaConfig>,

    /// The 32-byte seed that produced this session's role assignment.
    /// An auditor can re-derive the Verifier choice from this seed + the
    /// known replica list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<[u8; 32]>,
}

impl AdminSession {
    /// Create a new active admin session without a role assignment.
    /// Use `new_with_assignment` when the verification engine has a
    /// replica list; `new` is retained for tests and degraded code paths.
    pub fn new(session_id: Uuid, admin_id: String) -> Self {
        Self {
            session_id,
            admin_id,
            started_at: chrono::Utc::now().timestamp_millis(),
            operations: Vec::new(),
            state: SessionState::Active,
            verifier: None,
            seed: None,
        }
    }

    /// Create a new active admin session with a drand-seeded role
    /// assignment already computed by the engine.
    pub fn new_with_assignment(
        session_id: Uuid,
        admin_id: String,
        assignment: &RoleAssignment,
    ) -> Self {
        Self {
            session_id,
            admin_id,
            started_at: chrono::Utc::now().timestamp_millis(),
            operations: Vec::new(),
            state: SessionState::Active,
            verifier: Some(assignment.verifier.clone()),
            seed: Some(assignment.seed),
        }
    }

    /// Record an operation in this session.
    pub fn add_operation(&mut self, operation: SessionOperation) {
        self.operations.push(operation);
    }

    /// Mark the session as ended.
    pub fn end(&mut self) {
        self.state = SessionState::Ended {
            ended_at: chrono::Utc::now().timestamp_millis(),
        };
    }

    /// Calculate the session duration in milliseconds.
    /// Returns 0 if the session is still active.
    pub fn duration_ms(&self) -> i64 {
        match &self.state {
            SessionState::Active => {
                chrono::Utc::now().timestamp_millis() - self.started_at
            }
            SessionState::Ended { ended_at: _ } | SessionState::Verified { .. } => {
                let ended_at = match &self.state {
                    SessionState::Ended { ended_at } => *ended_at,
                    _ => chrono::Utc::now().timestamp_millis(),
                };
                ended_at - self.started_at
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_is_active() {
        let session = AdminSession::new(Uuid::new_v4(), "admin@co.com".into());
        assert!(matches!(session.state, SessionState::Active));
        assert!(session.operations.is_empty());
        assert!(session.verifier.is_none());
        assert!(session.seed.is_none());
    }

    #[test]
    fn add_operation_records_it() {
        let mut session = AdminSession::new(Uuid::new_v4(), "admin@co.com".into());
        session.add_operation(SessionOperation {
            sql_or_command: "SELECT * FROM users".into(),
            action: ActionType::Query,
            resource: "users".into(),
            affected_rows: Some(10),
            timestamp: chrono::Utc::now().timestamp_millis(),
        });
        assert_eq!(session.operations.len(), 1);
    }

    #[test]
    fn end_session_transitions_state() {
        let mut session = AdminSession::new(Uuid::new_v4(), "admin@co.com".into());
        session.end();
        assert!(matches!(session.state, SessionState::Ended { .. }));
    }

    #[test]
    fn duration_is_nonnegative() {
        let session = AdminSession::new(Uuid::new_v4(), "admin@co.com".into());
        assert!(session.duration_ms() >= 0);
    }

    #[test]
    fn new_with_assignment_stores_verifier_and_seed() {
        use crate::assignment::assign_replicas;
        let replicas: Vec<ReplicaConfig> = (0..3)
            .map(|i| ReplicaConfig {
                id: format!("r{i}"),
                host: format!("10.0.2.{}", 10 + i),
                port: 5432,
                user: "u".into(),
                password: "p".into(),
                database: "d".into(),
            })
            .collect();
        let assignment = assign_replicas(&Uuid::new_v4(), 1712592000000, &replicas, None);
        let session = AdminSession::new_with_assignment(
            Uuid::new_v4(),
            "admin@co.com".into(),
            &assignment,
        );
        assert!(session.verifier.is_some());
        assert_eq!(
            session.verifier.as_ref().unwrap().id,
            assignment.verifier.id
        );
        assert_eq!(session.seed, Some(assignment.seed));
    }
}
