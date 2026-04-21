//! Per-connection state machine for the Postgres proxy.
//!
//! Tracks connection lifecycle (startup -> auth -> ready -> queries),
//! classifies SQL operations, resolves affected users, and produces
//! `AccessEvent`s for admin connections.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::Utc;
use tracing::debug;
use uuid::Uuid;

use uninc_common::config::SchemaConfig;
use uninc_common::types::{
    AccessEvent, ActionType, ConnectionClass, Protocol,
};

use crate::postgres::fingerprint;
use crate::postgres::resolver::PostgresResolver;
use crate::postgres::sql_parser;
use crate::postgres::wire::{BackendMessage, FrontendMessage};

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

/// The lifecycle state of a Postgres connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Waiting for StartupMessage.
    Startup,
    /// Authentication exchange in progress.
    Authenticating,
    /// Connection is authenticated and ready for queries.
    Ready,
    /// Processing a query (between Query/Execute and ReadyForQuery).
    InQuery,
    /// Connection terminated.
    Terminated,
}

// ---------------------------------------------------------------------------
// Connection struct
// ---------------------------------------------------------------------------

/// Per-connection state for a proxied Postgres connection.
pub struct PostgresConnection {
    /// Current lifecycle state.
    state: ConnectionState,
    /// Username from the StartupMessage.
    username: Option<String>,
    /// Database from the StartupMessage.
    database: Option<String>,
    /// Classification of this connection (App, Admin, Suspicious).
    class: Option<ConnectionClass>,
    /// For extended query protocol: prepared statement name -> SQL template.
    prepared_statements: HashMap<String, String>,
    /// Unique session ID for this connection.
    session_id: Uuid,
    /// Source IP of the client.
    source_ip: IpAddr,
    /// The SQL currently being executed (for simple query or via extended protocol).
    current_sql: Option<String>,
    /// User resolver for looking up affected users.
    resolver: PostgresResolver,
}

impl PostgresConnection {
    /// Create a new connection state machine.
    pub fn new(source_ip: IpAddr, schema: SchemaConfig) -> Self {
        Self {
            state: ConnectionState::Startup,
            username: None,
            database: None,
            class: None,
            prepared_statements: HashMap::new(),
            session_id: Uuid::new_v4(),
            source_ip,
            current_sql: None,
            resolver: PostgresResolver::new(schema),
        }
    }

    /// Get the current state.
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Get the session ID.
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Get the username, if set.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Get the database, if set.
    pub fn database(&self) -> Option<&str> {
        self.database.as_deref()
    }

    /// Get the connection classification, if set.
    pub fn class(&self) -> Option<&ConnectionClass> {
        self.class.as_ref()
    }

    /// Set the connection classification (called after the classifier runs).
    pub fn set_class(&mut self, class: ConnectionClass) {
        self.class = Some(class);
    }

    /// Returns true if this connection is classified as App (passthrough).
    pub fn is_app(&self) -> bool {
        matches!(self.class, Some(ConnectionClass::App))
    }

    /// Handle a frontend (client -> server) message.
    ///
    /// Updates internal state and optionally returns an `AccessEvent` to emit.
    pub fn handle_frontend_message(
        &mut self,
        msg: &FrontendMessage,
    ) -> Option<AccessEvent> {
        match msg {
            FrontendMessage::StartupMessage {
                user, database, ..
            } => {
                self.username = Some(user.clone());
                self.database = Some(database.clone());
                self.state = ConnectionState::Authenticating;
                debug!(user, database, "startup message received");
                None
            }

            FrontendMessage::Query { sql } => {
                if self.state == ConnectionState::Ready || self.state == ConnectionState::InQuery {
                    self.state = ConnectionState::InQuery;
                    self.current_sql = Some(sql.clone());
                    debug!(sql, "simple query");
                    return self.build_access_event(sql);
                }
                None
            }

            FrontendMessage::Parse { name, sql, .. } => {
                // Store the SQL template for this prepared statement
                debug!(name, sql, "parse (extended query)");
                self.prepared_statements.insert(name.clone(), sql.clone());
                None
            }

            FrontendMessage::Bind {
                portal: _,
                statement,
                ..
            } => {
                // Look up the SQL for this statement; emit event on Execute
                if let Some(sql) = self.prepared_statements.get(statement) {
                    self.current_sql = Some(sql.clone());
                }
                None
            }

            FrontendMessage::Execute { .. } => {
                if let Some(ref sql) = self.current_sql.clone() {
                    self.state = ConnectionState::InQuery;
                    return self.build_access_event(sql);
                }
                None
            }

            FrontendMessage::Terminate => {
                self.state = ConnectionState::Terminated;
                debug!("connection terminated by client");
                None
            }

            FrontendMessage::PasswordMessage(_)
            | FrontendMessage::SASLInitialResponse { .. }
            | FrontendMessage::SASLResponse(_) => {
                // Auth messages — state stays Authenticating
                None
            }

            FrontendMessage::Unknown { tag, .. } => {
                debug!(tag, "unknown frontend message");
                None
            }
        }
    }

    /// Handle a backend (server -> client) message.
    ///
    /// Updates internal state based on server responses.
    pub fn handle_backend_message(&mut self, msg: &BackendMessage) {
        match msg {
            BackendMessage::AuthenticationOk => {
                debug!("authentication successful");
                // State will transition to Ready on ReadyForQuery
            }

            BackendMessage::ReadyForQuery { status } => {
                self.state = ConnectionState::Ready;
                self.current_sql = None;
                let status_char = *status as char;
                debug!(status = %status_char, "ready for query");
            }

            BackendMessage::ErrorResponse { fields } => {
                if let Some(msg) = fields.get(&b'M') {
                    debug!(error = msg, "backend error");
                }
            }

            BackendMessage::AuthenticationCleartextPassword
            | BackendMessage::AuthenticationMD5Password { .. }
            | BackendMessage::AuthenticationSASL { .. }
            | BackendMessage::AuthenticationSASLContinue(_)
            | BackendMessage::AuthenticationSASLFinal(_) => {
                self.state = ConnectionState::Authenticating;
            }

            _ => {
                // Other backend messages don't change our state machine
            }
        }
    }

    /// Build an AccessEvent for a SQL query.
    ///
    /// ALL connections (App, Admin, Suspicious) produce events.
    /// The `admin_id` field carries the Postgres role name regardless
    /// of connection class — the class is a label, not a gate.
    fn build_access_event(&self, sql: &str) -> Option<AccessEvent> {
        let (admin_id, session_id) = match &self.class {
            Some(ConnectionClass::Admin(identity)) => {
                (identity.username.clone(), identity.session_id)
            }
            Some(ConnectionClass::Suspicious(msg)) => {
                (format!("suspicious:{msg}"), self.session_id)
            }
            Some(ConnectionClass::App) => {
                // App connections: use the Postgres role as the identity.
                // The username was stored during startup message handling.
                let username = self.username.clone().unwrap_or_else(|| "app".into());
                (format!("app:{username}"), self.session_id)
            }
            None => return None, // not yet classified (during handshake)
        };

        // Parse the SQL
        let parsed = sql_parser::parse_sql(sql);
        let action = parsed.action.unwrap_or(ActionType::Read);

        // Resolve affected users
        let affected_users = self.resolver.resolve_from_where(&parsed);

        // Build resource string (table names)
        let resource = parsed
            .tables
            .iter()
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        // No early return on empty resource — admin commands like
        // SELECT version(), SHOW server_version, SET statements, etc.
        // must still produce an AccessEvent for the deployment chain. The org
        // chain is the complete admin activity log.
        let resource = if resource.is_empty() {
            "(utility)".to_string()
        } else {
            resource
        };

        // Build scope string
        let columns = if parsed.columns.is_empty() {
            "*".to_string()
        } else {
            parsed.columns.join(", ")
        };
        let scope = if let Some(ref where_clause) = parsed.raw_where {
            format!("columns: {columns}; filter: {where_clause}")
        } else {
            format!("columns: {columns}")
        };

        // Fingerprint
        let query_fingerprint = fingerprint::fingerprint_sql(sql);

        // Metadata
        let mut metadata = HashMap::new();
        metadata.insert("source_ip".to_string(), self.source_ip.to_string());
        if let Some(ref db) = self.database {
            metadata.insert("database".to_string(), db.clone());
        }

        Some(AccessEvent {
            protocol: Protocol::Postgres,
            admin_id,
            action,
            resource,
            scope,
            query_fingerprint,
            affected_users,
            timestamp: Utc::now().timestamp_millis(),
            session_id,
            metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uninc_common::config::{UserIdColumn, UserTableConfig};
    use uninc_common::types::AdminIdentity;

    fn make_schema() -> SchemaConfig {
        SchemaConfig {
            user_tables: vec![UserTableConfig {
                table: "users".to_string(),
                user_id_column: UserIdColumn::Single("id".to_string()),
                sensitive_columns: vec!["email".to_string()],
            }],
            user_collections: vec![],
            excluded_tables: vec![],
        }
    }

    fn make_admin_conn() -> PostgresConnection {
        let mut conn = PostgresConnection::new("192.168.1.100".parse().unwrap(), make_schema());
        conn.set_class(ConnectionClass::Admin(AdminIdentity {
            username: "admin".to_string(),
            source_ip: "192.168.1.100".parse().unwrap(),
            session_id: conn.session_id(),
        }));
        conn
    }

    fn make_app_conn() -> PostgresConnection {
        let mut conn = PostgresConnection::new("10.0.0.5".parse().unwrap(), make_schema());
        conn.set_class(ConnectionClass::App);
        conn
    }

    // --- State transitions ---

    #[test]
    fn initial_state_is_startup() {
        let conn = PostgresConnection::new("127.0.0.1".parse().unwrap(), make_schema());
        assert_eq!(conn.state(), ConnectionState::Startup);
    }

    #[test]
    fn startup_transitions_to_authenticating() {
        let mut conn = PostgresConnection::new("127.0.0.1".parse().unwrap(), make_schema());
        conn.handle_frontend_message(&FrontendMessage::StartupMessage {
            user: "admin".to_string(),
            database: "mydb".to_string(),
            params: HashMap::new(),
        });
        assert_eq!(conn.state(), ConnectionState::Authenticating);
        assert_eq!(conn.username(), Some("admin"));
        assert_eq!(conn.database(), Some("mydb"));
    }

    #[test]
    fn auth_ok_then_ready_for_query() {
        let mut conn = PostgresConnection::new("127.0.0.1".parse().unwrap(), make_schema());
        conn.handle_frontend_message(&FrontendMessage::StartupMessage {
            user: "admin".to_string(),
            database: "mydb".to_string(),
            params: HashMap::new(),
        });
        conn.handle_backend_message(&BackendMessage::AuthenticationOk);
        conn.handle_backend_message(&BackendMessage::ReadyForQuery { status: b'I' });
        assert_eq!(conn.state(), ConnectionState::Ready);
    }

    #[test]
    fn query_transitions_to_in_query() {
        let mut conn = make_admin_conn();
        conn.state = ConnectionState::Ready;
        conn.handle_frontend_message(&FrontendMessage::Query {
            sql: "SELECT 1".to_string(),
        });
        assert_eq!(conn.state(), ConnectionState::InQuery);
    }

    #[test]
    fn ready_for_query_returns_to_ready() {
        let mut conn = make_admin_conn();
        conn.state = ConnectionState::InQuery;
        conn.handle_backend_message(&BackendMessage::ReadyForQuery { status: b'I' });
        assert_eq!(conn.state(), ConnectionState::Ready);
    }

    #[test]
    fn terminate_transitions_to_terminated() {
        let mut conn = make_admin_conn();
        conn.state = ConnectionState::Ready;
        conn.handle_frontend_message(&FrontendMessage::Terminate);
        assert_eq!(conn.state(), ConnectionState::Terminated);
    }

    // --- Access events ---

    #[test]
    fn admin_query_produces_event() {
        let mut conn = make_admin_conn();
        conn.state = ConnectionState::Ready;
        let event = conn.handle_frontend_message(&FrontendMessage::Query {
            sql: "SELECT email FROM users WHERE id = 42".to_string(),
        });
        let event = event.expect("should produce an event");
        assert_eq!(event.protocol, Protocol::Postgres);
        assert_eq!(event.admin_id, "admin");
        assert_eq!(event.action, ActionType::Read);
        assert_eq!(event.resource, "users");
        assert_eq!(event.affected_users, vec!["42"]);
        assert!(event.scope.contains("email"));
    }

    #[test]
    fn app_query_produces_event_with_app_label() {
        let mut conn = make_app_conn();
        conn.state = ConnectionState::Ready;
        let event = conn.handle_frontend_message(&FrontendMessage::Query {
            sql: "SELECT * FROM users WHERE id = 1".to_string(),
        });
        // App queries now produce events (log everything).
        // The admin_id is prefixed with "app:" to distinguish from admin access.
        let event = event.expect("app queries should produce events");
        assert!(event.admin_id.starts_with("app:"));
        assert_eq!(event.action, ActionType::Read);
        assert_eq!(event.affected_users, vec!["1"]);
    }

    #[test]
    fn extended_query_protocol_produces_event() {
        let mut conn = make_admin_conn();
        conn.state = ConnectionState::Ready;

        // Parse
        let event = conn.handle_frontend_message(&FrontendMessage::Parse {
            name: "stmt1".to_string(),
            sql: "SELECT email FROM users WHERE id = $1".to_string(),
            param_types: vec![23],
        });
        assert!(event.is_none()); // Parse alone doesn't emit

        // Bind
        let event = conn.handle_frontend_message(&FrontendMessage::Bind {
            portal: "".to_string(),
            statement: "stmt1".to_string(),
            params: vec![Some(b"42".to_vec())],
        });
        assert!(event.is_none()); // Bind alone doesn't emit

        // Execute
        let event = conn.handle_frontend_message(&FrontendMessage::Execute {
            portal: "".to_string(),
            max_rows: 0,
        });
        assert!(event.is_some()); // Execute emits the event
        let event = event.unwrap();
        assert_eq!(event.resource, "users");
    }

    #[test]
    fn delete_query_produces_delete_event() {
        let mut conn = make_admin_conn();
        conn.state = ConnectionState::Ready;
        let event = conn.handle_frontend_message(&FrontendMessage::Query {
            sql: "DELETE FROM users WHERE id = 99".to_string(),
        });
        let event = event.unwrap();
        assert_eq!(event.action, ActionType::Delete);
        assert_eq!(event.affected_users, vec!["99"]);
    }

    #[test]
    fn schema_change_produces_event() {
        let mut conn = make_admin_conn();
        conn.state = ConnectionState::Ready;
        let event = conn.handle_frontend_message(&FrontendMessage::Query {
            sql: "ALTER TABLE users ADD COLUMN phone TEXT".to_string(),
        });
        let event = event.unwrap();
        assert_eq!(event.action, ActionType::SchemaChange);
    }

    #[test]
    fn query_on_unknown_table_still_produces_event_for_deployment_chain() {
        let mut conn = make_admin_conn();
        conn.state = ConnectionState::Ready;
        // `SELECT 1` has no tables — but admin connections must ALWAYS
        // produce an AccessEvent for the deployment chain. The resource is
        // "(utility)" as a fallback.
        let event = conn.handle_frontend_message(&FrontendMessage::Query {
            sql: "SELECT 1".to_string(),
        });
        let event = event.unwrap();
        assert_eq!(event.resource, "(utility)");
        assert!(event.affected_users.is_empty());
    }

    #[test]
    fn fingerprint_is_set() {
        let mut conn = make_admin_conn();
        conn.state = ConnectionState::Ready;
        let event = conn
            .handle_frontend_message(&FrontendMessage::Query {
                sql: "SELECT * FROM users WHERE id = 1".to_string(),
            })
            .unwrap();
        // Fingerprint should not be all zeros
        assert_ne!(event.query_fingerprint, [0u8; 32]);
    }
}
