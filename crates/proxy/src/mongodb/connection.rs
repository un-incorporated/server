//! Per-connection state machine for MongoDB proxy sessions.
//!
//! Tracks authentication state, classifies connections, and generates
//! [`AccessEvent`]s for admin operations.

use std::collections::HashMap;
use std::net::IpAddr;

use tracing::{debug, info, warn};
use uuid::Uuid;

use uninc_common::config::{IdentityConfig, SchemaConfig};
use uninc_common::types::{AccessEvent, ConnectionClass, Protocol};

use crate::identity::classifier;
use crate::mongodb::fingerprint::fingerprint_bson;
use crate::mongodb::parser::parse_command;
use crate::mongodb::resolver::MongoResolver;
use crate::mongodb::scram;
use crate::mongodb::wire::OpMsg;

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// The authentication/lifecycle state of a MongoDB connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MongoConnectionState {
    /// Waiting for the initial `hello` / `isMaster` handshake.
    Handshake,
    /// SCRAM exchange in progress.
    Authenticating,
    /// Authenticated and processing regular commands.
    Ready,
    /// Connection has been closed or encountered a fatal error.
    Terminated,
}

/// Per-connection state for the MongoDB proxy.
pub struct MongoConnection {
    state: MongoConnectionState,
    username: Option<String>,
    database: Option<String>,
    class: Option<ConnectionClass>,
    session_id: Uuid,
    source_ip: IpAddr,
    identity_config: IdentityConfig,
    resolver: MongoResolver,
}

impl MongoConnection {
    /// Create a new connection in the `Handshake` state.
    pub fn new(
        source_ip: IpAddr,
        identity_config: IdentityConfig,
        schema_config: SchemaConfig,
    ) -> Self {
        Self {
            state: MongoConnectionState::Handshake,
            username: None,
            database: None,
            class: None,
            session_id: Uuid::new_v4(),
            source_ip,
            identity_config,
            resolver: MongoResolver::new(schema_config),
        }
    }

    /// Current state of the connection.
    pub fn state(&self) -> &MongoConnectionState {
        &self.state
    }

    /// The classified connection type (set after authentication).
    pub fn class(&self) -> Option<&ConnectionClass> {
        self.class.as_ref()
    }

    /// The authenticated username, if known.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// The session ID for this connection.
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Whether this connection is classified as Admin.
    pub fn is_admin(&self) -> bool {
        matches!(self.class, Some(ConnectionClass::Admin(_)))
    }

    /// Whether this connection is classified as App (passthrough).
    pub fn is_app(&self) -> bool {
        matches!(self.class, Some(ConnectionClass::App))
    }

    /// Mark the connection as terminated.
    pub fn terminate(&mut self) {
        self.state = MongoConnectionState::Terminated;
    }

    /// Process a client-side OP_MSG, advancing the state machine.
    ///
    /// Returns an `AccessEvent` if this is an admin connection executing
    /// a data-access command that affects user data.
    pub fn handle_client_message(&mut self, msg: &OpMsg) -> Option<AccessEvent> {
        match self.state {
            MongoConnectionState::Handshake => {
                self.handle_handshake(msg);
                None
            }
            MongoConnectionState::Authenticating => {
                self.handle_auth(msg);
                None
            }
            MongoConnectionState::Ready => self.handle_command(msg),
            MongoConnectionState::Terminated => {
                warn!(session_id = %self.session_id, "message on terminated connection");
                None
            }
        }
    }

    /// Handle a message during the Handshake state.
    fn handle_handshake(&mut self, msg: &OpMsg) {
        let doc = &msg.body;

        // Extract database from $db field.
        if let Some(db) = scram::extract_database(doc) {
            self.database = Some(db);
        }

        // Try to get username from saslSupportedMechs in hello/isMaster.
        if let Some(username) = scram::extract_username_from_hello(doc) {
            debug!(username, "got username from hello/isMaster saslSupportedMechs");
            self.username = Some(username);
        }

        if scram::is_handshake(doc) {
            debug!(session_id = %self.session_id, "handshake received, moving to Authenticating");
            self.state = MongoConnectionState::Authenticating;
        }
    }

    /// Handle a message during the Authenticating state.
    fn handle_auth(&mut self, msg: &OpMsg) {
        let doc = &msg.body;

        // Extract username from saslStart payload.
        if let Some(username) = scram::extract_username_from_sasl_start(doc) {
            debug!(username, "extracted username from saslStart");
            self.username = Some(username);
        }

        if let Some(db) = scram::extract_database(doc) {
            self.database = Some(db);
        }

        // saslContinue means auth is still in progress.
        if scram::is_sasl_continue(doc) {
            debug!(session_id = %self.session_id, "saslContinue, still authenticating");
            return;
        }

        // If this is neither saslStart nor saslContinue, authentication
        // is likely complete (the next message is a regular command).
        if !scram::is_sasl_start(doc) && !scram::is_sasl_continue(doc) {
            self.finalize_auth();
            // Re-process this message as a regular command.
            if self.state == MongoConnectionState::Ready {
                // Do not return an event from the first post-auth message;
                // it is typically a metadata command.
            }
        }
    }

    /// Finalize authentication: classify the connection.
    fn finalize_auth(&mut self) {
        let credential = self.username.as_deref().unwrap_or("unknown");

        let class = classifier::classify(
            self.source_ip,
            credential,
            Protocol::MongoDB,
            &self.identity_config,
        );

        match &class {
            ConnectionClass::App => {
                info!(
                    session_id = %self.session_id,
                    username = credential,
                    "MongoDB connection classified as App"
                );
            }
            ConnectionClass::Admin(identity) => {
                info!(
                    session_id = %self.session_id,
                    username = %identity.username,
                    source_ip = %identity.source_ip,
                    "MongoDB connection classified as Admin"
                );
            }
            ConnectionClass::Suspicious(reason) => {
                warn!(
                    session_id = %self.session_id,
                    reason,
                    "MongoDB connection classified as Suspicious"
                );
            }
        }

        self.class = Some(class);
        self.state = MongoConnectionState::Ready;
    }

    /// Handle a regular command after authentication.
    fn handle_command(&mut self, msg: &OpMsg) -> Option<AccessEvent> {
        // Only generate events for admin connections.
        let admin_identity = match &self.class {
            Some(ConnectionClass::Admin(identity)) => identity.clone(),
            _ => return None,
        };

        let doc = &msg.body;

        // Skip internal/metadata commands.
        if is_internal_command(doc) {
            return None;
        }

        let parsed = parse_command(doc);

        // Skip if no action was parsed.
        let action = parsed.action?;

        let collection = parsed
            .tables
            .first()
            .map(|t| t.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        // Resolve affected users from the filter.
        let filter_doc = doc.get_document("filter").ok();
        let affected_users = self.resolver.resolve_from_filter(&collection, filter_doc);

        // Compute query fingerprint.
        let query_fingerprint = fingerprint_bson(doc);

        // Build scope string.
        let scope = build_event_scope(&parsed, &collection);

        let mut metadata = HashMap::new();
        if let Some(ref db) = self.database {
            metadata.insert("database".to_string(), db.clone());
        }
        metadata.insert("source_ip".to_string(), self.source_ip.to_string());

        let event = AccessEvent {
            protocol: Protocol::MongoDB,
            admin_id: admin_identity.username.clone(),
            action,
            resource: collection,
            scope,
            query_fingerprint,
            affected_users,
            timestamp: chrono::Utc::now().timestamp_millis(),
            session_id: self.session_id,
            metadata,
        };

        debug!(
            session_id = %self.session_id,
            admin = %event.admin_id,
            action = %event.action,
            resource = %event.resource,
            affected = event.affected_users.len(),
            "generated AccessEvent"
        );

        Some(event)
    }
}

/// Check if a command document represents an internal/metadata command
/// that should not generate access events.
fn is_internal_command(doc: &bson::Document) -> bool {
    let Some((cmd, _)) = doc.iter().next() else {
        return true;
    };

    matches!(
        cmd.as_str(),
        "ping"
            | "hello"
            | "isMaster"
            | "ismaster"
            | "buildInfo"
            | "buildinfo"
            | "getLog"
            | "getFreeMonitoringStatus"
            | "saslStart"
            | "saslContinue"
            | "authenticate"
            | "logout"
            | "endSessions"
            | "killCursors"
            | "getMore"
            | "whatsmyuri"
            | "replSetGetStatus"
            | "serverStatus"
            | "hostInfo"
            | "connectionStatus"
            | "currentOp"
            | "killOp"
    )
}

/// Build a scope string from a parsed operation.
fn build_event_scope(
    parsed: &uninc_common::types::ParsedOperation,
    collection: &str,
) -> String {
    let mut parts = vec![format!("collection: {collection}")];

    if !parsed.columns.is_empty() {
        parts.push(format!("fields: {}", parsed.columns.join(", ")));
    }

    if !parsed.filters.is_empty() {
        let filter_desc: Vec<String> = parsed
            .filters
            .iter()
            .map(|f| {
                if f.operator == "$eq" {
                    f.column.clone()
                } else {
                    format!("{} {}", f.column, f.operator)
                }
            })
            .collect();
        parts.push(format!("filter: {}", filter_desc.join(", ")));
    }

    parts.join("; ")
}

/// Transition the connection directly to Ready with a known classification.
///
/// Used when the server response to the final `saslContinue` indicates
/// authentication succeeded, so we can classify without waiting for the
/// next client message.
pub fn mark_authenticated(conn: &mut MongoConnection) {
    if conn.state == MongoConnectionState::Authenticating {
        conn.finalize_auth();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;
    use std::collections::HashMap;
    use uninc_common::config::{
        CredentialEntry, IdentityConfig, IdentityMode, SchemaConfig,
        UserCollectionConfig, UserIdColumn,
    };
    use uninc_common::types::ActionType;
    use crate::mongodb::wire::{MsgHeader, OpMsg, OP_MSG};

    fn test_identity_config() -> IdentityConfig {
        let mut app_credentials = HashMap::new();
        app_credentials.insert(
            "mongodb".to_string(),
            vec![CredentialEntry {
                username: Some("app_user".to_string()),
                access_key: None,
            }],
        );

        IdentityConfig {
            mode: IdentityMode::Credential,
            app_sources: vec![],
            admin_credentials: HashMap::new(),
            app_credentials,
            behavioral_fingerprinting: false,
            mtls: None,
        }
    }

    fn test_schema_config() -> SchemaConfig {
        SchemaConfig {
            user_tables: vec![],
            user_collections: vec![UserCollectionConfig {
                collection: "users".to_string(),
                user_id_field: UserIdColumn::Single("_id".to_string()),
            }],
            excluded_tables: vec![],
        }
    }

    fn make_op_msg(body: bson::Document) -> OpMsg {
        OpMsg {
            header: MsgHeader {
                message_length: 0,
                request_id: 1,
                response_to: 0,
                op_code: OP_MSG,
            },
            flag_bits: 0,
            body,
        }
    }

    fn make_sasl_start_msg(username: &str) -> OpMsg {
        use bson::{spec::BinarySubtype, Binary};
        let payload = format!("n,,n={username},r=clientnonce123");
        make_op_msg(doc! {
            "saslStart": 1,
            "mechanism": "SCRAM-SHA-256",
            "payload": bson::Bson::Binary(Binary {
                subtype: BinarySubtype::Generic,
                bytes: payload.into_bytes(),
            }),
            "$db": "admin"
        })
    }

    #[test]
    fn state_machine_handshake_to_ready() {
        let mut conn = MongoConnection::new(
            "192.168.1.100".parse().unwrap(),
            test_identity_config(),
            test_schema_config(),
        );

        assert_eq!(*conn.state(), MongoConnectionState::Handshake);

        // Send hello
        let hello = make_op_msg(doc! { "hello": 1, "$db": "admin" });
        conn.handle_client_message(&hello);
        assert_eq!(*conn.state(), MongoConnectionState::Authenticating);

        // Send saslStart
        let sasl = make_sasl_start_msg("admin_dba");
        conn.handle_client_message(&sasl);
        assert_eq!(conn.username(), Some("admin_dba"));

        // Send a regular command (triggers finalize_auth)
        let find = make_op_msg(doc! { "find": "users", "filter": {}, "$db": "mydb" });
        conn.handle_client_message(&find);
        assert_eq!(*conn.state(), MongoConnectionState::Ready);
    }

    #[test]
    fn admin_connection_generates_event() {
        let mut conn = MongoConnection::new(
            "192.168.1.100".parse().unwrap(),
            test_identity_config(),
            test_schema_config(),
        );

        // Fast-forward through handshake + auth.
        let hello = make_op_msg(doc! { "hello": 1, "$db": "admin" });
        conn.handle_client_message(&hello);
        let sasl = make_sasl_start_msg("admin_dba");
        conn.handle_client_message(&sasl);
        // Trigger classification with a non-data command.
        let ping = make_op_msg(doc! { "ping": 1, "$db": "admin" });
        conn.handle_client_message(&ping);

        assert!(conn.is_admin());

        // Now issue a find that should produce an event.
        let find = make_op_msg(doc! {
            "find": "users",
            "filter": { "_id": 42 },
            "$db": "mydb"
        });
        let event = conn.handle_client_message(&find);
        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.protocol, Protocol::MongoDB);
        assert_eq!(event.resource, "users");
        assert_eq!(event.action, ActionType::Read);
        assert_eq!(event.affected_users, vec!["42"]);
    }

    #[test]
    fn app_connection_no_event() {
        let mut conn = MongoConnection::new(
            "192.168.1.100".parse().unwrap(),
            test_identity_config(),
            test_schema_config(),
        );

        // Auth as app_user.
        let hello = make_op_msg(doc! { "hello": 1, "$db": "admin" });
        conn.handle_client_message(&hello);
        let sasl = make_sasl_start_msg("app_user");
        conn.handle_client_message(&sasl);
        let ping = make_op_msg(doc! { "ping": 1, "$db": "admin" });
        conn.handle_client_message(&ping);

        assert!(conn.is_app());

        let find = make_op_msg(doc! { "find": "users", "filter": {}, "$db": "mydb" });
        let event = conn.handle_client_message(&find);
        assert!(event.is_none());
    }

    #[test]
    fn internal_commands_no_event() {
        let internal_docs = vec![
            doc! { "ping": 1 },
            doc! { "isMaster": 1 },
            doc! { "buildInfo": 1 },
            doc! { "getMore": 12345_i64, "collection": "users" },
            doc! { "killCursors": "users", "cursors": [] },
        ];

        for d in &internal_docs {
            assert!(
                is_internal_command(d),
                "expected internal: {d:?}"
            );
        }

        let data_docs = vec![
            doc! { "find": "users" },
            doc! { "insert": "orders" },
            doc! { "delete": "sessions" },
        ];

        for d in &data_docs {
            assert!(
                !is_internal_command(d),
                "expected not internal: {d:?}"
            );
        }
    }

    #[test]
    fn terminate_prevents_events() {
        let mut conn = MongoConnection::new(
            "192.168.1.100".parse().unwrap(),
            test_identity_config(),
            test_schema_config(),
        );

        conn.terminate();
        assert_eq!(*conn.state(), MongoConnectionState::Terminated);

        let find = make_op_msg(doc! { "find": "users", "$db": "mydb" });
        let event = conn.handle_client_message(&find);
        assert!(event.is_none());
    }

    #[test]
    fn mark_authenticated_transitions_state() {
        let mut conn = MongoConnection::new(
            "192.168.1.100".parse().unwrap(),
            test_identity_config(),
            test_schema_config(),
        );

        let hello = make_op_msg(doc! { "hello": 1, "$db": "admin" });
        conn.handle_client_message(&hello);
        assert_eq!(*conn.state(), MongoConnectionState::Authenticating);

        mark_authenticated(&mut conn);
        assert_eq!(*conn.state(), MongoConnectionState::Ready);
        assert!(conn.class().is_some());
    }

    #[test]
    fn session_id_is_unique() {
        let c1 = MongoConnection::new(
            "127.0.0.1".parse().unwrap(),
            test_identity_config(),
            test_schema_config(),
        );
        let c2 = MongoConnection::new(
            "127.0.0.1".parse().unwrap(),
            test_identity_config(),
            test_schema_config(),
        );
        assert_ne!(c1.session_id(), c2.session_id());
    }
}
