# Proxy Implementation

> ⚠️ **Experimental / pre-1.0.** The wire-protocol surfaces (Postgres / MongoDB / S3) are implemented but not fully covered by tests. Expect rough edges on uncommon protocol paths. See [../README.md §Status](../README.md).

The proxy is a single Rust binary that listens on one port per supported protocol and forwards each connection to the corresponding upstream datastore. Responsibilities:

1. Classify every connection as `App` or `Admin` per [identity-separation.md](identity-separation.md).
2. For admin operations: parse the query, resolve affected users, emit an `AccessEvent` to NATS, wait for the JetStream ack, then forward upstream (fail-closed; see §"Audit gate" below).
3. For app operations: raw byte forwarding with no parsing or logging overhead.
4. On multi-VM topology: route admin connections to the Primary replica and tag the session for cross-replica verification against the drand-assigned Verifier.

The proxy is transparent at the wire level. Any Postgres client, MongoDB driver, or S3 SDK connects without modification.

---

## Architecture

```
                        ┌─────────────────────────────┐
Incoming connections    │     UNINC PROXY (Rust)       │
                        │                              │
  :5432 (Postgres) ────►│  ┌────────────────────────┐  │
                        │  │ Postgres protocol module│  │──► upstream Postgres
                        │  └────────────────────────┘  │
                        │                              │
  :27017 (MongoDB) ────►│  ┌────────────────────────┐  │
                        │  │ MongoDB protocol module │  │──► upstream MongoDB
                        │  └────────────────────────┘  │
                        │                              │
  :9000 (S3 HTTP)  ────►│  ┌────────────────────────┐  │
                        │  │ S3 HTTP module          │  │──► upstream S3 store
                        │  └────────────────────────┘  │
                        │                              │
                        │  ┌────────────────────────┐  │
                        │  │ Shared components:      │  │
                        │  │ - Identity classifier   │  │
                        │  │ - Event emitter (NATS)  │  │
                        │  │ - Connection pooling    │  │
                        │  │ - Replica router (M3)   │  │
                        │  └────────────────────────┘  │
                        └─────────────────────────────┘
```

Each protocol module is independent — it parses its own wire format and extracts the information the shared components need. The shared components (identity classification, NATS emission, replica routing) are protocol-agnostic. They receive a normalized `AccessEvent` struct regardless of whether it came from Postgres, MongoDB, or S3.

### The two pipelines

Every protocol module implements the same split:

**APP pipeline:** Raw socket forwarding. `recv()` on one socket, `send()` on the other. No parsing, no logging, no overhead. Less than 0.1ms added latency.

**ADMIN pipeline:** Parse the operation, extract table/collection/bucket + fields + filter, resolve affected users, **publish audit event to NATS and wait for JetStream ack (synchronous, fail-closed)**, then forward to upstream. The NATS publish adds ~sub-ms on the happy path. On NATS failure or timeout, the query is **rejected** — never forwarded. This is the "log-before-access" invariant; see §"The audit gate" below.

### The audit gate — per-protocol implementation

The audit gate enforces the log-before-access invariant: every admin query that reaches the database has already been durably committed to the audit stream. All three protocol modules implement the same pattern, adapted to their wire format:

1. Parse the incoming operation (SQL / BSON / HTTP)
2. Build an `AccessEvent` with affected users, action type, resource, scope
3. Call `nats.publish_for_affected_users(&event)` wrapped in `tokio::time::timeout`
4. **Wait for the JetStream ack** (the double `.await` in `publish_event` — first sends, second waits for durable ack)
5. On success → forward the query to upstream
6. On failure or timeout → reject the query, **never forward**

The timeout defaults to 500ms, overridable via `UNINC_AUDIT_PUBLISH_TIMEOUT_MS`.

**Per-protocol gate locations and error responses:**

| Protocol | Gate location | Error on NATS failure |
|---|---|---|
| **Postgres** | [`postgres/listener.rs:392`](../crates/proxy/src/postgres/listener.rs#L392) — `emit_event(&nats, event).await?` before `upstream.write_all`. The `?` propagates the error, so the query bytes never reach PgBouncer. | Postgres `ErrorResponse` packet, then connection dropped. |
| **MongoDB** | [`mongodb/listener.rs:306-334`](../crates/proxy/src/mongodb/listener.rs#L306) — `tokio::time::timeout(...)` + `publish_for_affected_users` inline, before upstream write. | `conn.terminate()` — drops the TCP connection, op not forwarded. |
| **S3** | [`s3/handler.rs:269-301`](../crates/proxy/src/s3/handler.rs#L269) — `tokio::time::timeout(...)` + `publish_for_affected_users` inline, before `forward_request`. | HTTP `503 Service Unavailable` with `SlowDown` error code. |

**The `emit_event` helper** (Postgres-specific, at [`postgres/listener.rs:460-523`](../crates/proxy/src/postgres/listener.rs#L460)):
- Skips publish if `affected_users` is empty (no one to notify)
- Skips publish if `nats` is `None` (dev/test only — **never deploy to prod without NATS**)
- Wraps `publish_for_affected_users` in `tokio::time::timeout(500ms)`
- On `Ok(Ok(()))` → logs success, returns `Ok(())`
- On `Ok(Err(e))` → logs "FAIL-CLOSED", returns `Err`
- On `Err(elapsed)` → logs "timed out — FAIL-CLOSED", returns `Err`

MongoDB and S3 inline the same logic rather than factoring it into a helper, because they each have a single entry point while Postgres has both simple and extended query paths.

**Why the gate must come after parsing, not before.** The audit event contains structured metadata: which end user is affected, what operation, which table/collection/bucket, a hash of the previous chain entry. You can't write that event without first understanding what the query *is*. So the order is: parse → audit gate → forward.

**Why fail-closed and not buffer-and-retry.** Buffering locally and retrying creates a window where data has been accessed but the chain hasn't been written yet. A crash during that window loses the audit event. Fail-closed is the only honest choice. See [ARCHITECTURE.md](../ARCHITECTURE.md) §"Capacity & overload protection" → "The trust-story invariant" for the full reasoning.

---

## Shared components

These are used by all three protocol modules.

### Normalized event format

Regardless of protocol, every admin operation produces the same struct:

```rust
struct AccessEvent {
    protocol: Protocol,            // Postgres | MongoDB | S3
    admin_id: String,              // Who performed the action
    action: ActionType,            // Read | Write | Delete | Export | SchemaChange
    resource: String,              // Table name / collection name / bucket+key
    scope: String,                 // Human-readable summary rendered by any :9091 reader
    query_fingerprint: [u8; 32],   // SHA-256 of normalized query/operation
    affected_users: Vec<UserId>,   // Resolved from filter/key pattern
    timestamp: i64,
    session_id: Uuid,
    metadata: HashMap<String, String>,
}
```

Published to NATS subject `uninc.access.{user_id}`. The chain engine consumes these and doesn't care which protocol generated them.

### Identity classification

Multi-signal admin/app classification (detailed in `identity-separation.md`):

```rust
enum ConnectionClass {
    App,                    // Whitelisted — passthrough, no logging
    Admin(AdminIdentity),   // Log everything
    Suspicious(String),     // Alert — unexpected pattern from app source
}

fn classify(
    source_ip: IpAddr,
    credential: &Credential,
    behavior: &ConnectionBehavior,
    client_cert: Option<&Certificate>,
    config: &IdentityConfig,
) -> ConnectionClass { ... }
```

### Affected user resolution

The same resolution logic applies across protocols — only the query language differs:

```rust
trait UserResolver {
    /// Given a parsed operation, return the affected user IDs
    async fn resolve(&self, operation: &ParsedOperation) -> Vec<UserId>;
}

// Implementations:
// - PostgresResolver: parses SQL WHERE clauses
// - MongoResolver: parses MongoDB filter documents
// - S3Resolver: matches object key against regex patterns
```

### Connection pooling

Per-upstream pool, shared config:

```rust
struct PoolConfig {
    min_connections: u32,        // Default: 2
    max_connections: u32,        // Default: 20
    idle_timeout: Duration,      // Default: 5 min
    connection_timeout: Duration, // Default: 5s
}
```

On multi-VM topology with replicas, the proxy maintains separate pools per replica. Admin queries always execute against Primary (pinned to `replicas[0]`); the drand-assigned Verifier replica is only read at verification time, not per-query.

### Replica routing (multi-VM topology)

Protocol-agnostic. Admin queries route to Primary; the `RoleAssignment` records which replica is the per-session Verifier so the nightly task knows which state to fingerprint:

```rust
struct ReplicaRouter {
    replicas: Vec<UpstreamPool>,
    assignment: RoleAssignment,  // { primary, verifier, seed, ... }
}

impl ReplicaRouter {
    fn primary(&self) -> &UpstreamPool { &self.pool_for(&self.assignment.primary) }
    fn verifier(&self) -> &UpstreamPool { &self.pool_for(&self.assignment.verifier) }
}
```

The old three-role (Access / Witness / Verifier) model from the 2026-04-15 predecessor design is gone — there is no `witnesses()` routing method, because the Witness slot had zero runtime behavior. See [`crates/verification/src/assignment.rs`](../crates/verification/src/assignment.rs) and [replica-verification.md](replica-verification.md) for the full two-role model.

Cross-replica Postgres verification uses streaming replication. MongoDB and S3 cross-replica verification use primitive-native mechanisms (`dbHash`, ETag manifest) — see [replica-verification.md](replica-verification.md) §"Replication model".

---

## Protocol module: PostgreSQL

**Difficulty: Hard.** Binary wire protocol with connection state, prepared statements, and extended query lifecycle.

**Protocol documentation:** https://www.postgresql.org/docs/current/protocol.html

### Key messages (client → server)

| Message | Purpose | Proxy action |
|---|---|---|
| StartupMessage | Handshake with username/database | Extract credentials, classify |
| Query (Simple) | SQL string | Parse SQL, extract tables/columns/filters |
| Parse (Extended) | Prepared statement template | Parse SQL template |
| Bind | Bind parameters | Record parameter values for fingerprinting |
| Execute | Execute prepared statement | Forward, emit event |
| Terminate | Close connection | Trigger session-end verification (multi-VM topology; T1 trigger is deferred in v1, so the session is recorded and picked up by the nightly T3 instead) |

### Key messages (server → client)

| Message | Purpose | Proxy action |
|---|---|---|
| AuthenticationOk | Auth succeeded | Confirm classification |
| RowDescription | Column metadata | Extract column names for scope |
| DataRow | Result row | Count rows |
| CommandComplete | Query finished | Record rows affected |
| ErrorResponse | Query failed | Don't log failed queries |

### SQL parsing

Uses `sqlparser-rs` to extract tables, columns, filters, and action type:

```rust
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

fn parse_postgres_query(sql: &str) -> ParsedOperation {
    let dialect = PostgreSqlDialect {};
    let ast = Parser::parse_sql(&dialect, sql).unwrap();
    // Walk AST → extract tables, columns, WHERE predicates, action type
    ParsedOperation { tables, columns, filters, action }
}
```

### Query fingerprinting

```
Raw:         SELECT name, email FROM users WHERE id = 42 AND status = 'active'
Normalized:  select name, email from users where id = ? and status = ?
Fingerprint: SHA-256("select name, email from users where id = ? and status = ?")
```

### Affected user resolution

```rust
impl UserResolver for PostgresResolver {
    async fn resolve(&self, op: &ParsedOperation) -> Vec<UserId> {
        for table in &op.tables {
            if let Some(user_table) = self.schema.user_tables.get(&table.name) {
                // Direct ID in WHERE clause → return immediately
                if let Some(id) = op.get_filter_value(&user_table.user_id_column) {
                    return vec![id];
                }
                // Otherwise, execute resolution query
                let query = format!(
                    "SELECT DISTINCT {} FROM {} WHERE {}",
                    user_table.user_id_column, table.name, op.where_clause
                );
                return self.execute_resolution(&query).await;
            }
        }
        vec![]
    }
}
```

### Crate dependencies (Postgres-specific)

| Crate | Purpose |
|---|---|
| `sqlparser` | SQL parsing and AST extraction |
| `postgres-protocol` | Postgres wire protocol message parsing |

---

## Protocol module: MongoDB

**Difficulty: Medium.** Binary wire protocol (OP_MSG), but simpler state machine than Postgres. No prepared statements. Operations are BSON documents.

**Protocol documentation:** https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/

### Wire protocol overview

MongoDB uses the OP_MSG wire protocol (since MongoDB 3.6). Every operation is a BSON document wrapped in an OP_MSG frame:

```
┌──────────────────────────────────────┐
│  OP_MSG Header (16 bytes)             │
│  - messageLength: i32                │
│  - requestID: i32                    │
│  - responseTo: i32                   │
│  - opCode: i32 (2013 = OP_MSG)       │
├──────────────────────────────────────┤
│  flagBits: u32                        │
├──────────────────────────────────────┤
│  Section 0 (body): BSON document     │
│  {                                    │
│    "find": "users",                  │
│    "filter": { "email": "a@b.com" }, │
│    "$db": "mydb"                     │
│  }                                    │
└──────────────────────────────────────┘
```

### Key operations

| Command | BSON field | Action type | Equivalent SQL |
|---|---|---|---|
| `find` | `"find": "collection"` | Read | SELECT |
| `insert` | `"insert": "collection"` | Write | INSERT |
| `update` | `"update": "collection"` | Write | UPDATE |
| `delete` | `"delete": "collection"` | Delete | DELETE |
| `aggregate` | `"aggregate": "collection"` | Read | SELECT with GROUP BY |
| `count` | `"count": "collection"` | Read | SELECT COUNT(*) |
| `findAndModify` | `"findAndModify": "collection"` | Write | UPDATE ... RETURNING |
| `getMore` | `"getMore": cursor_id` | Read (continuation) | FETCH from cursor |
| `drop` | `"drop": "collection"` | SchemaChange | DROP TABLE |
| `createIndexes` | `"createIndexes": "collection"` | SchemaChange | CREATE INDEX |

### Parsing strategy

Unlike Postgres where you need a SQL parser, MongoDB operations are already structured BSON. The proxy:

1. Reads the OP_MSG frame header
2. Deserializes the Section 0 BSON document
3. Checks the first key — that's the command name (`find`, `insert`, etc.)
4. The value of that key is the collection name
5. The `filter` field (for find/update/delete) is the equivalent of a WHERE clause
6. The `$db` field identifies the database

```rust
use bson::Document;

fn parse_mongodb_operation(body: &Document) -> ParsedOperation {
    // The first key in the document is the command
    let (command, collection) = body.iter().next().unwrap();
    let collection_name = collection.as_str().unwrap_or("unknown");
    
    let action = match command {
        "find" | "aggregate" | "count" | "distinct" => ActionType::Read,
        "insert" => ActionType::Write,
        "update" | "findAndModify" => ActionType::Write,
        "delete" => ActionType::Delete,
        "drop" | "createIndexes" | "dropIndexes" => ActionType::SchemaChange,
        _ => ActionType::Read, // Default to Read for unknown commands
    };
    
    let filter = body.get_document("filter").ok();
    
    ParsedOperation {
        tables: vec![TableRef { name: collection_name.to_string() }],
        columns: vec![], // MongoDB doesn't select specific fields by default
        filters: filter.map(|f| extract_filter_fields(f)).unwrap_or_default(),
        action,
    }
}
```

### Query fingerprinting (MongoDB)

Same principle as Postgres — strip values, keep structure:

```
Raw:         { "find": "users", "filter": { "email": "alice@example.com", "age": { "$gt": 25 } } }
Normalized:  { "find": "users", "filter": { "email": "?", "age": { "$gt": "?" } } }
Fingerprint: SHA-256(normalized)
```

The normalization recursively replaces all leaf values in the BSON document with `"?"` while preserving the key structure and operator names (`$gt`, `$in`, `$regex`, etc.).

```rust
fn normalize_bson(doc: &Document) -> Document {
    let mut normalized = Document::new();
    for (key, value) in doc.iter() {
        match value {
            Bson::Document(inner) if key.starts_with('$') => {
                // Preserve operator, normalize its operand
                normalized.insert(key, normalize_bson(inner));
            }
            Bson::Document(inner) => {
                normalized.insert(key, normalize_bson(inner));
            }
            Bson::Array(arr) => {
                normalized.insert(key, Bson::String("?[]".to_string()));
            }
            _ => {
                normalized.insert(key, Bson::String("?".to_string()));
            }
        }
    }
    normalized
}
```

### Affected user resolution (MongoDB)

MongoDB filters are BSON documents, not SQL WHERE clauses. The resolver traverses the filter to find the user ID field:

```rust
impl UserResolver for MongoResolver {
    async fn resolve(&self, op: &ParsedOperation) -> Vec<UserId> {
        let collection = &op.tables[0].name;
        if let Some(user_col) = self.schema.user_tables.get(collection) {
            if let Some(filter) = &op.raw_filter {
                // Direct match: { "user_id": 42 }
                if let Some(id) = filter.get(user_col.user_id_column) {
                    return vec![bson_to_user_id(id)];
                }
                // $in operator: { "user_id": { "$in": [42, 43, 44] } }
                if let Some(in_doc) = filter.get_document(user_col.user_id_column).ok() {
                    if let Some(ids) = in_doc.get_array("$in").ok() {
                        return ids.iter().filter_map(bson_to_user_id).collect();
                    }
                }
                // Complex filter → execute resolution query against upstream
                return self.resolve_via_query(collection, filter).await;
            }
        }
        vec![]
    }
}
```

### Admin identification (MongoDB)

MongoDB authentication uses SCRAM-SHA-256 (or SCRAM-SHA-1). The proxy intercepts the `saslStart` and `saslContinue` messages during the authentication handshake to extract the username:

```rust
fn extract_mongo_username(sasl_start: &Document) -> Option<String> {
    // The payload contains the username in the SCRAM handshake
    if let Some(payload) = sasl_start.get_binary_generic("payload").ok() {
        // Parse SCRAM client-first-message: "n,,n=username,r=nonce"
        let payload_str = String::from_utf8_lossy(payload);
        if let Some(user_part) = payload_str.split(',').find(|s| s.starts_with("n=")) {
            return Some(user_part[2..].to_string());
        }
    }
    None
}
```

### Projection tracking

MongoDB `find` commands can include a `projection` field that specifies which fields to return:

```json
{ "find": "users", "filter": { "_id": 42 }, "projection": { "email": 1, "name": 1 } }
```

The proxy extracts projection fields for the `scope` field in the chain entry:

```
scope: "users collection, fields: email, name; filter: _id"
```

If no projection is specified, MongoDB returns all fields. The scope records: `"users collection, all fields; filter: _id"`.

### Crate dependencies (MongoDB-specific)

| Crate | Purpose |
|---|---|
| `bson` | BSON serialization/deserialization |
| `mongodb-wire-protocol` or custom | OP_MSG frame parsing (may need custom implementation) |

---

## Protocol module: S3 (HTTP)

**Difficulty: Easy.** Standard REST over HTTP. No binary protocol. No connection state.

### Why S3 is dramatically simpler

S3 operations are HTTP requests:

```
PUT    /bucket/key         → Upload object
GET    /bucket/key         → Download object
DELETE /bucket/key         → Delete object
HEAD   /bucket/key         → Check existence
GET    /bucket?list-type=2 → List objects
```

The proxy is an HTTP reverse proxy using `axum` + `hyper`. It inspects method + path + auth header, forwards to upstream, emits event. No binary parsing. No state machine.

### Admin operations (logged)

| Operation | HTTP method | Chain action |
|---|---|---|
| GetObject | GET | Read |
| PutObject | PUT | Write |
| DeleteObject | DELETE | Delete |
| CopyObject | PUT (x-amz-copy-source header) | Read + Write |
| ListObjectsV2 | GET (?list-type=2) | Read |
| CompleteMultipartUpload | POST | Write (logged here, not per-part) |

Bucket-level operations (CreateBucket, DeleteBucket) are infrastructure, not user data. Not logged by default.

### Auth header inspection

S3 uses AWS Signature V4. The proxy extracts the access key ID — doesn't verify the signature (that's the upstream's job):

```rust
fn extract_s3_access_key(auth_header: &str) -> Option<String> {
    // "AWS4-HMAC-SHA256 Credential=KEYID/date/region/s3/aws4_request, ..."
    auth_header.find("Credential=")
        .and_then(|i| {
            let after = &auth_header[i + 11..];
            after.find('/').map(|j| after[..j].to_string())
        })
}
```

### Object key → user mapping

Configured via regex patterns with named capture groups:

```yaml
s3:
  user_data_patterns:
    - bucket: uploads
      key_pattern: "users/(?P<user_id>[^/]+)/.*"
    - bucket: media
      key_pattern: "(?P<user_id>[^/]+)/.*"
  excluded_prefixes:
    - system/
    - logs/
```

```rust
impl UserResolver for S3Resolver {
    async fn resolve(&self, op: &ParsedOperation) -> Vec<UserId> {
        let key = &op.resource; // e.g., "uploads/users/42/avatar.jpg"
        for pattern in &self.config.user_data_patterns {
            if let Some(captures) = pattern.regex.captures(key) {
                if let Some(user_id) = captures.name("user_id") {
                    return vec![user_id.as_str().to_string()];
                }
            }
        }
        vec![] // Key doesn't match any pattern — not logged
    }
}
```

### Query fingerprinting (S3)

```
Actual:      GET /uploads/users/42/avatar.jpg
Fingerprint: SHA-256("GET /uploads/users/{user_id}/*")
```

### Multipart uploads

Large uploads use S3 multipart protocol. The proxy logs at `CompleteMultipartUpload` (step 3), not per-chunk:

```
ChainEntry {
  action: Write,
  resource: "s3://uploads/users/42/large_export.zip",
  scope: "multipart upload, 250 MB, 12 parts",
}
```

### Presigned URLs

An admin can generate a presigned URL that provides temporary direct access to an object, bypassing the proxy. The proxy logs the URL generation as a Read event. The subsequent access via the presigned URL is not interceptable. On multi-VM topology where S3 lives in the private subnet, presigned URLs to internal MinIO endpoints don't work from outside the VPC anyway.

### S3-compatible store coverage

One implementation covers all S3-compatible stores:

| Store | Notes |
|---|---|
| MinIO | Default for Docker deployments |
| Cloudflare R2 | No egress fees |
| AWS S3 | The original |
| GCS (S3-compatible mode) | Requires interoperability API |
| DigitalOcean Spaces | Works without modification |
| Backblaze B2 | Works without modification |

### Crate dependencies (S3-specific)

| Crate | Purpose |
|---|---|
| `axum` | HTTP server framework |
| `hyper` | HTTP client for upstream forwarding |
| `regex` | Key pattern matching |

---

## Complexity comparison

| Aspect | PostgreSQL | MongoDB | S3 |
|---|---|---|---|
| Protocol type | Custom binary wire protocol | Binary (OP_MSG) over TCP | HTTP REST |
| State machine | Complex (startup, auth, simple query, extended query, copy, replication) | Medium (auth handshake, then stateless commands) | None (stateless HTTP) |
| Query language | SQL (needs full parser) | BSON documents (structured, no parsing needed) | URL path + query params |
| Prepared statements | Yes (Parse/Bind/Execute lifecycle) | No | No |
| Connection model | Long-lived, stateful | Long-lived, stateful | Stateless (or keep-alive) |
| Admin identification | Username from StartupMessage | Username from SCRAM handshake | Access key from Authorization header |
| Affected user resolution | SQL WHERE clause parsing | BSON filter document traversal | Regex pattern matching on object key |
| Estimated dev effort | 6-8 weeks | 3-4 weeks | 1-2 weeks |
| Replica verification support | v1 (streaming replication) | v2 (MongoDB replica set model) | N/A (object storage doesn't replicate the same way) |

---

## Performance targets

| Metric | Target | Notes |
|---|---|---|
| App passthrough latency (all protocols) | < 0.1ms | No parsing, raw forwarding |
| Admin passthrough latency (Postgres) | < 1ms | SQL parse + synchronous NATS publish (sub-ms happy path) + forward |
| Admin passthrough latency (MongoDB) | < 1ms | BSON inspection + synchronous NATS publish + forward |
| Admin passthrough latency (S3) | < 1ms | HTTP inspect + synchronous NATS publish + forward |
| Concurrent connections | > 1000 | Tokio async, per-protocol listeners |
| Memory (idle) | < 50MB | No JVM, no GC |
| Memory (1000 connections) | < 200MB | ~200KB per connection |
| Binary size | < 25MB | All three modules compiled in |

---

## Rust crate dependencies (full)

| Crate | Used by | Purpose |
|---|---|---|
| `tokio` | All | Async runtime, TCP listeners |
| `sha2` | All | SHA-256 fingerprinting |
| `nats` | All | Event emission |
| `serde` / `serde_json` | All | Event serialization |
| `tracing` | All | Structured logging |
| `config` | All | Configuration parsing |
| `clap` | CLI | Argument parsing |
| `rustls` | Postgres, MongoDB | TLS termination |
| `sqlparser` | Postgres | SQL AST parsing |
| `postgres-protocol` | Postgres | Wire protocol messages |
| `bson` | MongoDB | BSON ser/de |
| `axum` | S3 | HTTP server |
| `hyper` | S3 | HTTP client |
| `regex` | S3 | Key pattern matching |

---

## Configuration (unified)

```yaml
# uninc.yml — the proxy listens on hard-coded external ports:
#   Postgres: 6432   (native 5432 + 1000)
#   MongoDB:  28017  (native 27017 + 1000)
#   S3 HTTP:  10000  (native 9000 + 1000)
# These are wired into the binary and cannot be overridden via config.
proxy:
  # --- Protocol listeners ---
  postgres:
    enabled: true
    upstream: "postgres://user:pass@postgres:5432/mydb"
    pool: { min: 2, max: 20, idle_timeout_secs: 300 }

  mongodb:
    enabled: true
    upstream: "mongodb://user:pass@mongo:27017/mydb"
    pool: { min: 2, max: 20, idle_timeout_secs: 300 }

  s3:
    enabled: true
    upstream: "http://minio:9000"
    user_data_patterns:
      - bucket: uploads
        key_pattern: "users/(?P<user_id>[^/]+)/.*"
    excluded_prefixes: [system/, logs/]
    log_presigned_url_generation: true
    multipart_log_on_complete_only: true

  # --- Shared config ---
  tls:
    enabled: false
    cert_path: /etc/uninc/tls/cert.pem
    key_path: /etc/uninc/tls/key.pem

  nats:
    url: "nats://nats:4222"
    subject_prefix: "uninc.access"

  identity:
    mode: source+credential      # credential | source+credential | mtls+source+credential
    app_sources:
      - hostname: app
      - hostname: worker
    admin_credentials:
      postgres: [{ username: admin }, { username: dba }]
      mongodb: [{ username: admin }, { username: root }]
      s3: [{ access_key: ADMIN_ACCESS_KEY_ID }]
    app_credentials:
      postgres: [{ username: app_user }]
      mongodb: [{ username: app_user }]
      s3: [{ access_key: APP_ACCESS_KEY_ID }]
    behavioral_fingerprinting: true

  schema:
    user_tables:
      - table: users
        user_id_column: id
        sensitive_columns: [email, phone, ssn]
      - table: orders
        user_id_column: user_id
    excluded_tables: [migrations, schema_versions]

  mode: greenfield               # proxy-only | greenfield | full
```
