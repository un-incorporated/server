# Architecture

Reference for how the components fit together, what data flows where, and how each deployment shape differs. Pairs with [QUICKSTART.md](QUICKSTART.md) (Docker walkthrough) and [DEVELOPMENT.md](DEVELOPMENT.md) (build/test from source).

> ⚠️ **Experimental / pre-1.0.** Describes the v1 design as implemented in `crates/`. Coverage and test depth vary by component — see [README.md §Status](README.md) before relying on any specific flow.

## Repository layout

`server/` is backend-only; no frontend ships here. `docker compose up` brings up a complete node (proxy + chain-engine + NATS + optional replicas + optional Observer). The chain is exposed at the proxy's `:9091` HTTP API; any UI — customer app, `curl`, WASM verifier — reads from that port.

```text
server/
├── crates/                       Rust workspace (8 crates)
│   ├── uninc-common/             Shared types (AccessEvent, DeploymentChainEntry,
│   │                             config structs), NATS client, SHA-256 / AES-GCM
│   ├── proxy/                    uninc-proxy binary — Postgres/MongoDB/S3 wire
│   │                             protocols, guard pipeline, fail-closed audit gate,
│   │                             :9091 chain API, :9090 health
│   ├── chain-engine/             chain-engine binary — NATS consumer that writes
│   │                             per-user + deployment chains to disk
│   ├── chain-store/              On-disk chain format + LRU + MultiReplica fan-out
│   ├── chain-verifier-wasm/      Rust → WebAssembly: same hash code runs in the
│   │                             end user's browser
│   ├── verification/             Cross-replica state comparison (drand-seeded
│   │                             assignment) + failure handler chain
│   │                             (multi-VM topology only)
│   ├── observer/                 uninc-observer binary — independent WAL/oplog/
│   │                             bucket-notify subscriber on its own VM
│   └── cli/                      uninc binary — verify/export/status from the shell
├── docker/                       Self-hosted runtime
│   ├── docker-compose.yml        Full greenfield stack (proxy + chain + NATS +
│   │                             Postgres + MongoDB + MinIO)
│   ├── docker-compose.self-hosted.yml
│   │                             Drop-in mode: proxy in front of YOUR existing DB
│   ├── docker-compose.observer.yml
│   │                             Adds the Observer VM role (multi-VM topology)
│   ├── proxy/Dockerfile          Multi-stage build — produces BOTH the
│   │                             uninc-proxy and chain-engine binaries
│   │                             in one image; chain-engine is launched
│   │                             by overriding the entrypoint
│   ├── observer/Dockerfile       Multi-stage build for observer
│   ├── pgbouncer/                PgBouncer sidecar config (loopback-only :6433)
│   └── config/                   nats.conf, postgres initdb scripts
├── deploy/                       Cloud IaC recipes (see deploy/README.md)
│   ├── gcp/                      Terraform HCL — shipping, runnable
│   ├── aws/                      Placeholder (README only, contributions welcome)
│   └── bare-metal/               Placeholder (README only)
├── docs/                         Deep-dive protocol specs
├── ARCHITECTURE.md               (this file)
├── DEVELOPMENT.md                Build / test / run from source
├── TECHSTACK.md                  Every dep, why we chose it, what we hand-roll
├── LICENSE                       AGPLv3
└── uninc.yml.example             Config reference — copy to uninc.yml
```

The full stack is runnable from `docker/` + `uninc.yml.example`.

---

## Design principle: log all accesses, label by identity

Every query routed through the proxy produces a chain entry — app traffic, admin traffic, cron jobs, background workers. The proxy does not filter by "importance"; the end user receives every access that touched their data and judges the legitimacy themselves.

| Connection source | Upstream role | Chain label | Reader interpretation |
|---|---|---|---|
| End user via the app server | `app_user` | `app:app_user` | Expected — app-driven access. |
| Background ML / cron / worker | `app_user` | `app:app_user` | Legitimate but visible — reader sees an unexplained 3am read and can investigate. |
| Admin via psql / GUI / migration | `admin` / `dba` / `postgres` | `admin@<ident>` | High-attention — direct admin access to user data. |

### Two identities, App and Admin

The DB role in the connection string determines the label. Configured in `uninc.yml`:

```yaml
identity:
  admin_credentials:
    postgres:
      - username: admin
      - username: dba
      - username: postgres
  app_credentials:
    postgres:
      - username: app_user
      - username: web
```

Both app and admin connections go through the same audit gate (synchronous NATS publish + JetStream ack before the query reaches the database). The label is different; the logging is the same.

**"Suspicious" connections** are classified when something doesn't fit (e.g., admin credentials from an app container's IP). Logged like admin with a "suspicious" tag.

### Summary: everything is logged

| Connection | Postgres role | Classified as | Chain entry label | Overhead |
|---|---|---|---|---|
| End user using the app | `app_user` | `App` | `app:app_user` | ~1ms |
| Cron job / background worker | `app_user` | `App` | `app:app_user` | ~1ms |
| ML pipeline reading data | `app_user` | `App` | `app:app_user` | ~1ms |
| Admin running psql | `admin` | `Admin` | `admin@company.com` | ~1ms |
| Support engineer investigating | `support` | `Admin` | `support@company.com` | ~1ms |
| DBA running a migration | `postgres` | `Admin` | `postgres` | ~1ms |
| Unknown pattern from app source | `admin` from app IP | `Suspicious` | `suspicious:...` | ~1ms |

### Data retention

Chain data is kept for `chain.retention_days` (default: 365 days / 1 year). After that, entries are auto-deleted by a daily reaper task (`chain-engine/src/reaper.rs`) that walks chain directories, reads `meta.json`, and removes entries older than the cutoff. Each reaped batch emits a `RetentionSweep` tombstone to the deployment chain — quorum-replicated in multi-VM topologies — so the retention action is itself tamper-evident. SOC2 and PCI DSS require 1 year minimum; GDPR Article 5(1)(e) says "no longer than necessary."

Users can request earlier deletion under GDPR Article 17 (right to erasure) via `DELETE /api/v1/chain/u/{user_id_hash}` on the proxy. The handler publishes a `UserErasureRequested` tombstone to the deployment chain (permanent and tamper-evident), then deletes the per-user chain directory across all replicas. See `docs/chain-storage-architecture.md` §"Deletion" for the full flow.

---

## The four components

```text
                   ┌──────────────────────────────────────────────────────────┐
                   │                THE UNINCORPORATED SERVER                  │
                   │                                                          │
  Customer's app   │  ┌─────────────────────────────────────────────────────┐ │
  connects here    │  │            1. UNINC-PROXY (Rust binary)             │ │
  (one connection  │  │                                                     │ │
   string change)  │  │  Speaks native Postgres / MongoDB / S3 wire        │ │
       ──────────▶ │  │  protocols. The customer's app thinks it's         │ │
                   │  │  talking to the real database.                      │ │
                   │  │                                                     │ │
                   │  │  INTERNAL GUARD PIPELINE (per admin query):         │ │
                   │  │    1. Connection cap (semaphore)                    │ │
                   │  │    2. Rate limit (token bucket)                     │ │
                   │  │    3. Parse wire protocol                           │ │
                   │  │    4. AUDIT GATE: publish to NATS, wait for ack    │ │
                   │  │       → always publishes to deployment chain (_deployment)        │ │
                   │  │       → publishes to per-user chains if users found │ │
                   │  │       → FAIL-CLOSED: no ack = query rejected       │ │
                   │  │    5. Forward query to upstream database            │ │
                   │  │    6. Return result to client                       │ │
                   │  │                                                     │ │
                   │  │  Ports:                                             │ │
                   │  │    :5432  Postgres wire (or :6432 on host)          │ │
                   │  │    :27017 MongoDB wire  (or :28017 on host)         │ │
                   │  │    :9000  S3 HTTP       (or :10000 on host)         │ │
                   │  │    :9090  /health endpoint (3-tier: open /health,   │ │
                   │  │            open /health/ready, JWT-gated              │ │
                   │  │            /health/detailed)                          │ │
                   │  │    :9091  Chain API (read chain data — used by       │ │
                   │  │            www /v/ pages and customer frontends)      │ │
                   │  │                                                     │ │
                   │  │  Crate: crates/proxy/                               │ │
                   │  └───────────┬──────────────────────────┬──────────────┘ │
                   │              │ audit events             │ forwarded      │
                   │              │ (NATS publish)           │ queries        │
                   │              ▼                          ▼                │
                   │  ┌───────────────────┐   ┌──────────────────────────┐   │
                   │  │   NATS JetStream  │   │   UPSTREAM DATABASE      │   │
                   │  │   :4222 (internal) │   │                          │   │
                   │  │                   │   │   Postgres :5432          │   │
                   │  │  Stream:          │   │   MongoDB  :27017        │   │
                   │  │   UNINC_ACCESS    │   │   MinIO    :9000         │   │
                   │  │                   │   │                          │   │
                   │  │  Subjects:        │   │   (internal only —       │   │
                   │  │   uninc.access.   │   │    no published ports)   │   │
                   │  │     _deployment          │   │                          │   │
                   │  │     {user_id}     │   └──────────────────────────┘   │
                   │  └───────┬───────────┘                                  │
                   │          │ subscribe                                     │
                   │          ▼                                               │
                   │  ┌─────────────────────────────────────────────────────┐ │
                   │  │         2. CHAIN-ENGINE (Rust binary)               │ │
                   │  │                                                     │ │
                   │  │  NATS consumer. Routes messages:                    │ │
                   │  │    uninc.access._deployment     → deployment chain at /_deployment/      │ │
                   │  │    uninc.access.{user}   → per-user chain           │ │
                   │  │                                                     │ │
                   │  │  Hot tier (local disk, LRU-managed):                │ │
                   │  │    /data/chains/_deployment/             — deployment chain       │ │
                   │  │    /data/chains/{user_id_hash}/   — per-user chains │ │
                   │  │                                                     │ │
                   │  │  On-disk format per chain:                          │ │
                   │  │    chain.dat           — JSON-lines, append-only    │ │
                   │  │    chain.idx           — binary index (8b/entry)    │ │
                   │  │    head.hash           — 32-byte SHA-256 of latest  │ │
                   │  │    meta.json           — creation time, entry count │ │
                   │  │    verified_ranges.json — ranges marked verified    │ │
                   │  │                           by nightly trigger        │ │
                   │  │    durable_ranges.json — ranges quorum-durable on   │ │
                   │  │                           replica MinIOs            │ │
                   │  │  LRU eviction requires BOTH sidecars to mark safe.  │ │
                   │  │                                                     │ │
                   │  │  Durable tier (multi-VM only): MultiReplica fan-out │ │
                   │  │    to N replica MinIOs at :9002, quorum-acked.      │ │
                   │  │    Bucket: uninc-chain                              │ │
                   │  │    Prefixes: chains/user/{hash}/, chains/_deployment/      │ │
                   │  │                                                     │ │
                   │  │  Single-host: no replicas, no MinIO anywhere. Chain │ │
                   │  │    data stays on the proxy VM's local disk only —   │ │
                   │  │    no quorum, no cross-replica check. Weaker trust  │ │
                   │  │    shape, documented explicitly.                    │ │
                   │  │                                                     │ │
                   │  │  See docs/chain-storage-architecture.md for both.   │ │
                   │  │                                                     │ │
                   │  │  Crate: crates/chain-engine/                        │ │
                   │  └───────────┬─────────────────────────────────────────┘ │
                   │              │ chain data on disk, served via :9091                     │
                   │              ▼                                           │
                   │  ┌─────────────────────────────────────────────────────┐ │
                   │  │    3. CHAIN VISUALIZATION (no container — served    │ │
                   │  │       externally via the :9091 chain API)           │ │
                   │  │                                                     │ │
                   │  │  The chain API at :9091 on the proxy is the single │ │
                   │  │  source of truth. Two consumers:                    │ │
                   │  │                                                     │ │
                   │  │    a) www's /v/ pages (fetches from                 │ │
  End user opens   │  │       {proxyIp}:9091 chain API)                     │ │
  this in their    │  │                                                     │ │
  browser ─────▶   │  │    b) Customer's own frontend (calls :9091          │ │
                   │  │       directly)                                      │ │
                   │  │                                                     │ │
                   │  │  No UI container ships in server/. The chain API   │ │
                   │  │  built into uninc-proxy is the sole read surface.   │ │
                   │  └─────────────────────────────────────────────────────┘ │
                   │                                                          │
                   │  ┌─────────────────────────────────────────────────────┐ │
                   │  │    4. VERIFICATION ENGINE (Rust, inside proxy)      │ │
                   │  │                                                     │ │
                   │  │  Multi-VM only. Cross-replica state comparison      │ │
                   │  │  (NOT Byzantine fault tolerant in v1 — no quorum    │ │
                   │  │   vote, no 2f+1 threshold, just pairwise compare):  │ │
                   │  │    Primary  — pinned to replicas[0], the DB primary │ │
                   │  │    Verifier — picked per session from non-primary   │ │
                   │  │               replicas via Fisher-Yates shuffle     │ │
                   │  │                                                     │ │
                   │  │  Assignment: drand-seeded per-session shuffle       │ │
                   │  │    (drand round + signature stored on the session   │ │
                   │  │    record as an auditable proof of which replica    │ │
                   │  │    was picked to verify).                           │ │
                   │  │                                                     │ │
                   │  │  v1 trigger: **ONLY T3 nightly**.                   │ │
                   │  │    T3: once per day, jittered 02:00–04:00 UTC,      │ │
                   │  │        full cross-replica head comparison, marks    │ │
                   │  │        entries verified, drives LRU eviction,       │ │
                   │  │        fires failure handler on divergence.         │ │
                   │  │                                                     │ │
                   │  │  Scheduler is error-tolerant: tokio::time::timeout  │ │
                   │  │    (30min), futures::FutureExt::catch_unwind for    │ │
                   │  │    panics, min sleep floor, exponential backoff on  │ │
                   │  │    repeated failures. One bad run never kills the   │ │
                   │  │    loop.                                            │ │
                   │  │                                                     │ │
                   │  │  Deferred: T1 per-session, T2 periodic              │ │
                   │  │    sampling, T4 randomized reshuffle.               │ │
                   │  │                                                     │ │
                   │  │  Per-primitive ReplicaStateVerifier trait:          │ │
                   │  │    verifiers/postgres.rs — SHA-256 over sorted rows │ │
                   │  │    verifiers/mongodb.rs  — dbHash (v1 stub)         │ │
                   │  │    verifiers/s3.rs       — manifest hash of ETags   │ │
                   │  │                                                     │ │
                   │  │  Failure handler chain (verification/src/failure.rs)│ │
                   │  │    1. Deployment chain entry (VerificationFailure)         │ │
                   │  │    2. NATS alert to configured endpoint             │ │
                   │  │    3. Customer webhook (Slack/PagerDuty)            │ │
                   │  │    4. Credential revoke (proxy-local deny list)    │ │
                   │  │    5. Read-only lockdown (on severity=Critical)     │ │
                   │  │                                                     │ │
                   │  │  Crate: crates/verification/                        │ │
                   │  └─────────────────────────────────────────────────────┘ │
                   └──────────────────────────────────────────────────────────┘
```

---

## Component 5: the Observer VM (multi-VM topology only)

The four components above all run on the **proxy VM**. The Observer runs on its own dedicated VM in the Verified and Enterprise topologies, and it is the piece that makes the trust story survive a compromised proxy. Without it, the proxy could write consistent tampered data to its own chain (and to every replica chain-MinIO it fans out to) and head comparison would agree with itself — multi-copy storage does not defend against a writer that controls every copy.

```text
┌─ Observer VM (private subnet, no SSH, no public IP) ──────────────────────┐
│                                                                            │
│  uninc-observer (Rust binary, crate: crates/observer/)                     │
│                                                                            │
│  Subscribes directly to each upstream primitive's NATIVE replication       │
│  stream using read-only credentials issued by an out-of-band control plane (NOT by the       │
│  proxy):                                                                    │
│                                                                            │
│    Postgres  → logical replication via pg_logical_slot_get_changes()        │
│                 (tokio-postgres, standard SQL polling)                      │
│    MongoDB   → Change Streams via the official driver's watch()            │
│    MinIO     → bucket notifications published by MinIO itself to NATS      │
│                                                                            │
│  For each observed operation, the Observer hashes with the same            │
│  UNINC_CHAIN_V1 algorithm the proxy uses and appends to its own            │
│  independent deployment chain on local disk.                                │
│                                                                            │
│  Ports:                                                                     │
│    :2026  Observer HTTP endpoint — read chain head                          │
│           (internal-only; GCE firewall restricts inbound to the             │
│           proxy VM's service-account tag; auth via shared                   │
│           x-uninc-read-secret header provisioned by the control plane)      │
└────────────────────────────────────────────────────────────────────────────┘
```

**The key structural property:** the Observer's input is produced by Postgres / MongoDB / MinIO themselves — software written by upstream projects, not by us and not by the operator. A compromised proxy has no code path to suppress, filter, or forge what the Observer sees. The Observer's credentials are issued out-of-band from the proxy's own provisioning, so the proxy cannot rotate the Observer out of the loop either.

### Two read paths — end user vs verification task

Each VM holds its own independent chain. They serve different readers on different ports with different trust semantics:

```text
End user's browser
    │
    │  GET :9091   (public, JWT-gated chain API on the proxy)
    ▼
proxy's chain ──▶ WASM-verified in user's browser

Verification task  (runs on the proxy VM, nightly T3 + session-end)
    │
    │  GET :2026/observer/chain/{id}/head
    │       (internal-only, GCE firewall restricts inbound to the
    │        proxy VM's service-account tag, shared-secret header auth)
    ▼
observer's chain head
    │
    ▼
hash-by-hash comparison against the proxy's local chain head
    │
    ▼
divergence? → failure handler chain (verification/src/failure.rs):
    · VerificationFailure entry appended to the deployment chain
    · NATS alert to the configured alerting endpoint
    · credential revoke (proxy-local deny list)
    · read-only lockdown (on severity=Critical)
```

End users only ever read the proxy's chain — they do **not** hit the Observer directly, and the Observer has no public-facing surface. When the Observer detects divergence, the failure handler writes a `VerificationFailure` entry to the deployment chain, and **that** entry is the visible trail end users see through the normal `:9091` API. In other words: the Observer is silent infrastructure whose presence is only noticed when a compromise fires it.

### v1 limits

- **Single Observer VM per deployment.** Not a Byzantine quorum. Simultaneous compromise of proxy + Observer can still forge history. v2 multi-observer quorum closes this.
- **Write-centric coverage.** Replication streams carry writes only, so a compromised proxy fabricating read results (returning data that was never in the database) is detectable only via secondary consequences. v2 value-hash chain entries + external chain-head publication narrow this.
- **Payload-level comparison, not head-byte equality.** Per protocol spec §5.5.2, the Observer emits `ObservedDeploymentEvent` (§4.12) — a four-field subset `{action, resource, actor_id_hash, query_fingerprint}` recoverable from replication streams alone. Scheduled Verification's Process 2 walks the proxy's deployment chain and the observation chain from monotonic cursors, projects each projectable proxy entry via `project_to_observed`, canonicalizes both payloads per §4.9, and byte-compares. Rich proxy-side metadata (source IP, session, correlation ID) lives outside the hashed payload bytes (spec §6.4 sidecar). Head-level byte equality is not an invariant — the two chains have independent lineage by construction.
- **Capacity & overload protection: rate-limit + timeouts only; no behavioral tracking, no edge DDoS.** v1 enforces per-IP and per-credential token-bucket rate limits at every primitive's listener (`crates/proxy/src/rate_limit.rs`) and per-class idle timeouts (`crates/uninc-common/src/config.rs::TimeoutConfig`). Both are configured via `uninc.yml` and on by default in mothership-provisioned deployments (since 2026-04-26). `BehavioralTracker` ([crates/proxy/src/identity/behavioral.rs](crates/proxy/src/identity/behavioral.rs)) is built and tested but not yet instantiated by the identity classifier — wiring tracked for v1.1. Layer-3/4 DDoS is undefended at the v1 data plane (single GCE VM with the customer's reserved IP attached directly to the NIC); the v1.1 "Proxy capacity tier" item adds a regional Network Load Balancer + Cloud Armor in front.

---

## Protocol data types (code-as-schema)

The protocol has no `.proto` or `.graphql` schema file. The Rust structs in `crates/uninc-common/src/types.rs` are the canonical schema. Everything else (NATS messages, chain entries, chain API responses) derives from these types.

### AccessEvent — the normalized event the proxy produces

Every query through the proxy produces an `AccessEvent`. This is the intermediate representation — it gets published to NATS, and the chain-engine consumes it to create chain entries.

```
AccessEvent {
  protocol:          Protocol         // Postgres | MongoDB | S3
  admin_id:          String           // who performed the action
  action:            ActionType       // Read | Write | Delete | Export | SchemaChange
  resource:          String           // table / collection / bucket+key
  scope:             String           // "columns: email, name; filter: id = 42"
  query_fingerprint: [u8; 32]        // SHA-256 of normalized query (never raw SQL)
  affected_users:    Vec<String>      // resolved user IDs (may be empty)
  timestamp:         i64              // Unix millis
  session_id:        Uuid             // one per admin connection
  metadata:          Map<String,String> // source IP, database name, etc.
}
```

Example — admin runs `SELECT email, phone FROM users WHERE id = 42`:

```json
{
  "protocol": "Postgres",
  "admin_id": "dba@company.com",
  "action": "Read",
  "resource": "users",
  "scope": "columns: email, phone; filter: id = 42",
  "query_fingerprint": "a1b2c3d4e5f6...  (SHA-256 of 'select email, phone from users where id = ?')",
  "affected_users": ["42"],
  "timestamp": 1744444800000,
  "session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "metadata": {
    "source_ip": "10.0.1.50",
    "database": "myapp_prod",
    "pg_role": "dba"
  }
}
```

Published to NATS as JSON on `uninc.access._deployment` (always) and `uninc.access.{user_id}` (one message per affected user — so the example above publishes to both `uninc.access._deployment` and `uninc.access.42`).

### ChainEntry — per-user Merkle chain entry

What the chain-engine writes to `/data/chains/{user_id_hash}/chain.dat` (JSON-lines, one entry per line). Each entry is cryptographically linked to the previous one via `previous_hash`.

```
ChainEntry {
  index:             u64              // sequential position (0, 1, 2, ...)
  previous_hash:     [u8; 32]        // SHA-256 of prior entry (zeros for genesis)
  timestamp:         i64
  admin_id:          String
  action:            ActionType
  resource:          String
  scope:             String
  query_fingerprint: [u8; 32]
  metadata:          Option<Map>
  entry_hash:        [u8; 32]        // SHA-256 of all fields above
}
```

Hash computation: `SHA-256(index || previous_hash || timestamp || admin_id || action || resource || scope || fingerprint || sorted_metadata)`. Deterministic — same inputs always produce the same hash regardless of metadata key insertion order.

### DeploymentChainEntry — deployment-wide chain entry

What the chain-engine writes to `/data/chains/_deployment/chain.dat`. Same append-only, hash-linked structure as per-user chains, but scoped to **table-level** information only — no user IDs, no WHERE clauses, no row-level scope.

```
DeploymentChainEntry {
  index:             u64
  previous_hash:     [u8; 32]
  timestamp:         i64
  actor_id:          String           // who (admin, system, CI/CD, operator)
  actor_type:        ActorType        // Admin | System | CiCd | Operator
  category:          DeploymentCategory      // AdminAccess (v1) | AdminLifecycle | Config | Deploy | Schema | System (v2)
  action:            ActionType
  resource:          String
  scope:             String
  query_fingerprint: [u8; 32]
  details:           Option<Map>
  artifact_hash:     Option<[u8; 32]> // hash of changed artifact (config, binary, migration)
  user_chain_refs:   Vec<String>      // cross-references to affected user chains (hashed, not raw IDs)
  session_id:        Option<Uuid>
  entry_hash:        [u8; 32]
}
```

---

## Two chain types

One `AccessEvent` from the proxy becomes **two chain entries** — one in the per-user chain (row-level detail for the affected user) and one in the deployment chain (table-level summary for the operator). Here's what each chain stores and why.

| | Per-user chain | Admin activity (org) chain |
|---|---|---|
| **NATS subject** | `uninc.access.{user_id}` | `uninc.access._deployment` |
| **Storage path** | `/data/chains/{user_id_hash}/` | `/data/chains/_deployment/` |
| **Detail level** | Row-level: which admin, which columns, which WHERE filter, full scope | Table-level only: which admin, which table, what action. **No user IDs, no WHERE clauses, no row-level scope.** |
| **Who reads it** | The affected end user (WASM-verified in browser) | The operator (deployment-wide audit), the cross-replica verifier |
| **GDPR-deletable?** | **Yes** — delete the whole `{user_id_hash}/` directory on erasure request | **No** — but it contains no personal data, so GDPR doesn't apply |

### What each chain stores for the same admin query — exact examples

Scenario: admin `dba@company.com` runs `SELECT email, phone FROM users WHERE id = 42`. The proxy resolves that user 42 is affected. Two chain entries are created:

**Per-user chain entry** (written to `/data/chains/{hash_of_42}/chain.dat`):

```json
{
  "index": 7,
  "previous_hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "timestamp": 1744444800000,
  "admin_id": "dba@company.com",
  "action": "Read",
  "resource": "users",
  "scope": "columns: email, phone; filter: id = 42",
  "query_fingerprint": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
  "metadata": {
    "source_ip": "10.0.1.50",
    "database": "myapp_prod",
    "session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
  },
  "entry_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

The user sees: *"dba@company.com read your email and phone from the users table."* Full detail — which columns, which filter, who, when.

**Deployment chain entry** (written to `/data/chains/_deployment/chain.dat`):

```json
{
  "index": 1042,
  "previous_hash": "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
  "timestamp": 1744444800000,
  "actor_id": "dba@company.com",
  "actor_type": "Admin",
  "category": "AdminAccess",
  "action": "Read",
  "resource": "users",
  "scope": "table: users, action: read",
  "query_fingerprint": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
  "details": {
    "affected_user_count": "1",
    "source_ip": "10.0.1.50",
    "database": "myapp_prod"
  },
  "artifact_hash": null,
  "user_chain_refs": ["hash_of_42"],
  "session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "entry_hash": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
}
```

The operator sees: *"dba@company.com read from the users table, 1 user affected."* No user ID, no column names, no WHERE clause. The `user_chain_refs` field contains hashed references so the cross-replica verifier can cross-check, but the operator's transparency view (rendered by whatever frontend reads the `:9091` chain API — typically www's `/v/` pages) does not resolve them back to user IDs.

**Why the split:** if user 42 exercises GDPR Article 17 (right to erasure), we delete `/data/chains/{hash_of_42}/`. The deployment chain entry above is unaffected — it contains no user-identifying data. The admin's action is still auditable ("dba read from users table") but which specific user was read is gone.

**The "org view"** (what any frontend reading `:9091` shows the operator — www's `/v/` pages, a customer UI, anything) is dynamically constructed at read time by joining both chains by `session_id` / `timestamp`. It's a view, not a third stored chain.

### Comprehensive examples — different entry types

These show what real chain entries look like for each `ActionType` across different scenarios.

**1. App reads user profile (normal app traffic)**

Per-user chain entry for user 42:

```json
{
  "index": 8,
  "previous_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "timestamp": 1744444860000,
  "admin_id": "app:app_user",
  "action": "Read",
  "resource": "users",
  "scope": "columns: id, name, avatar_url; filter: id = 42",
  "query_fingerprint": "1a2b3c4d5e6f7890...",
  "metadata": {
    "source_ip": "10.0.1.20",
    "database": "myapp_prod",
    "session_id": "c91e3a5b-1234-4abc-9def-abcdef123456"
  },
  "entry_hash": "7d793037a0760186574b0282f2f435e7..."
}
```

The user sees: *"app loaded your profile"* — expected, not concerning.

**2. Admin writes to a user's record**

Per-user chain entry for user 42:

```json
{
  "index": 9,
  "previous_hash": "7d793037a0760186574b0282f2f435e7...",
  "timestamp": 1744445000000,
  "admin_id": "support@company.com",
  "action": "Write",
  "resource": "users",
  "scope": "columns: email; filter: id = 42; old: jane@old.com, new: jane@new.com",
  "query_fingerprint": "2b3c4d5e6f7890ab...",
  "metadata": {
    "source_ip": "192.168.1.100",
    "database": "myapp_prod",
    "session_id": "d82f4b6c-5678-4def-0123-456789abcdef"
  },
  "entry_hash": "9f86d081884c7d659a2feaa0c55ad015..."
}
```

The user sees: *"support@company.com changed your email from jane@old.com to jane@new.com"* — concerning if they didn't request it.

**3. Admin deletes user data**

Per-user chain entry for user 42:

```json
{
  "index": 10,
  "previous_hash": "9f86d081884c7d659a2feaa0c55ad015...",
  "timestamp": 1744446000000,
  "admin_id": "dba@company.com",
  "action": "Delete",
  "resource": "messages",
  "scope": "filter: sender_id = 42; rows_affected: 17",
  "query_fingerprint": "3c4d5e6f7890abcd...",
  "metadata": {
    "source_ip": "10.0.1.50",
    "database": "myapp_prod",
    "session_id": "e93g5c7d-9012-4567-89ab-cdef01234567"
  },
  "entry_hash": "a94a8fe5ccb19ba61c4c0873d391e987..."
}
```

The user sees: *"dba@company.com deleted 17 of your messages"* — very concerning.

**4. Admin exports user data (bulk read)**

Per-user chain entry for user 42:

```json
{
  "index": 11,
  "previous_hash": "a94a8fe5ccb19ba61c4c0873d391e987...",
  "timestamp": 1744447000000,
  "admin_id": "analytics@company.com",
  "action": "Export",
  "resource": "users, orders, messages",
  "scope": "full table scan; filter: none; rows: users=1, orders=23, messages=417",
  "query_fingerprint": "4d5e6f7890abcdef...",
  "metadata": {
    "source_ip": "10.0.1.75",
    "database": "myapp_prod",
    "session_id": "fa4h6d8e-3456-4789-abcd-ef0123456789"
  },
  "entry_hash": "b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9..."
}
```

The user sees: *"analytics@company.com exported your data from users, orders, and messages tables (441 rows)"* — this is what "ML pipeline reads training data at 3am" looks like in the chain.

**5. Admin runs a schema migration**

Deployment chain entry only (no per-user chain — schema changes don't touch user data directly):

```json
{
  "index": 1043,
  "previous_hash": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
  "timestamp": 1744448000000,
  "actor_id": "dba@company.com",
  "actor_type": "Admin",
  "category": "AdminAccess",
  "action": "SchemaChange",
  "resource": "users",
  "scope": "ALTER TABLE users ADD COLUMN phone_verified BOOLEAN DEFAULT false",
  "query_fingerprint": "5e6f7890abcdef12...",
  "details": {
    "source_ip": "10.0.1.50",
    "database": "myapp_prod",
    "migration_name": "add_phone_verified"
  },
  "artifact_hash": null,
  "user_chain_refs": [],
  "session_id": "gb5i7e9f-4567-4890-bcde-f01234567890",
  "entry_hash": "c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0..."
}
```

No user is directly affected, so `user_chain_refs` is empty and no per-user entries are created. The operator sees: *"dba@company.com altered the users table (added phone_verified column)."*

**6. S3 object access**

Per-user chain entry for user 42:

```json
{
  "index": 12,
  "previous_hash": "b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9...",
  "timestamp": 1744449000000,
  "admin_id": "support@company.com",
  "action": "Read",
  "resource": "uploads/users/42/id-scan.pdf",
  "scope": "GET object; bucket: uploads; key: users/42/id-scan.pdf; size: 2.4MB",
  "query_fingerprint": "6f7890abcdef1234...",
  "metadata": {
    "source_ip": "192.168.1.100",
    "database": "minio",
    "session_id": "hc6j8f0g-5678-4901-cdef-012345678901",
    "content_type": "application/pdf"
  },
  "entry_hash": "d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1..."
}
```

The user sees: *"support@company.com downloaded your file id-scan.pdf (2.4MB)"* — a support agent looking at your uploaded ID document.

**7. Suspicious connection**

Per-user chain entry for user 42:

```json
{
  "index": 13,
  "previous_hash": "d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1...",
  "timestamp": 1744450000000,
  "admin_id": "suspicious:admin@10.0.1.20",
  "action": "Read",
  "resource": "users",
  "scope": "columns: email, phone, ssn; filter: id = 42",
  "query_fingerprint": "7890abcdef123456...",
  "metadata": {
    "source_ip": "10.0.1.20",
    "database": "myapp_prod",
    "session_id": "id7k9g1h-6789-4012-def0-123456789012",
    "classification": "suspicious",
    "reason": "admin credentials from app container IP range"
  },
  "entry_hash": "e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2..."
}
```

The user sees: *"suspicious: someone using admin credentials from an app server's IP read your email, phone, and SSN"* — red flag.

---

## Deployment topologies

### Shape A — Drop-in proxy (existing DB)

```text
┌─ Your existing infra ──────────────────────────────────┐
│                                                         │
│  Your app ──▶ uninc-proxy ──▶ Your existing Postgres    │
│                    │                                    │
│             NATS + chain-engine                         │
│             (added via docker-compose.self-hosted.yml)  │
└─────────────────────────────────────────────────────────┘
```

- 3 containers added to the existing stack (proxy, NATS, chain-engine)
- One connection string change (`:5432` → `:6432`)
- Zero code changes
- **No replicas, no cross-replica check.** The proxy is the only path, but the operator controls Docker and could `docker exec` to bypass it.

### Shape B — Batteries-included single host

```text
┌─ One host (laptop / single VM) ──────────────────────────┐
│                                                           │
│  Your app ──▶ uninc-proxy + pgbouncer                     │
│                    + nats + chain-engine                  │
│                    + Postgres + MongoDB + MinIO           │
│                                                           │
│  Single Docker Compose stack (docker-compose.yml)         │
└───────────────────────────────────────────────────────────┘
```

- All data primitives run alongside the proxy on one host
- Good for laptop development, small deployments, a single-VM production install
- Still **no replicas, no cross-replica check, no Observer** — single-host trust model

### Shape C — Multi-VM with replica verification

```text
┌─ Per-customer VPC ──────────────────────────────────────────────────────┐
│                                                                          │
│  Public subnet 10.0.1.0/24:                                              │
│  ┌─ Proxy VM (GCE) ──────────────────────────────────────────────────┐  │
│  │ uninc-proxy + pgbouncer + nats + chain-engine                     │  │
│  │ + verification engine (T3 nightly trigger only in v1)             │  │
│  │                                                                    │  │
│  │ Public IP: 34.82.x.x (dev-mode access, firewalled)               │  │
│  │ Private IP: 10.0.1.5 (Cloud Run connects here)                   │  │
│  └──────────┬──────────────────────────────────────────┬─────────────┘  │
│             │ port 5432 only                           │                 │
│             ▼                                          │                 │
│  Private subnet 10.0.2.0/24:                           │                 │
│  ┌─ Replica 0 (10.0.2.10) ──┐                         │                 │
│  │ Postgres 16               │  No public IP           │                 │
│  │ No SSH daemon             │  No SSH                 │                 │
│  │ Firewall: ONLY 5432      │  Firewall: DENY ALL     │                 │
│  │   from 10.0.1.5          │    except proxy→5432     │                 │
│  └───────────────────────────┘                         │                 │
│  ┌─ Replica 1 (10.0.2.11) ──┐                         │                 │
│  └───────────────────────────┘                         │                 │
│  ┌─ Replica 2 (10.0.2.12) ──┐                         │                 │
│  └───────────────────────────┘                         │                 │
│                                                         │                │
└─────────────────────────────────────────────────────────┼────────────────┘
                                                          │
                                        Cloud Run (customer's app)
                                        attaches to this VPC via
                                        Direct VPC Egress and reaches
                                        the proxy's private IP
                                        intra-subnet (no connector,
                                        no peering)
```

- **Cross-replica verification**: 3/5/7 replica VMs, drand-seeded per-session Primary/Verifier assignment. Not Byzantine fault tolerant in v1 — no quorum vote, just pairwise compare; real BFT (multi-observer quorum) is deferred.
- Each replica VM runs ALL primitives the customer uses (Postgres + MongoDB + MinIO co-located)
- 3 replicas = 3 VMs, not 9 — replica independence comes from separate VMs, not separate primitives
- Replicas have no SSH, no public IP, firewall allows only DB ports from proxy
- **v1 verification trigger: only T3 (nightly full).** T1 per-session, T2 periodic sampling, and T4 randomized reshuffle are deferred. The scheduler runs as a single background task with timeout + panic catching; a single bad run never kills the loop.
- T3 marks chain entries as "verified" (`verified_ranges.json`) and — in combination with the `durable_ranges.json` sidecar written at quorum-commit time — gates LRU eviction of hot-tier entries.

---

## Ports

| Port | Owner | Notes |
|---|---|---|
| `:5432` | Customer Postgres upstream | On replica VMs |
| `:6432` | Proxy's Postgres listener | +1000 shift from upstream |
| `:6433` | PgBouncer sidecar | Loopback only |
| `:9000` | Customer MinIO upstream | Customer application data (optional) |
| `:9001` | MinIO console (customer) | Web UI |
| `:9002` | **chain-MinIO sidecar** | Our per-replica chain entries; bucket `uninc-chain` |
| `:9090` | Proxy health | `/health`, `/health/ready`, `/health/detailed` (JWT) |
| `:9091` | Proxy chain API | JWT-gated reads |
| `:10000` | Proxy's S3 listener | +1000 shift from `:9000` |
| `:27017` | Customer MongoDB upstream | On replica VMs |
| `:28017` | Proxy's MongoDB listener | +1000 shift |
| `:2026` | Observer HTTP | Head + entries endpoint; internal-only, shared-secret gated |
| `:4222` | NATS | Internal |

`:9002` is deliberately **not** `:9001` (customer MinIO console collides) and **not** `:9100` (node_exporter claims that by convention). Clients connect to proxy listeners at the `+1000` shifted ports; the proxy forwards to the native upstream port. This shift is baked into the proxy binary — not overridable via config — so the "paste this connection string" experience stays consistent.

## /health surface on :9090

Three endpoints, split by information sensitivity:

- `GET /health` — open, `{"status":"ok"}`, no state leak.
- `GET /health/ready` — open, gated on NATS-publish liveness only. 503 flips the LB out of rotation. **Not** gated on chain-commit — a chain-engine hiccup degrades the detailed status but does not evict the proxy from LB rotation (would create feedback loop: hiccup → evict → admin writes 503 → worse state).
- `GET /health/detailed` — JWT-gated (`aud: "health-detailed"`, `jti` deny-list enforced). Returns per-subsystem rollup:

```json
{
  "status": "ok|degraded|unhealthy",
  "uptime_secs": 12345,
  "now_ms": 1745200000000,
  "checks": {
    "subsystems": {
      "nats":          { "status": "ok",       "last_ok_ms": ..., "last_err_ms": 0,   "last_err_reason": "" },
      "chain_commit":  { "status": "down",     "last_ok_ms": ..., "last_err_ms": ..., "last_err_reason": "quorum not reached: 1/3 acked" },
      "observer_head": { "status": "ok",       "last_ok_ms": ..., "last_err_ms": 0,   "last_err_reason": "" }
    },
    "listeners": { "postgres": {...}, "mongodb": {...}, "s3": {...} }
  }
}
```

Subsystems per-cell: `last_ok_ms`, `last_err_ms`, bounded-256-char `last_err_reason`. Status derivation: `down` if a recent err post-dates the last ok; `stale` if ok hasn't landed in 60s; `idle` if no ok yet and past the 30s startup grace window; `not_configured` for subsystems the deployment doesn't use (e.g. observer in single-host setups).

Cross-process subsystems stamp via a NATS ops relay rather than direct memory: chain-engine publishes `uninc.ops.subsystem_health.chain_commit` on core NATS (not JetStream — ephemeral), the proxy subscribes and stamps the cell. Keeps processes loosely coupled and survives chain-engine restart without a proxy restart.

## Chain-engine quorum failure handling

Three wires trigger on durable-tier (quorum) failure:

**Wire 1 — FailureHandlerChain escalation.** `consumer.rs` tracks a per-chain consecutive-failure counter (`QuorumFailureTracker`). On `ChainError::QuorumFailed` / `DeploymentChainError::QuorumFailed`, the counter increments and a `subsystem_health.chain_commit = err(reason)` ping fires on the ops relay. Once the counter crosses `QUORUM_ALERT_THRESHOLD` (3), chain-engine publishes a `ChainFailurePing::ChainCommitFailed` on `uninc.ops.failure_event.chain_commit_failed`. The proxy subscribes and dispatches each ping through the verification crate's `FailureHandlerChain` (same handlers that run for scheduled-verification divergences: alert / credential deny-list / read-only lockdown).

**Wire 2 — local-hot-only `quorum_failed` DeploymentEvent.** On the same threshold crossing (exactly once per outage), chain-engine calls `DeploymentChainManager::append_deployment_event_best_effort` to record a `category=system, action=write, resource=chain-engine, scope=quorum_failed` DeploymentEvent. Best-effort means: local hot-tier write MUST succeed, durable fan-out MAY fail — the entry is flagged `durable=false` in metadata and reconciliation (future work) republishes to durable once quorum returns. Reentrant guard: if the failing chain IS the deployment chain, skip the best-effort write to avoid storm.

**Wire 3 — stuck-consumer detector.** `spawn_stuck_consumer_detector` polls the tracker every 30 seconds. Any chain that has been failing for longer than `STUCK_CONSUMER_ALERT_SECS` (300s default) gets a `CRITICAL` log line and a fresh `subsystem_health.chain_commit = err(reason including "stuck for Ns")` ping. This fires the duration-based alert even when no new NATS messages are arriving to trip the count-based Wire 1 path (JetStream redelivery is what drives Wire 1; an idle chain that's stuck doesn't generate new NAKs).

**Why no DLQ (max_deliver exhaustion).** Chain entries are index-ordered and hash-linked (`e_{i+1}.prev_hash = H(e_i)`). Skipping a failing message and moving to the next breaks the chain — there is no safe "skip ahead" for an ordered hash chain. JetStream is configured for unlimited redelivery (`max_deliver = -1`), subsequent access events queue behind the stuck message in the durable stream (disk-backed, 7-day TTL), and the tracker/detector pair raises the alert after duration, not delivery count. This is the correct semantic for the chain; a DLQ would be the wrong abstraction.

## NATS subject model

| Subject | Kind | Publisher | Consumer | Volume |
| --- | --- | --- | --- | --- |
| `uninc.access._deployment` | JetStream | uninc-proxy (every admin op) | chain-engine → deployment chain | Every admin query |
| `uninc.access.{user_id}` | JetStream | uninc-proxy (per affected user) | chain-engine → per-user chain | Only queries with resolved users |
| `uninc.system._deployment` | JetStream | uninc-verifier (scheduled results) | chain-engine → deployment chain | Once per scheduled run (plus reaper + future triggers) |
| `uninc.ops.subsystem_health.{name}` | Core | Any subsystem (chain-engine, verification task) | proxy health stamper | Per commit / per observer read |
| `uninc.ops.failure_event.{kind}` | Core | chain-engine (on threshold crossing) | proxy FailureHandlerChain dispatcher | Rare (once per outage) |

Access subjects are in the `UNINC_ACCESS` stream (wildcard `uninc.access.>` + `uninc.system.>`). WorkQueue retention, 7-day TTL, file storage, explicit ack. The `uninc.ops.*` family deliberately uses core NATS (not JetStream): health and failure pings are ephemeral, losing one on a broker restart is acceptable, and routing them through JetStream would queue failure alerts behind the stuck chain-append work that caused them.

The `uninc.system._deployment` subject carries `DeploymentEvent` messages (not `AccessEvent`). The chain-engine consumer routes them to `DeploymentChainManager.append_org_event()` with `actor_id: "uninc-verifier"`, `actor_type: System`, `category: System`.

---

## Verification taxonomy

The word `verify` appears in five distinct places in this repo. Each answers a different question, catches a different failure mode, and uses a different mechanism.

Each flow compares two independently-produced copies of something. What differs is where the copies come from, whether the comparison is a hash recompute or a raw byte-equality check, and when it runs.

None of v1 is Byzantine fault tolerant in the academic sense — no quorum vote, no 2f+1 threshold, no leader election. v1 ships cross-replica *detection*: every replica should produce the same head, and the failure handler fires on disagreement. Byzantine tolerance (multi-observer quorum, signed votes) is tracked as v2 work in [ROADMAP.md](../ROADMAP.md).

| # | Flow | Files | Mechanism (hash recompute vs byte compare) | When it runs | Topology scope |
|---|------|-------|--------------------------------------------|--------------|----------------|
| 1 | **Chain entry integrity** | `crates/chain-store/src/entry.rs` (Rust, canonical)<br>`crates/chain-verifier-wasm/src/lib.rs` (browser) | **Hash recompute.** SHA-256 over all entry fields in canonical order (length-prefixed, sorted metadata) compared against the entry's stored `entry_hash`. | On every end-user read (browser WASM), on every `uninc verify` CLI call | All shapes — the `:9091` chain API serves entries and the reader verifies client-side |
| 2 | **Chain head across replica chain-MinIOs** | `crates/chain-engine/src/multi_replica_storage.rs`<br>`crates/verification/src/nightly.rs` (sweep loop)<br>`crates/verification/src/verifiers/{postgres,mongodb,s3}.rs::verify_chain_head` | **Byte compare.** Each replica's chain-MinIO stores a 32-byte raw SHA-256 in `head.hash`. Verification reads all N, compares the bytes — no rehashing, just `a == b`. | Every quorum-commit on the write path, plus nightly T3 full sweep | multi-VM topology only (3/5/7 chain-MinIOs in the private subnet — see topology §Component 4) |
| 3 | **Cross-replica DB state** | `crates/verification/src/verifiers/postgres.rs`<br>`crates/verification/src/verifiers/mongodb.rs`<br>`crates/verification/src/verifiers/s3.rs`<br>`crates/verification/src/replica_client.rs` | **Primitive-specific fingerprint, then hash compare.** Fingerprint algorithm differs per primitive because the client protocol differs — see §#3 expanded below. | Nightly T3. (T1 per-session-end is planned, not in v1.) | multi-VM topology only — Primary replica vs drand-picked Verifier replica |
| 4 | **Observer vs proxy deployment chain** | `crates/verification/src/task.rs` (comparison — `run_scheduled_verification` step 4)<br>`crates/verification/src/observer_client.rs` (HTTP client + retry policy)<br>`crates/observer/src/chain.rs` (Observer write path)<br>`crates/observer/src/http.rs` (`:2026` head endpoint) | **Byte compare.** Proxy's baseline head is the value already read in row #2 for this scheduled run (no duplicate disk read). Observer's head fetched via `GET :2026/observer/chain/_deployment/head` with `x-uninc-read-secret` header. Raw byte equality check. Retry-once on transient HTTP errors (timeout, 5xx, transport); auth and invalid-response errors fail fast. On mismatch, the existing `VerificationDivergence` failure event fires with the synthetic replica id `"observer"` so the lockdown / credential-deny / alert handlers run the same as for replica-level divergence. | Scheduled run (T3) | multi-VM topology with an observer configured — set `verification.observer_url` + `verification.observer_read_secret` in `uninc.yml`. Single-host / playground deployments skip the comparison. |
| 5 | **JWT bearer on `:9091`** | `crates/proxy/src/chain_api/` (auth middleware) + `crates/proxy/src/jwt_replay.rs` (shared `jti` deny-list). Shared HMAC secret injected as `UNINC_JWT_SECRET` (minted by whatever identity service your deployment uses). | **HMAC signature verify + replay check.** HS256 over header+payload with the shared secret, compared against the signature segment of the inbound `Authorization: Bearer …`. Every accepted token's `jti` claim is then recorded in an in-memory LRU deny-list for the duration of its `exp` window; a repeat `jti` is rejected (§10.5 of the protocol spec — tokens are effectively single-use). | Every `:9091/api/v1/chain/*` request; every `:9090/health/detailed` call (the deny-list is shared across both surfaces). | Every deployment that exposes `:9091` |

Two orthogonal trust axes fall out of this table:

- **"Are the stored entries well-formed?"** — #1 is the only verification an end user can run themselves. The server cannot fake a passing WASM result because the WASM runs in the user's browser, not on our infrastructure.
- **"Did the proxy log what the databases actually did?"** — only #4 covers this. #2 and #3 catch a *single* rogue replica, but they are useless against a proxy that writes the same forged history to every replica. Only the Observer has an input (native replication streams) the proxy doesn't control. Row #4 is wired as of the observer-comparison shipment: the scheduled verification task (`crates/verification/src/task.rs::run_scheduled_verification` step 4) fetches the Observer's deployment-chain head every run and byte-compares it to the proxy's baseline, emitting `verification_failure` on mismatch per UAT §3.3.

### #3 expanded — why per-primitive algorithms differ

The question ("do Primary and Verifier replicas hold the same data right now?") is the same for every primitive. The mechanism differs because each primitive's client protocol exposes different introspection surfaces — and the verifier runs *outside* the primitive, on the proxy VM, over the normal client port.

| Primitive | File | Fingerprint mechanism | Comparison shape | Why this shape |
|-----------|------|----------------------|------------------|----------------|
| **Postgres** | `crates/verification/src/verifiers/postgres.rs::verify_session` | `ReplicaClient::full_state_checksum(tables)` — for each configured table, stream rows sorted by PK via `tokio-postgres` and SHA-256 them client-side. Final fingerprint is a 32-byte SHA-256. | 32-byte SHA-256 from Primary vs 32-byte SHA-256 from Verifier — byte compare on the final digest | Postgres lets a read-replica role run arbitrary `SELECT`, so we have full data reach and can compute our own SHA-256 — stays consistent with the rest of the chain protocol |
| **MongoDB** | `crates/verification/src/verifiers/mongodb.rs::verify_session` | `dbHash` admin command — Mongo's own server-computed MD5 per collection, returned as `{collection: md5}` | Per-collection MD5 from Primary vs Verifier — hash compare, any single collection mismatch = divergence | BSON-in-WiredTiger storage is opaque to a client. Without `dbHash` we'd have to read every document to fingerprint state; `dbHash` is Mongo's canonical answer to "what's the state of this DB right now?" |
| **S3 / MinIO** | `crates/verification/src/verifiers/s3.rs::verify_session` | Manifest hash — `list_objects()`, sort by key, compute `SHA-256(key₁‖ETag₁‖key₂‖ETag₂‖…)`. ETag is server-computed by MinIO, so we never download object bodies. | 32-byte SHA-256 of the manifest from Primary vs Verifier — byte compare | Object bodies are opaque and often huge; downloading them all is a non-starter. ETags catch **content** divergence (same key, different bytes → different ETag); sorted keys catch **set** divergence (key missing on one replica) |

All three implement the same `ReplicaStateVerifier` trait (`crates/verification/src/verifiers/mod.rs`) so the scheduler and failure handler stay protocol-agnostic.

The actual comparison is dead simple — abridged from `verifiers/postgres.rs::verify_session`:

```rust
let primary_state  = primary_client.full_state_checksum(&self.tables).await?;   // [u8; 32]
let verifier_state = verifier_client.full_state_checksum(&self.tables).await?;  // [u8; 32]

if primary_state != verifier_state {
    report.divergences.push(Divergence {
        replica_a: assignment.primary.id.clone(),
        replica_b: assignment.verifier.id.clone(),
        detail: format!(
            "state checksum mismatch: primary={} verifier={}",
            hex::encode(primary_state), hex::encode(verifier_state),
        ),
        ..
    });
}
```

### #4 expanded — what the Observer actually stores

Worth stating loudly because it's commonly misread: **the Observer VM is not a database replica.** It holds no Postgres tables, no Mongo collections, no S3 objects. It runs an independent chain-engine in the same on-disk format the proxy uses.

From `crates/observer/src/chain.rs`:

```text
/data/observer-chains/observer/_deployment/
  chain.dat      — JSON-lines, append-only (same format as the proxy's chain)
  chain.idx      — entry_number → byte_offset (binary, 8 bytes per entry)
  head.hash      — 32-byte raw SHA-256 of the latest entry  ← this is what :2026 returns
  meta.json      — creation time, entry count
```

It is not a MinIO instance either — local-disk append-only JSON-lines, same envelope as the proxy chains, hashed with the same `UNINC_CHAIN_V1` algorithm via the shared `chain-store` crate.

The Observer emits payload type `0x03` — `ObservedDeploymentEvent`, spec §4.12 — carrying the four-field subset both the proxy and the replication stream can produce: `action`, `resource`, `actor_id_hash`, `query_fingerprint`. The payload omits `timestamp` (each side's envelope at §4.4 witnesses its own chain's view of the operation), `source_ip`, `session_id`, `affected_user_id_hashes`, and free-form `details`. Replication streams (Postgres WAL / MongoDB oplog / S3 notifications) do not carry those fields; forcing placeholder values would produce false positives on every comparison. The proxy's deployment chain interleaves `DeploymentEvent` entries (payload type `0x02`, deploy / config / schema / system / lifecycle) with the `ObservedDeploymentEvent` subset that §5.5 cross-witnesses.

Comparison runs as Process 2 of Scheduled Verification per spec §5.5.2: a monotonic-cursor entry walk over both chains, canonicalizing each projectable proxy entry to `ObservedDeploymentEvent` shape via `project_to_observed` and byte-comparing against the corresponding observation-chain entry. The payload carries no wall-clock field, so JCS canonicalization of identical field values produces identical bytes without quantization. Replication lag and cross-host clock skew are absorbed by the un-compared tail — cursors only advance over the prefix both chains have already witnessed — so no time-window parameter is needed. Rich proxy-side metadata (source IP, session, correlation ID, query shape) lives in sidecar metadata (spec §6.4) outside the hashed bytes; sidecar tampering does not invalidate the chain.

Chain-head byte equality between the two chains is not an invariant: the observation chain and proxy deployment chain have independent lineage (different `prev_hash` sequences, different envelope timestamps, different entry sets). The invariant is per-entry canonicalized-payload byte equality for the `ObservedDeploymentEvent` subset both chains witness.

The Observer's input is each primitive's **native replication stream**, not the proxy's audit events:

- **Postgres** → `crates/observer/src/subscribers/postgres.rs` — logical replication slot created with `pg_create_logical_replication_slot(..., 'pgoutput')`, polled via `tokio-postgres`
- **MongoDB** → `crates/observer/src/subscribers/mongodb.rs` — change streams via `watch()` on the official driver
- **MinIO** → `crates/observer/src/subscribers/minio.rs` — bucket notifications published by MinIO itself to NATS

Those streams are generated by Postgres, MongoDB, and MinIO — code the upstream projects maintain, not code we or the customer write. A compromised proxy has no path to suppress, filter, or forge what the Observer sees.

```text
            ┌──── proxy VM ────┐                 ┌──── Observer VM ────┐
            │                  │                 │                     │
 app ─────▶ │ uninc-proxy      │  writes to own  │ uninc-observer      │
            │  guard pipeline  │  deployment     │  subscribes to      │
            │  audit gate      │  chain on disk  │  WAL / oplog /      │
            │  :9091 chain API │                 │  bucket-notify      │
            │                  │                 │  writes to OWN      │
            │ /data/chains/    │                 │  deployment chain   │
            │   _deployment/   │                 │ /data/observer-     │
            │   {user_hash}/…  │                 │   chains/observer/  │
            │                  │                 │   _deployment/      │
            └────┬─────────────┘                 └──────────┬──────────┘
                 │                                          │
                 │   :9091 GET head ◄──────────┐            │  :2026 GET head
                 │                             │            │  (internal-only)
                 │                     verification task on proxy VM
                 │                     compares 32-byte heads byte-by-byte
                 │                                          │
                 │                                          ▼
                 │                            divergence? → failure handler:
                 │                              · VerificationFailure entry
                 │                                on deployment chain
                 │                              · NATS alert → alerting
                 │                              · credential revoke
                 │                              · read-only lockdown
                 ▼
      end user browser reads here
      (WASM-verifies via #1)
```

### v1 coverage limits across these flows

- **Payload-level byte equality, not head-byte equality.** Flow #4 compares canonicalized `ObservedDeploymentEvent` payloads per spec §5.5.2 via a monotonic-cursor entry walk; matched entries advance both cursors, a mismatch emits `verification_failure` on the deployment chain. Replication lag is absorbed by the un-compared tail, so there is no time-window parameter. Proxy-side metadata stays in non-hashed sidecar (§6.4). Chain-head byte equality between the two chains is not an invariant — the chains have independent lineage.
- **Single Observer.** Simultaneous compromise of proxy + Observer can still forge history. v1 is Byzantine *detection*, not *tolerance*; multi-observer quorum is v2 work.
- **Reads produce no replication events.** Read-side forgery by the proxy is a remaining gap. Value-hash chain entries and external chain-head publication close most of it and are scheduled for v2.

---

## Verification trigger model (multi-VM topology)

**v1 ships a single trigger: T3 (nightly).** T1/T2/T4 are deferred. The single trigger is enough for v1 because a 24-hour cross-replica comparison window is well inside the time frame an auditor or breach investigator cares about, and the replicas are already independently hardened (no SSH, no public IPs, firewall-limited).

| Trigger | When | Scope | Marks verified? | Logged to deployment chain? |
|---|---|---|---|---|
| **T3** Nightly | Once per day at a jittered 02:00–04:00 UTC | ALL replicas, full head-hash comparison | **Yes** | **Yes** — drand round + replica comparison results |

**The nightly scheduler is error-tolerant by design.** The loop wraps each run in:
- `tokio::time::timeout` (30 minute hard cap) so a stuck replica can't stall the task forever
- `AssertUnwindSafe + FutureExt::catch_unwind` so a panic in the pipeline is caught and logged — the loop continues
- A minimum sleep floor (60 s) so edge-case jitter math can never tight-loop
- Exponential backoff between unrecoverable errors

One bad nightly run never kills the task for the rest of the process lifetime. See `server/crates/verification/src/task.rs::start_nightly_task` for the loop body.

**Deferred triggers**, in priority order for when they should come back:
- **T4 reshuffle** (highest priority deferred) — drand-seeded role reassignment at a randomized interval. Without it, the assignment is stable for the process lifetime, which is fine for v1 but a long-lived compromised proxy could eventually learn which replica is the Verifier.
- **T1 per-session** — fires the cross-replica check immediately after an admin session closes, catching drift faster than waiting up to 24h for the next nightly.
- **T2 periodic sampling** — cheaper than nightly, catches drift inside a 24-hour window.

All three preserve the existing machinery (same `VerifierRegistry`, same `FailureHandlerChain`, same drand seed path). Bringing them back is code-gen-style work when customer demand makes it worthwhile.

Example T3 nightly deployment chain entry:

```json
{
  "actor_id": "uninc-verifier",
  "actor_type": "System",
  "category": "System",
  "action": "Read",
  "resource": "replicas",
  "scope": "T3 verification passed",
  "details": {
    "trigger": "T3",
    "replicas_checked": "3",
    "pairs_checked": "3",
    "result": "all replicas agree"
  },
  "session_id": null
}
```

---

## Chain entry lifecycle

```text
  admin query arrives at proxy
           │
           ▼
  audit gate publishes to NATS ──────▶ chain-engine appends to disk
  (deployment chain + per-user chains)              │
           │                                 ▼
           ▼                          entry on local disk (hot tier)
  query forwarded to DB               status: UNVERIFIED, NOT YET DURABLE
                                             │
                                             │  MultiReplicaStorage fan-out
                                             │  to replica MinIOs (multi-VM)
                                             ▼
                                       quorum-acked writes
                                       durable_ranges.json marks
                                       entry quorum-safe
                                             │
                                             │  (once per day, jittered 02:00 UTC)
                                             ▼
                                       T3 NIGHTLY full comparison
                                       (the only v1 trigger)
                                             │
                                       all replicas agree?
                                        ╱            ╲
                                     YES              NO
                                      │                │
                                verified_ranges   fire FailureHandlerChain:
                                marks entries     deployment chain entry, NATS alert,
                                VERIFIED          customer webhook, credential
                                      │           revoke, read-only lockdown
                                      ▼
                                LRU eviction unlocked
                                (needs BOTH verified_ranges
                                 AND durable_ranges)
```

**Deferred triggers (T1 session-end, T2 periodic, T4 reshuffle)** are not in the diagram — they're tracked as future work. The v1 flow is: append → quorum-commit → (wait 24h) → nightly verification → LRU eviction.

---

## Crate map

| Crate | Binary | Purpose |
|---|---|---|
| `crates/uninc-common/` | — | Shared types (`AccessEvent`, `DeploymentEvent`, config), NATS client, crypto |
| `crates/chain-store/` | — | Binary envelope + JCS payload canonicalization (spec §4.1, §4.9), `SHA-256(serialize(entry))` hash (§5.1), on-disk chain format, tombstone writes |
| `crates/chain-engine/` | `chain-engine` | NATS consumer, per-user + deployment chain writer, multi-replica fan-out, retention reaper |
| `crates/proxy/` | `uninc-proxy` | Postgres/MongoDB/S3 wire-protocol proxy, guard pipeline, audit gate, `:9091` chain API |
| `crates/chain-verifier-wasm/` | — | Rust → WebAssembly verifier (spec §5.2 V1–V8 predicate); runs in the end user's browser |
| `crates/verification/` | — | Scheduled Verification (Process 1 + Process 2 per spec §5.5), drand-seeded replica assignment, failure-handler chain |
| `crates/observer/` | `observer` | Independent WAL / oplog / bucket-notification subscriber; writes its own chain (spec §3.3) |
| `crates/cli/` | `uninc` | Operator CLI for chain inspection, verification, export |

---

## Configuration

Single file: `uninc.yml` (see [uninc.yml.example](uninc.yml.example)).

| Section | What it configures |
|---|---|
| `proxy.postgres` | Postgres upstream, pool, timeouts, rate limits (listen port is hard-coded — see below) |
| `proxy.mongodb` | MongoDB upstream, pool, rate limits (listen port is hard-coded) |
| `proxy.s3` | S3 upstream, user-data patterns. **No own `rate_limit` / `pool` field**: [main.rs:259-274](crates/proxy/src/main.rs) reads both from `proxy.postgres` as a shared knob — an S3-only deployment with no `proxy.postgres` block is unprotected (no rate limit, default pool). Tracked for fix in `www/ROADMAP.md`. |
| `proxy.nats` | NATS URL, subject prefix |
| `proxy.identity` | Admin vs app credential classification |
| `proxy.schema` | Which tables contain user data, user ID columns |
| `chain` | Storage path, shard size, salt, keystore, S3 backup, LRU cache |
| `verification` | Replica list, assignment entropy, nightly (T3) scheduling, failure handler chain |

### Proxy listen ports are hard-coded, not config-driven

The proxy binds to the following external ports, always, on every deployment:

```rust
// crates/uninc-common/src/config.rs
pub const PROXY_POSTGRES_PORT: u16 = 6432;
pub const PROXY_MONGODB_PORT: u16 = 28017;
pub const PROXY_S3_PORT: u16 = 10000;
```

These are the canonical "+1000 shift" ports documented in `LOCAL-DEV.md` — clients point their `DATABASE_URL` at `:6432`, their Mongo driver at `:28017`, their S3 client at `:10000`. **There is no `listen_port:` field in `uninc.yml`.** If an old config has one, serde fails loudly at startup — this is deliberate, because a custom listen port would break the "paste this connection string, it Just Works" UX that the whole dev-ergonomics argument rests on.

Rationale for hard-coding rather than default-with-override:

1. **Canonical-port convention.** The upstream primitives themselves have canonical ports (Postgres `5432`, MongoDB `27017`, S3 `9000`); documenting a single proxy port per primitive matches that convention and simplifies connection-string guidance.
2. **Collision avoidance under `network_mode: host`.** The PgBouncer sidecar shares the host network namespace with the Rust proxy. User-configurable listen ports risk silent port collisions between the two; fixed ports make any collision a startup-time failure.
3. **No operator benefit from customization.** A self-hoster who needs a different external port can iptables-forward into the container without changing the binary.

The listeners implement this by reading the constants directly:

```rust
// crates/proxy/src/postgres/listener.rs
let listener = TcpListener::bind(format!("0.0.0.0:{PROXY_POSTGRES_PORT}")).await?;
```

Upstream ports (the proxy's dial target for the real primitive) are still config-driven — that's a legitimate per-deployment knob, since your Postgres container might live at `postgres:5432` in one setup and `localhost:5432` in another. Only the **listen** side is fixed.

**PgBouncer on the proxy VM lives on `127.0.0.1:6433`**, not `6432`. The Rust proxy takes `0.0.0.0:6432`, and under `network_mode: host` those would collide if both tried `6432`. PgBouncer is loopback-only (only the Rust proxy ever dials it) and port `6433` is deliberate — see [`deploy/gcp/modules/uninc-server/startup-proxy.sh`](deploy/gcp/modules/uninc-server/startup-proxy.sh).

---

## Docker images

Published to `ghcr.io/un-incorporated/`:

| Image | Source | Ports exposed |
|---|---|---|
| `ghcr.io/un-incorporated/proxy` | `docker/proxy/Dockerfile` (contains both `uninc-proxy` and `chain-engine` binaries; callers switch via entrypoint override) | `6432` (pg), `28017` (mongo), `10000` (s3), `9090` (health), `9091` (chain API) — chain-engine container exposes nothing |
| `ghcr.io/un-incorporated/observer` | `docker/observer/Dockerfile` | `2026` (verification-read HTTP) |

---

## Deploy recipes

The `server/` stack is deliberately cloud-agnostic at the **code** level — nothing in [`crates/`](crates/) or [`docker/`](docker/) depends on any specific cloud vendor. What differs by deployment target is the Infrastructure-as-Code layer that creates VMs, networks, and firewall rules. Those recipes live under [`deploy/`](deploy/):

| Recipe | Status | Description |
|---|---|---|
| [`deploy/gcp/`](deploy/gcp/) | **Shipping** | Terraform HCL module + examples for running the multi-VM topology on Google Cloud Platform. |
| [`deploy/aws/`](deploy/aws/) | Placeholder | Not yet written. Porting notes for contributors: map `google_compute_*` → `aws_*`. Single-VM shape is a weekend port; multi-VM is harder because AWS has no Cloud Run analog with equivalent Direct VPC Egress semantics. |
| [`deploy/bare-metal/`](deploy/bare-metal/) | Placeholder | Single-host Docker Compose recipe for your own Linux box (Hetzner, a Pi, an EC2 instance you hand-manage). |

Pick the recipe for your target, run its setup, and you have a working Unincorporated server. Nothing in the Rust crates needs to change — `deploy/` provisions infrastructure; `crates/` are cloud-agnostic.

---

## Deep-dive docs

| Doc | What it covers |
|---|---|
| [DEVELOPMENT.md](DEVELOPMENT.md) | Build, test, run instructions for all Rust crates |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to send a change (license, review flow, test requirements) |
| [TECHSTACK.md](TECHSTACK.md) | Every dependency, why we chose it, what we hand-roll |
| [docs/proxy-implementation.md](docs/proxy-implementation.md) | Per-protocol implementation: Postgres, MongoDB, S3 wire parsing, audit gate |
| [docs/merkle-chain.md](docs/merkle-chain.md) | Chain format, hash computation, verification algorithm, encryption, sharding |
| [docs/replica-verification.md](docs/replica-verification.md) | Cross-replica verification model (N-replica topology, Primary/Verifier assignment, drand entropy, timing, failure responses) |
| [docs/identity-separation.md](docs/identity-separation.md) | Admin vs app classification, multi-signal detection, behavioral fingerprinting |
| [docs/transparency-view-ui-spec.md](docs/transparency-view-ui-spec.md) | UI spec for frontends reading `:9091`: per-user access view, org/deployment view, embeddable badge, WASM verification, notification settings |
| [docs/chain-api.md](docs/chain-api.md) | Chain API v1 contract: endpoints, auth, pagination, error codes |
| [deploy/](deploy/) | Deployment recipes: GCP (shipping), AWS and bare-metal (placeholders) |
