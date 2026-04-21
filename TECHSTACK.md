# Tech Stack

Dependency decisions for the server workspace. Records what we use, what we hand-roll, and why.

> ⚠️ **Experimental / pre-1.0.** The crate picks are settled; the code *calling* them isn't fully exercised. See [README.md §Status](README.md).

See [ARCHITECTURE.md](ARCHITECTURE.md) for runtime architecture and [DEVELOPMENT.md](DEVELOPMENT.md) for the build/test guide.

---

## Core Runtime

| Crate | Version | What it does | Why this one |
|-------|---------|-------------|--------------|
| `tokio` | 1.x (full) | Async runtime | Industry standard. Every async Rust crate assumes tokio. |
| `axum` | 0.8 | HTTP framework (S3 proxy listener, health endpoint, observer HTTP) | Built on hyper/tower, first-party tokio ecosystem. |
| `hyper` | 1.x | HTTP/1 core | Used by axum under the hood + direct use for S3 upstream forwarding. |
| `tower` | 0.5 | Service/middleware abstraction | Used by axum, potential future use for per-protocol middleware. |
| `futures` | 0.3 | Async combinators (Stream, Sink, catch_unwind) | Standard. Used for nightly scheduler panic catching. |

## Serialization

| Crate | What it does | Why |
|-------|-------------|-----|
| `serde` + `serde_json` | JSON (de)serialization | Universal. Every NATS message, chain entry, API response is JSON. |
| `serde_yaml` | YAML config parsing | `uninc.yml` and `observer.yml` are YAML. |
| `bson` | MongoDB BSON | Official crate, pinned to 2.x for type-inference compatibility with mongodb 2.x. |

## Cryptography

| Crate | What it does | Why |
|-------|-------------|-----|
| `sha2` | SHA-256 (chain hashing, query fingerprinting, user ID hashing) | RustCrypto project, audited, standard. |
| `aes-gcm` | AES-256-GCM (per-user chain encryption at rest) | RustCrypto project. AEAD; authenticated encryption prevents silent ciphertext tampering. |
| `rustls` + `tokio-rustls` | TLS 1.3 | Pure Rust, no OpenSSL dependency. Simpler build, smaller attack surface. |
| `rand` | CSPRNG | OS entropy source for fallback seeds when drand is unreachable. |
| `jsonwebtoken` | JWT HS256 | Chain API auth tokens. Standard crate. |
| `drand-verify` | BLS signature verification for drand randomness beacons | Verifies that drand rounds are authentic (not forged by a compromised control plane or MITM). Uses BLS12-381 against the League of Entropy public key. By Nois Labs, also compiles to WASM. |

## Database / Protocol Clients

| Crate | What it does | Why |
|-------|-------------|-----|
| `tokio-postgres` | Postgres client | Used by: cross-replica state verifier (replica state checksums), observer (WAL polling via `pg_logical_slot_get_changes`). NOT used by the proxy itself (proxy speaks wire protocol directly). |
| `mongodb` | MongoDB client | Used by: cross-replica state verifier (`dbHash` comparison), observer (change streams via `watch()`). NOT used by the proxy (proxy speaks wire protocol directly). |
| `async-nats` | NATS JetStream client | Official client by Synadia/nats-io. Audit event transport, observer MinIO subscriber. |
| `rust-s3` | S3/MinIO client | Used by: chain-engine (MultiReplicaStorage quorum writes to replica chain-MinIOs), cross-replica state verifier. |
| `sqlparser` | SQL AST parsing | Extracts table names, columns, WHERE filters from Postgres queries for chain entry metadata. |
| `reqwest` | HTTP client | drand relay fetch, customer webhook delivery in failure handler. |

## Utilities

| Crate | What it does |
|-------|-------------|
| `bytes` | Zero-copy byte buffers (BytesMut) for wire protocol parsing |
| `hex` | Hex encoding/decoding (chain hashes, drand signatures) |
| `base64` | Base64 encoding (secrets, credentials) |
| `regex` | S3 user-data-pattern matching, SigV4 credential extraction |
| `chrono` | Datetime handling with serde |
| `uuid` | v4 UUID generation (session IDs, deployment IDs) |
| `dashmap` | Lock-free concurrent hashmap (observer chain head cache) |
| `clap` | CLI argument parsing (uninc CLI tool) |
| `thiserror` + `anyhow` | Error handling (thiserror for library errors, anyhow for application errors) |
| `tracing` + `tracing-subscriber` | Structured logging with JSON output |

---

## What We Hand-Roll (and Why)

### Postgres Wire Protocol — 1,056 lines

**File:** `crates/proxy/src/postgres/wire.rs`

Hand-rolled parser for the Postgres v3 frontend/backend wire protocol. Handles startup, authentication passthrough (SCRAM, MD5, cleartext), simple query, extended query protocol (Parse/Bind/Execute), SSL negotiation.

**Why not `pgwire` crate?** `pgwire` is designed for building Postgres-compatible *servers* (custom SQL engines). We're building a *transparent byte-level proxy* — we parse just enough to extract metadata (table names, action type, user IDs) and forward the rest unchanged. pgwire's server-oriented abstraction would make our job harder. Also, `pgwire` is a community crate by an individual maintainer (sunng87), not official Postgres.

**Why not `postgres-protocol`?** Lower-level than `pgwire`, part of the tokio-postgres ecosystem. Covers some message types but doesn't provide the full lifecycle management our proxy needs. Would reduce maybe 200 lines but add coupling to tokio-postgres internals.

### MongoDB OP_MSG Wire Protocol — 300 lines

**File:** `crates/proxy/src/mongodb/wire.rs`

Hand-rolled parser for MongoDB's OP_MSG binary format (opCode 2013). Reads 16-byte header, flag bits, BSON body. Falls back to raw forwarding for legacy opcodes.

**Why hand-rolled?** No competing crate exists for MongoDB wire protocol parsing in Rust. The official `mongodb` driver is opaque — it speaks the protocol internally but doesn't expose parsing. OP_MSG is simple (header + flags + BSON), so 300 lines is appropriate.

### SCRAM Username Extraction — 239 lines (95 logic + 144 tests)

**File:** `crates/proxy/src/mongodb/scram.rs`

Extracts the username from MongoDB SCRAM-SHA-256 `saslStart` messages for identity classification. Does NOT implement full SCRAM — just parses the client-first-message format (`n,,n=<username>,r=<nonce>`).

**Why not the `scram` crate?** The `scram` crate implements the full SCRAM protocol (negotiation, proof, verification). We need exactly one thing: the username from byte 0 of the handshake. 50 lines of string parsing vs. a full SCRAM dependency.

### S3 SigV4 Access Key Extraction — 115 lines

**File:** `crates/proxy/src/s3/auth.rs`

Extracts the AWS access key ID from Authorization headers and presigned URL query params. Does NOT verify signatures — that's the upstream S3's job.

**Why not `aws-sigv4`?** The AWS SDK's signature crate does full SigV4 verification (canonicalization, signing, verification). We only need to extract the key ID string for identity classification. Regex + string split is the right tool.

### Rate Limiting — 216 lines

**File:** `crates/proxy/src/rate_limit.rs`

Token bucket per-IP and per-credential. Uses `std::sync::Mutex<HashMap<String, TokenBucket>>`. Stale buckets (idle >5 min) are swept when the map exceeds 10,000 entries.

**Why not `governor`?** Governor is a good crate, but it's 15+ transitive dependencies for something we implement in 73 lines of logic. Our rate limiter runs in the synchronous hot path (check before every query forwarding) and the Mutex hold time is nanoseconds. Governor's `DashMap`-based concurrent approach is overkill for a single-process proxy.

### Fisher-Yates Shuffle — ~50 lines

**File:** `crates/verification/src/assignment.rs`

Seeded Fisher-Yates for per-session replica role assignment. Uses `rand` for the OS random seed, drand for the external entropy seed.

**Why hand-rolled?** Fisher-Yates is 10 lines of code. Using a library would add a dependency for something simpler than a for loop.

### Merkle Chain Hash — ~100 lines

**File:** `crates/chain-store/src/entry.rs`

The canonical `UNINC_CHAIN_V1` hash computation (SHA-256 with version prefix, length-prefixed variable fields, sorted metadata). This IS the protocol — it must be hand-rolled because it's the thing third-party verifiers implement against.

---

## Evaluated and Rejected

| Crate | Why we looked at it | Why we didn't use it |
|-------|--------------------|--------------------|
| `pgwire` | Postgres wire protocol | Server-oriented, not proxy-oriented. Community-maintained by individual. |
| `governor` | Rate limiting | 15+ transitive deps for 73 lines of logic. Overkill for synchronous single-process check. |
| `scram` | SCRAM authentication | We only need username extraction, not full SCRAM. |
| `aws-sigv4` | S3 signature verification | We don't verify signatures, only extract access key IDs. |
| `percent-encoding` | URL decoding in S3 auth | Our 24-line `urldecode` handles exactly `%XX` on ASCII access keys. The crate handles UTF-8 multibyte which we don't need. Optional future cleanup. |

---

## Dependency Health Watchlist

| Crate | Concern | Action if needed |
|-------|---------|-----------------|
| `rust-s3` | Less mainstream than `aws-sdk-s3`. Watch for maintenance status. | Switch to `aws-sdk-s3` (official AWS SDK) if `rust-s3` becomes unmaintained. API is similar. |
| `drand-verify` | Small crate by Nois Labs. Last updated Dec 2023 on crates.io. | BLS12-381 math doesn't change. If the crate becomes unmaintained, the algorithm is stable and we could vendor the ~200 lines of BLS code. |
| `mongodb` 2.x | Pinned to 2.x for bson type compatibility. 3.x exists. | Upgrade to 3.x when bson 3.x stabilizes and the type-inference bugs are fixed. |

---

## Observer-Specific Dependencies

The observer crate (`crates/observer/`) uses the same workspace dependencies plus:

| Crate | What it does in the observer |
|-------|------------------------------|
| `tokio-postgres` | SQL polling of logical replication slot via `pg_logical_slot_get_changes()` |
| `mongodb` | Change streams via `watch()` for real-time oplog tracking |
| `async-nats` | MinIO bucket notification subscription |
| `chain-store` | Disk writes in the same format as the proxy's chain-engine |
| `dashmap` | In-memory cache of per-chain head hashes |

The observer does NOT use `pgwire-replication` in v1 — it polls via SQL instead of streaming via the replication protocol. This is simpler (standard SQL, no binary pgoutput parsing) with 1-second latency, which is acceptable for operation-level comparison. Streaming replication is a future upgrade for sub-second latency if needed.
