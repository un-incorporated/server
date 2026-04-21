# Data Access Transparency, Version 1

Draft                                                   Tiger Wang (Yun Wang)
Version 1.0.0-pre                                                   April 2026

## Status of this memo

This is a draft specification, version 1.0.0-pre. It is published to invite implementation and review. It is not an IETF document and has not been reviewed by the IETF. Distribution of this document is unlimited.

## Copyright notice

This specification is placed in the public domain under the Creative Commons CC0 1.0 Universal dedication. Reference implementations referenced in Appendix C are released under their own licenses; those licenses do not encumber independent implementations of this specification.

## Abstract

This document specifies Data Access Transparency version 1, a format and protocol for cryptographically verifiable logs of server-side database access events. Entries in a Data Access Transparency log are organized in append-only hash chains keyed by a pseudonymous identifier for the affected end user, or by deployment for administrative events. The specification defines a binary entry format, a canonical serialization of entry payloads, the hash algorithm used to link entries, verification algorithms, an HTTP API for retrieving chain contents, and a JSON Web Token (JWT) scheme for authenticating API access.

The protocol is designed to produce tamper-evident records of accesses against a hosted database by a transparency proxy, such that the affected end user can verify those records independently of the party operating the proxy. This specification is independent of any implementation. A conformant implementation MUST reproduce the same hash outputs for the same byte-level inputs and MUST expose the HTTP and JWT contracts defined in this document.

## Table of contents

1. Introduction
    1.1. Scope
    1.2. Requirements language
    1.3. Related work
2. Terminology
3. Protocol overview
    3.1. Deployment components
        3.1.1. Access capture completeness
    3.2. Chain topology
    3.3. Replication-stream observer
4. Chain entry format
    4.1. Binary layout
    4.2. Version
    4.3. Index
    4.4. Timestamp
    4.5. Prev_hash
    4.6. Payload_type
    4.7. Payload_length
    4.8. Payload
    4.9. Payload canonicalization
    4.10. AccessEvent payload
    4.11. DeploymentEvent payload
        4.11.1. `user_erasure_requested` category
        4.11.2. `retention_sweep` category
    4.12. ObservedDeploymentEvent payload
5. Hash algorithm and verification
    5.1. Hash algorithm
    5.2. Full-chain verification
    5.3. Incremental verification
    5.4. Divergence bisection
    5.5. Scheduled Verification
        5.5.1. Process 1: Per-user chain cross-replica verification
        5.5.2. Process 2: Deployment chain observer-proxy verification
6. Authentication
    6.1. JWT format
    6.2. Audiences
    6.3. Subject binding for user endpoints
    6.4. Sidecar metadata
7. HTTP API
    7.1. Per-user chain endpoints
    7.2. Deployment chain endpoints
    7.3. Erasure endpoint
8. Deletion and retention
    8.1. User-initiated erasure
    8.2. Retention sweeps
    8.3. Effect on verification
9. Versioning
10. Security considerations
    10.1. Threat model
    10.2. Hash primitive
    10.3. HMAC salt disclosure
    10.4. JWT signing key disclosure
    10.5. Token replay
    10.6. Observer compromise
    10.7. Post-quantum security
11. IANA considerations
12. References
    12.1. Normative references
    12.2. Informative references
13. Acknowledgements

Author's address

Appendix A. Compliance mapping (informative)
Appendix B. Related work (informative)
Appendix C. Reference implementations (informative)
Appendix D. Other applications of the chain format (informative)
Appendix E. Evaluating this specification (informative)
Appendix F. Worked example (informative)

---

## 1. Introduction

Database audit logs today are produced by the same party whose access is being recorded. A party with write access to the log can rewrite, suppress, or fabricate entries without detection by the affected user. This document specifies a protocol in which entries are organized into append-only cryptographic hash chains, the heads of those chains are published before the corresponding database access is permitted to proceed, and the verification algorithm is executable by the affected user on their own device without reliance on the operator.

The protocol does not prevent authorized access. It records accesses such that silent tampering after the fact is detectable by any party in possession of a chain and its claimed head hash. Throughout this document, the verifying party is termed the "affected user"; the party operating the transparency proxy is termed the "operator."

The practical consequence is a shift in who holds the ability to verify a data access. Today, when an operator tells a data subject "your data was accessed," the subject has to take that assertion on faith — the audit log sits inside the operator's trust boundary. Under the protocol defined here, the subject receives a chain they can walk themselves, on their own device, with software the operator does not control. Operators who behave correctly lose nothing. Operators who do not lose the ability to lie silently.

### 1.1. Scope

This document specifies:

1. The binary format of a chain entry (Section 4.1).
2. The canonicalization rules for entry payloads (Section 4.9).
3. The schemas for the two payload types defined in this version: `AccessEvent` (Section 4.10) and `DeploymentEvent` (Section 4.11).
4. The hash algorithm linking entries (Section 5.1).
5. Algorithms for full-chain verification, incremental verification, and divergence bisection (Sections 5.2 through 5.4).
6. An HTTP API for chain retrieval and deletion (Section 7).
7. A JWT scheme for authenticating HTTP API access (Section 6).
8. Semantics for chain deletion and retention (Section 8).

This document does not specify:

1. Storage and durability mechanics for chain entries across replicas.
2. Byzantine fault tolerance topology for a multi-replica deployment.
3. Transport from proxy to chain engine within a deployment.
4. Use of the chain format by non-server applications.

### 1.2. Requirements language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

### 1.3. Related work

The architectural pattern of an append-only cryptographic log publicly verifiable by the affected party is established in Certificate Transparency [RFC6962] and subsequently in the Sigstore / Rekor system [SIGSTORE]. This specification applies the same pattern to database access events; differences and points of reuse are summarized in Appendix B.

A conformant implementation reuses the following existing specifications at the byte level: JSON Canonicalization Scheme [RFC8785] (Section 4.9), SHA-256 [FIPS180-4] (Section 5.1), and JSON Web Tokens [RFC7519] with HS256 [RFC7518] (Section 6).

The principle that the specification, rather than any operator, serves as the arbiter of correctness is adopted from ACME [RFC8555]. No wire format or procedure from [RFC8555] is reused; only the principle.

---

## 2. Terminology

For the purposes of this document:

**Chain.** An append-only ordered sequence of entries, each committing to all prior entries via the `prev_hash` field defined in Section 4.5.

**Entry.** A single record in a chain, serialized per Section 4.1.

**Head hash.** The SHA-256 hash of the serialized bytes of the most recent entry in a chain. The head hash commits to the entire chain up to and including that entry.

**Per-user chain.** A chain whose identifier is `HMAC-SHA-256(deployment_salt, user_id)` and whose entries carry `AccessEvent` payloads.

**Deployment chain.** A chain identified by deployment identifier whose entries carry `DeploymentEvent` payloads.

**Payload.** The deserialized JSON object inside an entry, of the type indicated by `payload_type`.

**Verifier.** An implementation of the algorithms specified in Sections 5.2 through 5.4.

**Tombstone.** An `DeploymentEvent` entry with `category` equal to `user_erasure_requested` or `retention_sweep`, recording the deletion of other data.

**Affected user.** The end user whose data is accessed by an event recorded as an `AccessEvent`.

**Operator.** The party operating a transparency proxy and associated chain infrastructure.

---

## 3. Protocol overview

### 3.1. Deployment components

A conformant deployment consists of:

1. A **transparency proxy** sitting in front of one or more database primitives (Postgres, MongoDB, S3). Application traffic to the database MUST pass through the proxy.
2. A **chain engine** accepting access events from the proxy and producing chain entries as specified in Section 4.
3. A **chain store** retaining serialized chain entries in a durable storage backend.
4. A **chain API** serving HTTP requests as specified in Section 7.
5. A **verifier** executable in the affected user's environment, implementing the algorithms in Sections 5.2 through 5.4.

A deployment MAY additionally include:

6. A **replication-stream observer** subscribing to the database primitive's native replication stream and independently computing chain entries (Section 3.3).

#### 3.1.1. Access capture completeness

The compliance model of this specification is **total access transparency**, not write-only transparency. A conformant proxy MUST capture every data-access operation that passes through it — including reads (`SELECT`, MongoDB `find`, S3 `GET`/`HEAD`), writes (`INSERT`/`UPDATE`, MongoDB inserts/updates, S3 `PUT`), deletes (`DELETE`, MongoDB deletes, S3 `DELETE`), schema changes (DDL, MongoDB index operations), and exports (`COPY`, dumps) — and MUST emit the corresponding `AccessEvent` (Section 4.10) to the chain engine BEFORE forwarding the operation to the database primitive. The hash algorithm in Section 5.1 treats every captured operation identically; the wire-format AccessEvent carries an `action` enum (Section 4.10) with variants for every captured verb.

The asymmetric visibility of database replication streams — which typically carry writes but not reads — does NOT relax this proxy-side capture requirement. It means only that the replication-stream observer (Section 3.3), when present, has reduced coverage for read operations relative to write operations. That is an observer-side limitation, not a proxy-side one. A conformant proxy that captured only writes would violate the access-transparency claim the verifier-side proof relies on, even if the observer still cross-checked writes against the WAL/oplog/bucket-notification streams.

This specification does not prescribe how a deployment sources read-capture on the observer side. Implementations seeking non-default read coverage have several options per primitive: Postgres `log_statement=all` (or the `pgaudit` extension) with log-shipping to the observer; MongoDB Database Profiler at `slowms=0` with replication of `system.profile`; S3 `s3:ObjectAccessed:*` bucket notifications. The cost and operational burden of read capture on the observer side is deployment-specific; this specification defines what the proxy MUST capture, not how an observer MUST rediscover it from replication.

#### 3.1.2. Actor identity propagation

The compliance model requires attribution: every captured operation MUST record the principal that initiated it (`AccessEvent.actor_id`, `DeploymentEvent.actor_id`, Sections 4.10 and 4.11) and — where a replication-stream observer is present (Section 3.3) — the same principal MUST be recoverable on the observer side so that the `ObservedDeploymentEvent.actor_id_hash` field (Section 4.12) satisfies byte-identity under Section 5.5 comparison.

The proxy knows the principal because it authenticated the client connection. The observer reads the database primitive's replication stream and has no direct path to the client's session identity. To close that gap a conformant deployment MUST propagate the actor identifier into the replication stream by a mechanism the observer can recover. This specification does not mandate a specific mechanism, but defines the observer-recoverability contract: for every operation that appears on both chains in the §5.5 comparison set, the pre-hash string the proxy HMAC'd to form `actor_id_hash` MUST equal the pre-hash string the observer HMAC'd from the replication stream.

A conformant deployment MAY satisfy the observer-recoverability contract by, for example: (a) writing a dedicated audit row to a sentinel table / collection before each forwarded operation so the row appears ahead of the operation in the replication stream; (b) attaching an object-metadata header to S3 PUTs that the bucket notification preserves; (c) injecting a logical replication message that a MESSAGE-capable output plugin propagates to the observer; or (d) any mechanism equivalent in effect. The mechanism is implementation-defined so that deployments can match the propagation primitive to what their chosen output plugin / change-stream API / bucket-notification configuration supports.

The relationships between these components and the trust boundary between the operator's infrastructure and the affected user are shown in Figure 1.

```text
   ┌──────────────────────────────────────────────────────────────┐
   │                  Operator's infrastructure                   │
   │                                                              │
   │   ┌──────────┐     ┌────────────┐      ┌────────────┐        │
   │   │   App    │ (1) │Transparency│ (2)  │  Database  │        │
   │   │ clients  ├────▶│   Proxy    ├─────▶│ primitive  │        │
   │   │          │     │  (§3.1)    │      │(PG/Mongo/S3│        │
   │   └──────────┘     └──────┬─────┘      │   §3.1)    │        │
   │                           │ (3)        └──────┬─────┘        │
   │                           │ AccessEvent       │ (5)          │
   │                           ▼                   │ replication  │
   │                    ┌────────────┐             │ stream       │
   │                    │   Chain    │             ▼              │
   │                    │   Engine   │      ┌────────────┐        │
   │                    │   (§3.1)   │      │  Observer  │        │
   │                    └──────┬─────┘      │  (§3.3,    │        │
   │                           │ (4)        │  OPTIONAL) │        │
   │                           │ append     └──────┬─────┘        │
   │                           ▼                   │              │
   │                    ┌────────────┐             │ (6)          │
   │                    │   Chain    │◀────────────┘ compare      │
   │                    │   Store    │               heads        │
   │                    │ (§3.1,§3.2)│                            │
   │                    └──────┬─────┘                            │
   │                           │ (7) read                         │
   │                           ▼                                  │
   │                    ┌────────────┐                            │
   │                    │ Chain API  │                            │
   │                    │ (§6, §7,   │                            │
   │                    │ JWT-gated) │                            │
   │                    └──────┬─────┘                            │
   └───────────────────────────┼──────────────────────────────────┘
                               │ (8) HTTPS + JWT (§6)
           ════ Trust boundary ╪ ════════════════════════
                               │
                               ▼
                       ┌──────────────┐
                       │   Verifier   │  (§3.1, §5.2)
                       │  on affected │  Runs on the user's
                       │   user's     │  own device (browser
                       │   device     │  WASM, CLI, etc.) —
                       │              │  outside the
                       │              │  operator's control.
                       └──────────────┘

   (1) application issues a database query through the proxy.
   (2) proxy forwards the query to the database primitive only
       after step (3) durably succeeds.
   (3) proxy emits an AccessEvent (§4.10) to the chain engine.
   (4) chain engine appends an entry to the chain store per
       the format of Section 4 and the hash construction of
       Section 5.
   (5) where present, the observer independently constructs a
       chain from the database's native replication stream
       (Postgres WAL, MongoDB oplog, S3 bucket notifications)
       and maintains its own chain.
   (6) observer's chain head is compared to the proxy's chain
       head for the same key. Comparison MAY be performed by
       the observer itself or by a separate verification task
       (§3.3). Any divergence MUST produce a verification_
       failure DeploymentEvent on the deployment chain (§4.11),
       appended through the chain engine at step (3)/(4)
       (feedback arrow elided for clarity).
   (7) chain API reads entries from the chain store under JWT
       authentication (§6, §7).
   (8) verifier on the affected user's device fetches entries
       over HTTPS and independently recomputes the hash
       construction of Section 5.

       Figure 1: Protocol-level data flow (informative;
                 deployment topology varies)
```

Figure 1 is abstract: it fixes the protocol-level data flow and the position of the trust boundary, but does not specify deployment topology. A conformant deployment MAY co-locate the proxy, chain engine, chain store, and chain API on a single process, distribute them across separate hosts, or introduce intermediate queues (such as a message broker) between the proxy and the chain engine. The reference implementation's multi-host Google Cloud topology — including message-broker placement, private-subnet containment, and per-role service accounts — is described informatively in the accompanying reference-implementation diagram at `server/docs/topology.svg`.

### 3.2. Chain topology

Let `HMAC(K, M)` denote HMAC-SHA-256 per [RFC2104] with key `K` and message `M`. String-valued messages are UTF-8 encoded to octets before HMAC input. Let `deployment_salt ∈ {0,1}^256` be a per-deployment random secret. The chain-identifier function is defined for this version as:

```text
chain_id_user(user_id)     := HMAC(deployment_salt, user_id)   ∈ {0,1}^256
chain_id_org(deployment)   := deployment.id                    ∈ {0,1}*
```

Two classes of chain are defined:

1. A **per-user chain** keyed by `chain_id_user(user_id)`, containing `AccessEvent` entries (Section 4.10) that describe accesses to a specific end user's data.
2. A **deployment chain** keyed by `chain_id_org(deployment)`, containing `DeploymentEvent` entries (Section 4.11) that describe administrative events affecting the deployment.

A deployment MUST maintain exactly one deployment chain. A deployment maintains one per-user chain for each distinct user whose data has been accessed through the transparency proxy.

### 3.3. Replication-stream observer

Where present, the replication-stream observer reads from the database primitive's native replication stream (e.g., Postgres write-ahead log via logical replication slot, MongoDB oplog via change stream, or S3 bucket notifications) and independently constructs chain entries from observed replication events. The observer's chain is the **observation chain**, keyed by

```text
chain_id_observation(deployment)  :=  chain_id_org(deployment)
```

as defined in Section 3.2, and contains `ObservedDeploymentEvent` entries (Section 4.12). The observation chain reuses the deployment-chain identifier because both chains describe the same deployment, but the two are independent sequences: different `prev_hash` lineages, different envelope timestamps, different entry sets, maintained on independent storage substrates (the observation chain lives on the observer's local disk; the proxy's deployment chain lives in the proxy's chain store). A chain-identifier collision therefore does not occur in practice, because the two storage substrates do not share a keyspace.

At verification time, the observer's observation chain is compared with the proxy's deployment chain. The comparison is **payload-level**, not chain-head-level: the two chains have independent lineage (independent `prev_hash` sequences, independent envelope timestamps, and the proxy chain additionally carries `DeploymentEvent` entries for deploy/config/schema/system events the observer cannot see), so a chain-head hash match is neither expected nor meaningful. What IS expected is byte-level equality of the canonicalized payload bytes for the `ObservedDeploymentEvent` subset (Section 4.12): the observer and proxy emit the same field values for the same operation, and JCS canonicalization produces identical bytes. The verification procedure compares these payload bytes per Section 5.5 and checks set inclusion. Any replication-observed operation that is absent from the proxy chain MUST cause the deployment to emit an `DeploymentEvent` with `category = "verification_failure"` on the deployment chain (Section 4.11).

A conformant deployment MAY split this responsibility between two components: an observer that constructs the observation chain and exposes its entries over an internal endpoint, and a separate verification task that reads those entries, performs the payload comparison, and emits the `verification_failure` `DeploymentEvent`. The emission requirement is satisfied so long as every detected mismatch results in such an entry on the deployment chain; the specification places no requirement on which component performs the comparison.

The v1 observer is a single replica. This version does not specify Byzantine fault tolerance semantics for multiple observers.

Rationale: earlier drafts specified head-level byte comparison between the observer and the proxy. That formulation fails because the two chains have independent lineage — even when both authorities record the same operations, their envelope timestamps, indices, and `prev_hash` sequences will never align. The payload-level comparison avoids that problem by comparing only what both authorities can honestly produce in byte-identical form: an `ObservedDeploymentEvent` (Section 4.12) carrying `(action, resource, actor_id_hash, query_fingerprint)` — fields derivable from a replication stream alone — with no wall-clock timestamp, no source-IP or session-identifier leakage, and no per-user identifiers (deployment-chain entries are table-level per Section 4.11). The richer proxy-side metadata (source IP, session identifier, correlation identifier, query shape) stays in non-hashed sidecar metadata (Section 6.4) where it does not participate in the comparison. Cross-host envelope-timestamp skew and DB replication latency are handled by the tick-based cursor-advance mechanism of Section 5.5.2: entries stay in the un-compared **tail** until the slower side has committed its counterpart, so legitimate lag produces tail depth rather than a verification failure. Envelope timestamps do not participate in the hashed payload bytes of Section 4.12.

---

## 4. Chain entry format

### 4.1. Binary layout

Each entry is serialized to a byte string using the following layout. All multi-byte integers are encoded in network byte order (big-endian).

```text
Offset   Size         Field               Notes
------   ----         -----               -----
  0      1            version             Protocol version. MUST be 0x01
                                          for v1 of this specification.
  1      8            index               Monotonic entry index within this
                                          chain, starting at 0.
  9      8            timestamp           Unix seconds since epoch (UTC).
 17     32            prev_hash           SHA-256 of the previous entry's
                                          serialized bytes. For index=0,
                                          prev_hash MUST be 32 octets of 0x00.
 49      1            payload_type        0x01 = AccessEvent     (Section 4.10)
                                          0x02 = DeploymentEvent        (Section 4.11)
                                          0x03 = ObservedDeploymentEvent (Section 4.12)
 50      4            payload_length      Length of payload in octets.
                                          MUST NOT exceed 1 048 576 (1 MiB).
 54      N            payload             Payload octets, N = payload_length.
                                          Serialized per Section 4.9.
```

Total entry size is 54 + N octets, where N ≤ 1 048 576.

### 4.2. Version

The `version` field MUST be `0x01` for entries conforming to this document. A verifier encountering a `version` value it does not recognize MUST reject the entry.

### 4.3. Index

The `index` field is a monotonically increasing 64-bit unsigned integer. The first entry in a chain has `index = 0`. An entry at index N MUST be preceded in the chain by entries at all indices 0..N-1. A verifier encountering a gap in indices MUST treat the chain as corrupt.

### 4.4. Timestamp

The `timestamp` field records the time at which the entry was created, in Unix seconds, UTC. Ordering of `timestamp` values is NOT REQUIRED to match ordering of `index` values. A verifier MAY use `timestamp` for out-of-band checks but MUST NOT use it for chain-integrity determination.

### 4.5. Prev_hash

Let `H : {0,1}* → {0,1}^256` denote SHA-256 [FIPS180-4], and let `serialize : Entry → {0,1}*` denote the function mapping an entry to the byte sequence defined in Section 4.1 with payload canonicalized per Section 4.9.

For a chain `C = (e_0, e_1, ..., e_{n-1})`, the `prev_hash` field MUST satisfy:

```text
e_0.prev_hash   =   0x00 ^ 32                           (the 32-octet zero string)
e_i.prev_hash   =   H(serialize(e_{i-1}))               for all i ∈ [1, n-1]
```

That is, the `prev_hash` field of the first entry is 32 octets of `0x00`, and the `prev_hash` field of every subsequent entry is the SHA-256 hash of the complete serialized byte sequence of the immediately preceding entry (including that entry's own `prev_hash` field).

This constraint establishes the hash chain linking entries. Modification of any single octet of any entry `e_k` invalidates `e_{k+1}.prev_hash` and therefore invalidates the predicate of Section 5.2.1. Restoring predicate validity after such a modification requires recomputing `H(serialize(e_j))` for every `j ≥ k`, which changes the chain head hash (Section 5.1); any verifier in possession of a previously-published head will detect the change.

### 4.6. Payload_type

Defined values:

- `0x01`: the payload is an `AccessEvent` as specified in Section 4.10.
- `0x02`: the payload is an `DeploymentEvent` as specified in Section 4.11.
- `0x03`: the payload is an `ObservedDeploymentEvent` as specified in Section 4.12.

All other values are reserved for future versions of this specification. A v1 verifier MUST reject entries with `payload_type` values other than `0x01`, `0x02`, or `0x03`.

### 4.7. Payload_length

A 32-bit unsigned integer giving the length of the payload in octets, in network byte order. The value MUST NOT exceed 1 048 576. A conformant writer MUST NOT produce entries with larger payloads; a verifier MAY reject such entries on read.

### 4.8. Payload

A UTF-8 encoded JSON document canonicalized as specified in Section 4.9, carrying a payload of the type indicated by `payload_type`.

### 4.9. Payload canonicalization

Payload serialization is JSON Canonicalization Scheme (JCS) [RFC8785] with one additional constraint (rule 5) on OPTIONAL member absence. Rules 1 through 4 are direct applications of [RFC8785] and carry no deviation; a conformant JCS library implementation satisfies them. Rule 5 is the only point at which this specification extends [RFC8785] and it is the rule most likely to produce silent cross-implementation hash divergence if loosened — readers working on interoperability SHOULD focus there first.

1. Object member names MUST be sorted per [RFC8785] Section 3.2.3 (UTF-16 code-unit order).
2. Whitespace outside JSON strings MUST NOT be emitted.
3. String values and object member names MUST be normalized to Unicode Normalization Form C (NFC) prior to serialization. This rule applies at every depth of the payload tree, not only at its outermost members. Without it, two conformant producers that emit byte-equivalent semantic content in different Unicode normalization forms (for example, `U+00E9` vs `U+0065 U+0301` for the character "é") would produce different canonicalized bytes and therefore different chain hashes. The object-member-name half of this rule matters independently of the string-value half: [RFC8785] sorts member names by UTF-16 code unit, so two member names that differ only in normalization form sort to different byte positions and produce different canonicalized bytes even before any string value is serialized.
4. Number serialization MUST follow [RFC8785] Section 3.2.2.3, without trailing zeros and without a leading `+`.
5. OPTIONAL members whose value is absent MUST be omitted from the canonicalized output. The JSON literal `null` MUST NOT appear in a canonicalized payload. A verifier receiving a payload that contains `null` MUST reject the entry as malformed. This rule removes a hash-determinism ambiguity: without it, two conformant implementations could disagree on whether an absent OPTIONAL member serializes as nothing or as `null`, producing different bytes and therefore different hashes for what is semantically the same payload.

A conformant JCS library implementation satisfies items 1 through 4; item 5 is an additional constraint that the producer MUST enforce before passing the payload to the JCS library. Implementers SHOULD use an existing JCS library where one is available.

Any signature or authentication tag computed over a payload MUST be computed over the canonicalized form; otherwise cross-implementation verification will fail.

### 4.10. AccessEvent payload

An `AccessEvent` payload is a JSON object with the following members:

```json
{
  "actor_id":          "<string>",
  "actor_type":        "app" | "admin" | "agent" | "system" | "suspicious",
  "actor_label":       "<string>",
  "protocol":          "postgres" | "mongodb" | "s3",
  "action":            "read" | "write" | "delete" | "export" | "schema_change",
  "resource":          "<string>",
  "affected_user_ids": ["<string>", "..."],
  "query_fingerprint": "<string, REQUIRED>",
  "query_shape":       "<string, OPTIONAL>",
  "scope":             { "rows": 0, "bytes": 0 },
  "source_ip":         "<string>",
  "session_id":        "<string>",
  "correlation_id":    "<string, OPTIONAL>"
}
```

`affected_user_ids` entries MUST be hex-encoded outputs of `HMAC-SHA-256(deployment_salt, user_id)` per Section 3.2. The array MUST be sorted in ascending byte-wise lexicographic order (equivalent to ascending order of the hex-encoded strings under Unicode code-point comparison, since hex encoding uses only ASCII `0-9a-f`), and MUST NOT contain duplicate entries. Producers MUST apply this ordering and deduplication before handing the payload to the canonicalizer of Section 4.9; verifiers MUST reject a payload whose `affected_user_ids` array is unsorted or contains duplicates as malformed. [RFC8785] JCS is silent on array element ordering (it prescribes only object-member ordering), so without this rule two conformant producers resolving the same query via different query plans, index orders, or set-iteration orders would produce different canonicalized bytes — and therefore different chain hashes — for semantically identical events. This rule closes that cross-implementation divergence surface. `query_fingerprint` MUST be the 64-character hex encoding of a SHA-256 hash over the normalized query shape; it serves as a dedup and index key and MUST NOT be derived from the raw query text. `query_shape`, where present, is a human-readable parameterized template (e.g. `"SELECT email FROM users WHERE id = $1"`) for display in audit UIs; it is OPTIONAL because some protocols cannot yield a safe parameterized form (e.g., opaque binary payloads). `session_id` and `correlation_id`, where present, MUST be UUID strings as defined in [RFC4122].

### 4.11. DeploymentEvent payload

An `DeploymentEvent` payload is a JSON object with the following members:

```json
{
  "actor_id":   "<string>",
  "actor_type": "admin" | "system" | "cicd" | "operator",
  "category":   "admin_access" | "admin_lifecycle" | "config" | "deploy"
              | "schema" | "system" | "approved_access" | "egress"
              | "user_erasure_requested" | "retention_sweep"
              | "verification_failure" | "nightly_verification"
              | "replica_reshuffle",
  "action":     "<string>",
  "resource":   "<string>",
  "scope":      { },
  "details":    { },
  "source_ip":  "<string>",
  "session_id": "<string, OPTIONAL>"
}
```

DeploymentEvent payloads with `category = "admin_access"` MUST NOT include `affected_user_ids` or row-level scope information. The deployment chain is defined as table-level; per-user data is carried in per-user chains (Section 3.2) to permit user-initiated erasure under Section 8.1.

Two categories (`user_erasure_requested` and `retention_sweep`) carry additional per-category field-value constraints specified in Section 4.11.1 and Section 4.11.2 below. The procedures in Section 8 that emit these tombstones populate fields per those subsections.

#### 4.11.1. `user_erasure_requested` category

When used for a user-initiated erasure (Section 8.1), an `DeploymentEvent` carries the following field values. Fields not listed here follow the general `DeploymentEvent` rules.

| Field | Value |
| ----- | ----- |
| `category` | `"user_erasure_requested"` |
| `actor_id` | The hex-encoded `user_id_hash` (HMAC-SHA-256 of the user id under the deployment salt). The plaintext user id MUST NOT appear on the tombstone. |
| `actor_type` | `"system"` (the server committed the erasure; the request came from the data subject — recorded in `details.requested_by`). |
| `action` | `"delete"` |
| `resource` | `"user_chain"` |
| `scope` | A JSON object of the form `{"description": <string>}`, where `<string>` is a short human-readable summary, e.g., `{"description": "user_chain erasure for <user_id_hash>"}`. The object wrapper preserves the Section 4.11 base-schema convention that `scope` is a JSON object on every `DeploymentEvent` category; the free-form summary is carried inside under the `description` member. |
| `details.requested_by` | `"data_subject"` for a user-initiated erasure (distinguishes from retention sweeps, which set it to `"retention_policy"`). |
| `details.user_id_hash` | The same hex-encoded `user_id_hash` as `actor_id`, restated for consumers that index `details` by key. |
| `details.source_ip` | The source IP of the HTTP caller that requested erasure, as recorded by the server's proxy-aware extraction. May be `"unknown"` if no trusted header is present. |
| `details.requested_at` | Unix seconds when the server received the DELETE request. |

#### 4.11.2. `retention_sweep` category

When used for a retention-driven deletion (Section 8.2), an `DeploymentEvent` carries the following field values. Fields not listed here follow the general `DeploymentEvent` rules.

| Field | Value |
| ----- | ----- |
| `category` | `"retention_sweep"` |
| `actor_id` | `"system:retention-reaper"` |
| `actor_type` | `"system"` |
| `action` | `"delete"` |
| `resource` | `"chain"` |
| `scope` | A JSON object of the form `{"description": <string>}`, where `<string>` is a short human-readable summary, e.g., `{"description": "retention sweep removed chain <chain_id>"}`. The object wrapper preserves the Section 4.11 base-schema convention that `scope` is a JSON object on every `DeploymentEvent` category. |
| `details.chain_id` | The hex-encoded chain identifier that was removed. |
| `details.entry_count` | The number of entries in the chain at the moment of deletion. |
| `details.created_at` | Unix seconds when the chain was originally created. |
| `details.retention_days` | The retention threshold (in days) in effect at the time of deletion. |

### 4.12. ObservedDeploymentEvent payload

An `ObservedDeploymentEvent` payload is a JSON object carrying only the fields that both the proxy and the replication-stream observer (Section 3.3) can honestly produce from their independent views of the same database operation. The schema is a strict structural subset of `DeploymentEvent` (Section 4.11): every field present on `ObservedDeploymentEvent` is also present on `DeploymentEvent`, with the same encoding. The converse does not hold — `DeploymentEvent` carries additional fields (`source_ip`, `session_id`, `actor_type`, `category` variants outside admin access) that the observer cannot recover from replication metadata.

```json
{
  "action":            "read" | "write" | "delete" | "schema_change",
  "resource":          "<string>",
  "actor_id_hash":     "<hex, 64 chars, HMAC-SHA-256 of actor under deployment_salt>",
  "query_fingerprint": "<hex, 64 chars>"
}
```

- `action` is drawn from the same enumeration as `AccessEvent.action` (Section 4.10) excluding `"export"`, which has no native replication-stream counterpart under any v1 primitive: Postgres `COPY TO` surfaces as a sequence of row reads in the WAL (indistinguishable from a normal `SELECT`), MongoDB `mongodump` is a client-side cursor walk that produces no oplog entry, and S3 bulk copy operations surface as a sequence of `GET`s on the bucket-notification side. A v1 `ObservedDeploymentEvent.action` MUST therefore be one of `{"read", "write", "delete", "schema_change"}`.
- `resource` is the namespace-qualified table, collection, or bucket+key-prefix affected. Format per Section 4.10's `resource` rules.
- `actor_id_hash` is the HMAC-SHA-256 of the actor identifier under `deployment_salt`, encoded lower-case hex. Proxy- and observer-side values MUST agree on the actor identifier pre-hash for byte-identical output; Section 3.3 describes the replication-marker convention that makes this identifier recoverable from WAL/oplog/notification streams.
- `query_fingerprint` is the SHA-256 of a canonicalized representation of the DB-level operation (identical to `AccessEvent.query_fingerprint`, Section 4.10), encoded hex.

This payload deliberately omits two fields present in earlier drafts:

- **`timestamp`**: each side's envelope (Section 4.4) already records when that chain witnessed the operation. Duplicating the value into the payload would force the proxy and observer to agree on a single wall-clock reading across two hosts and across replication latency — a synchronization problem that adds no integrity property the envelope does not already provide. Comparison (Section 5.5) is therefore pure canonicalized-payload byte equality; envelope timestamps do not participate in the comparison at all. Replication lag and cross-host clock skew are absorbed by the monotonic-cursor tail of Section 5.5.2, not by any timestamp window.
- **`affected_user_id_hashes`**: the deployment chain is table-level per Section 4.11 ("MUST NOT include row-level scope or `affected_user_ids`"), so the proxy-side projection carries no per-user identifiers. The observer cannot resolve user identifiers from replication alone (no schema configuration), so its direct emission carries none either. Both sides would uniformly carry an empty array, making the field pure overhead on every entry. A successor version MAY reintroduce the field under a new payload type once observer-side schema-aware user resolution lands.

Canonicalization per Section 4.9 applies unchanged. The observation chain (Section 3.3) contains only `ObservedDeploymentEvent` entries; the proxy's deployment chain MAY contain `ObservedDeploymentEvent` entries for replication-visible operations interleaved with `DeploymentEvent` entries for system, config, deploy, and schema events. The verification comparison (Section 5.5) operates on the `ObservedDeploymentEvent` subset of the deployment chain.

Rich operational metadata (source IP, session identifiers, query shape, correlation IDs) for proxy-side entries is carried in a sidecar metadata file (Section 6.4) outside the entry's hashed bytes. Sidecar data is served by the chain-read API alongside the entry but does not participate in the hash chain; tampering with a sidecar does not invalidate the chain but is detected by users who also receive the original emit-time digest via the JWT audience binding (future work; not required for v1).

---

## 5. Hash algorithm and verification

### 5.1. Hash algorithm

Let `H : {0,1}* → {0,1}^256` denote SHA-256 [FIPS180-4]. Let `Entry` denote the set of byte sequences conforming to the layout of Section 4.1 with a payload canonicalized per Section 4.9. Let `serialize : Entry → {0,1}*` denote the function mapping an entry to that byte sequence.

The entry hash of an entry `e ∈ Entry` is defined as:

```text
entry_hash(e)   :=   H(serialize(e))
```

For a chain `C = (e_0, e_1, ..., e_{n-1})`, the chain head hash is defined as:

```text
chain_head_hash(C)   :=   H(serialize(e_{n-1}))         if n ≥ 1
chain_head_hash(C)   :=   0x00 ^ 32                     if n = 0
```

Observe that `chain_head_hash(C)` is NOT a hash computed over the concatenation or any other composition of multiple entries, and implementations MUST NOT compute it by hashing any set of entries other than `e_{n-1}` alone. Because `e_{n-1}.prev_hash` transitively commits to every prior entry via the constraint of Section 4.5, the single 32-octet output of `H(serialize(e_{n-1}))` suffices to commit to the entire chain.

Readers unfamiliar with hash-chain constructions often expect the head to be a digest taken over every entry in the chain. It is not. The commitment to prior entries lives in the `prev_hash` field of each entry, not in a separate aggregating digest. To see why this is sufficient: `entry_{n-1}.prev_hash` is defined to be `H(serialize(entry_{n-2}))`; `entry_{n-2}.prev_hash` is `H(serialize(entry_{n-3}))`; and so on recursively to `entry_0.prev_hash = 0x00 ^ 32`. Modifying any byte of any `entry_k` (`k < n-1`) changes `H(serialize(entry_k))`, which forces a change to `entry_{k+1}.prev_hash`, which changes `H(serialize(entry_{k+1}))`, and so on — the alteration propagates through the serialized bytes of every subsequent entry and therefore changes `H(serialize(entry_{n-1}))`, the head. Consequently, the head hash behaves as a cryptographic "seal" over the complete chain: its 32 octets are sensitive to every byte of every prior entry, and comparing two head hashes is equivalent to comparing the two chains in full without transmitting the entries themselves. Head comparison across replicas therefore runs in O(1) time, independent of `n`, and incremental verification (Section 5.3) reuses a previously-trusted head as the starting point for a shorter verification walk.

**Forward compatibility with non-hash verification mechanisms (informative).** Version 1 verification is purely hash-based: the validity predicate of Section 5.2.1 is satisfied by recomputing SHA-256 outputs and comparing byte strings. A successor version MAY introduce additional, complementary verification mechanisms without replacing this hash-based core. Three directions are anticipated in this specification: (i) **witness co-signatures on chain heads** — multi-party threshold signatures over the head hash, per the multi-observer quorum planned in Section 10.6; (ii) **Merkle-tree inclusion proofs** for the deployment chain specifically, to admit O(log n) inclusion witnesses at deployment scale, per Appendix B.2; and (iii) **alternative or post-quantum hash primitives**, per Section 10.2 and Section 10.7. Such extensions will be introduced by major or minor releases that change the `version` octet (Section 9) or add an OPTIONAL signature/proof envelope around the existing entry format. A v1 implementation that verifies only the hash chain remains conformant under this specification regardless of what successor versions add.

### 5.2. Full-chain verification

#### 5.2.1. Chain validity predicate

Let `C = (e_0, e_1, ..., e_{n-1})` be an ordered sequence of entries in `Entry`, and let `h ∈ {0,1}^256` be a candidate head hash. The pair `(C, h)` is defined to be **valid** iff all of the following conditions hold:

```text
(V1)   ∀ i ∈ [0, n-1].   e_i.version         = 0x01
(V2)   ∀ i ∈ [0, n-1].   e_i.index           = i
(V3)   ∀ i ∈ [0, n-1].   e_i.payload_type    ∈ { 0x01, 0x02, 0x03 }
(V4)   ∀ i ∈ [0, n-1].   e_i.payload_length  ≤ 2^20
(V5)                     n = 0   ∨   e_0.prev_hash = 0x00 ^ 32
(V6)   ∀ i ∈ [1, n-1].   e_i.prev_hash       = H(serialize(e_{i-1}))
(V7)                     n = 0   ⇒   h = 0x00 ^ 32
(V8)                     n ≥ 1   ⇒   h = H(serialize(e_{n-1}))
```

A conformant verifier MUST accept `(C, h)` if and only if conditions V1 through V8 all hold.

#### 5.2.2. Verification procedure

A full-chain verifier given input `(entries, expected_head)` with `entries = (e_0, ..., e_{n-1})` and `expected_head ∈ {0,1}^256` MUST perform the following procedure, which is a constructive evaluation of the predicate of Section 5.2.1:

```text
verify_chain(entries, expected_head):
  if n = 0:
    if expected_head = 0x00 ^ 32:           return SUCCESS
    else:                                    return Err(HeadHashMismatch)

  running_prev := 0x00 ^ 32
  for i in 0..n-1:
    e := entries[i]
    if e.version         ≠ 0x01:             return Err(UnsupportedVersion)
    if e.index           ≠ i:                return Err(IndexMismatch)
    if e.payload_type    ∉ { 0x01, 0x02, 0x03 }: return Err(UnknownPayloadType)
    if e.payload_length  > 2^20:             return Err(PayloadTooLarge)
    if e.prev_hash       ≠ running_prev:     return Err(PrevHashMismatch)
    running_prev := H(serialize(e))

  if running_prev ≠ expected_head:           return Err(HeadHashMismatch)
  return SUCCESS
```

The procedure runs in O(n) time and O(1) auxiliary space (excluding the transient space required to serialize each entry).

**Theorem 5.2.** For all chains `C` and candidate heads `h`, `verify_chain(C, h)` returns SUCCESS if and only if `(C, h)` is valid per Section 5.2.1.

*Proof sketch.* Conditions V1 through V4 are checked directly on each entry within the loop. V5 is enforced by initializing `running_prev` to `0x00 ^ 32` and checking `e_0.prev_hash = running_prev` on the first iteration. V6 is enforced by updating `running_prev := H(serialize(e))` after each iteration and checking `e_i.prev_hash = running_prev` at the start of iteration `i ≥ 1`; by induction on `i`, `running_prev = H(serialize(e_{i-1}))` at that point. V7 is the `n = 0` branch. V8 is enforced by the final comparison `running_prev = expected_head`, since after the loop terminates `running_prev = H(serialize(e_{n-1}))`. □

### 5.3. Incremental verification

A verifier having previously verified `entries[0..n-1]` against head `head_n` MAY verify an extension `entries[n..n+m-1]` against an expected head `head_n_plus_m` by executing the procedure of Section 5.2 with `running_prev` initialized to `head_n` rather than to 32 octets of `0x00`.

### 5.4. Divergence bisection

Given two sources `A` and `B` each claiming a chain of length `n`, where `A.chain_head_hash != B.chain_head_hash`, the first index at which the two chains disagree MAY be located by binary search:

```text
bisect(A, B, n):
  lo = 0
  hi = n
  while lo < hi:
    mid = (lo + hi) / 2
    if A.entry_hash(mid) == B.entry_hash(mid):
      lo = mid + 1
    else:
      hi = mid
  return lo
```

where `entry_hash(i)` denotes `SHA-256(serialize(entries[i]))`. The procedure runs in O(log n) round-trips to each source.

### 5.5. Scheduled Verification

A conformant deployment runs **Scheduled Verification** at each **Tick**. A Tick is the moment Scheduled Verification is triggered; a conformant deployment MUST trigger at least one Tick per configured cadence (for example, every four wall-clock hours) and MAY trigger additional Ticks in response to operational events such as the close of an administrative session.

Each Scheduled Verification runs two processes against the chains the deployment maintains:

- **Process 1 — Per-user chain cross-replica verification.** For each per-user chain that had activity since the previous Tick, the verifier compares that chain across every replica holding it. The comparison invariant is byte-equal head hashes under the same `entry_count`. A divergence across replicas MUST emit a `DeploymentEvent` with `category = "verification_failure"`. This process also runs against the deployment chain itself, since the deployment chain is quorum-replicated alongside the per-user chains.
- **Process 2 — Deployment chain observer-proxy verification.** The proxy's deployment chain and the observation chain are compared by a monotonic-cursor entry walk over their `ObservedDeploymentEvent`-projectable subsets (see Section 4.12). This process runs only for the deployment chain; per-user chains have no observation counterpart because the observer cannot resolve per-user chain identifiers from the replication stream without schema configuration (table-to-user-id mapping) that it is deliberately not given.

```text
                         ┌────── Tick (scheduled | session-end) ──────┐
                         │                                            │
                         ▼                                            ▼
              ┌──────────────────────┐               ┌─────────────────────────────┐
              │   Process 1          │               │   Process 2                 │
              │                      │               │                             │
              │ For each chain in    │               │ Walk the deployment chain's │
              │ {deployment} ∪       │               │ `ObservedDeploymentEvent`-  │
              │ {active per-user}:   │               │  projectable subset against │
              │   Compare each       │               │ the observation chain, from │
              │   replica's          │               │ each side's last-verified   │
              │   (entry_count,     │               │ cursor forward, advancing    │
              │    head_hash) to the │               │ on byte-match, stopping on  │
              │   baseline replica.  │               │ byte-mismatch.              │
              └──────────┬───────────┘               └──────────────┬──────────────┘
                         │                                          │
                         ▼                                          ▼
                 head mismatch                              entry payload mismatch
                         │                                          │
                         ├──────────────┬───────────────────────────┤
                         ▼                                          ▼
                  ┌──────────────────────────────────────────────────────┐
                  │  Emit DeploymentEvent with category = verification_  │
                  │  failure on the deployment chain; fire the failure   │
                  │  handler chain (lockdown / credential-deny / alert). │
                  └──────────────────────────────────────────────────────┘
```

```text
 │                      │                       │                        │
 │ Verification process │ Invariant checked     │ Chains covered         │
 │                      │                       │                        │
 │ Process 1 — per-user │ byte-equal head_hash  │ deployment chain       │
 │ chain cross-replica  │ under same            │ + every active per-    │
 │                      │ entry_count           │ user chain             │
 │                      │                       │                        │
 │ Process 2 —          │ byte-equal            │ deployment chain only  │
 │ deployment chain     │ canonicalized         │                        │
 │ observer-proxy       │ ObservedDeployment-   │                        │
 │                      │ Event payload per     │                        │
 │                      │ cursor offset         │                        │
 │                      │                       │                        │
```

#### 5.5.1. Process 1: Per-user chain cross-replica verification

The per-user chain cross-replica invariant is byte-equal head hashes under identical entry counts. For each chain `c` in the verification set (`{deployment} ∪ {active per-user chains}`), the verifier SHALL read `(entry_count(c, r), head_hash(c, r))` from every replica `r` holding `c`. Let `(N₀, H₀)` denote the pair from the baseline replica (implementation-defined; typically the lowest-indexed replica). For every other replica `r`:

1. If `entry_count(c, r) = N₀` and `head_hash(c, r) = H₀`, replica `r` is consistent with the baseline for chain `c`.
2. If `entry_count(c, r) ≠ N₀` OR `head_hash(c, r) ≠ H₀`, replica `r` has diverged from the baseline. The verifier MUST emit a `DeploymentEvent` with `category = "verification_failure"` recording `(chain_id, baseline_replica, divergent_replica, baseline_head_hash, divergent_head_hash, baseline_entry_count, divergent_entry_count)` in `details`.

Head-hash comparison is a single-round, constant-cost check. It does NOT require walking entries. If the heads match under the same entry count, chain integrity (Section 5.1 hash construction) guarantees every entry up to the head is byte-identical. If the heads disagree, the implementation MAY invoke the divergence-bisection procedure of Section 5.4 to locate the offending entry.

#### 5.5.2. Process 2: Deployment chain observer-proxy verification

Byte-level *chain* equality between the proxy's deployment chain and the observation chain is NOT REQUIRED — the two chains have independent lineage (`prev_hash` sequences), independent envelope timestamps (Section 4.4), and the proxy's chain carries `DeploymentEvent` entries (deploy, config, schema, system) that the observer cannot see. What IS REQUIRED is byte-level *payload* equality for the `ObservedDeploymentEvent` subset both sides witness.

The two emitters produce `ObservedDeploymentEvent` payloads (Section 4.12) that are byte-identical for the same operation, because the payload carries only fields both sides can derive from their independent views and no wall-clock timestamp. Canonicalization per Section 4.9 applied to identical field values produces identical bytes.

Two monotonic cursors govern the comparison:

- `cursor_prx`, initially 0, advances past proxy-chain entries already verified.
- `cursor_obs`, initially 0, advances past observation-chain entries already verified.

Cursors MAY be held in volatile storage. Implementations that hold cursors in volatile storage MUST resume from `cursor_prx = 0` and `cursor_obs = 0` after a process restart, and will emit one `verification_failure` `DeploymentEvent` per Tick for each unredressed divergence until the divergent entry is resolved; this repetition is expected and non-normative. Implementations that persist cursors across restarts MUST emit at least one `verification_failure` per divergence and MAY deduplicate subsequent emissions.

Each Tick executes the following procedure in Process 2:

1. Let `proxy_new` be the sequence of `ObservedDeploymentEvent`-projectable entries on the proxy's deployment chain with indices in `[cursor_prx .. proxy_head)`, in chain order. Non-projectable entries (entries for which `project_to_observed` returns the empty projection — for example, `DeploymentEvent` entries in `deploy`, `config`, `system`, `retention`, or `egress` categories) are skipped without consuming an observation-chain counterpart and `cursor_prx` advances past them in the same pass.
2. Let `observer_new` be the sequence of `ObservedDeploymentEvent` entries on the observation chain with indices in `[cursor_obs .. observer_head)`, in chain order.
3. Let `n := min(|proxy_new|, |observer_new|)`. For `i` in `0..n`, compare `canonicalize(proxy_new[i].payload)` byte-for-byte against `canonicalize(observer_new[i].payload)`.
4. If all `n` comparisons match, advance `cursor_prx` past the `n` matched entries (plus any interleaved non-projectable proxy entries consumed in step 1) and advance `cursor_obs` by `n`. The matched entries are verified.
5. If any comparison fails at index `i`, the Tick is rejected: the implementation MUST emit a `DeploymentEvent` with `category = "verification_failure"` on the deployment chain, carrying both payloads in `details.proxy_payload` and `details.observed_payload` and the cursor indices in `details.cursor_prx` and `details.cursor_obs`, so downstream readers can reconstruct the disagreement without re-fetching either chain. The cursors are NOT advanced on rejection; the next Tick will re-observe the same mismatch unless the divergent entry has been redressed.

The un-compared **tail** — entries `[n .. |proxy_new|)` on the longer side, or `[n .. |observer_new|)` when the observer is ahead — stays unverified until the slower side has committed its counterpart. This is by construction, not a separate retry mechanism: the verifier only verifies the prefix both chains have already witnessed. A tail that persists across many consecutive Ticks is itself a signal — either one side is stuck consuming replication, or the proxy has written entries whose counterparts the database primitive never produced. Deployments SHOULD surface tail depth as an operator-visible metric (recommended: a `DeploymentEvent` with `category = "system"` and `details.kind = "verification_tail"` summarising the unverified count) so operators see persistent tails without relying on a hard-coded time budget.

Envelope timestamps on the two chains (Section 4.4) are written independently by the proxy and the observer and are expected to differ arbitrarily: the proxy stamps its envelope when it forwards the operation; the observer stamps its envelope when it receives the corresponding event on the replication stream. Replication latency and per-primitive notification delivery timing introduce legitimate drift. The protocol MUST NOT treat envelope-timestamp skew as a failure signal, and a verifier MUST NOT reject a payload match because the two envelope timestamps differ. The hashed payload bytes (Section 4.12) deliberately do not include a timestamp so that legitimate drift cannot break byte-level payload equality.

**Why byte-level payload equality, not head equality, in Process 2.** Chain-head byte equality between observer and proxy is not achievable: the two chains have independent lineage (different `prev_hash` sequences, different envelope timestamps, different entry sets because the proxy chain carries `DeploymentEvent` entries — deploy, config, schema, system — that the observer cannot see). What IS achievable is per-payload byte equality over the `ObservedDeploymentEvent` subset: both sides emit the same field values for the same operation, and JCS canonicalization produces identical bytes. Process 1 is able to use head hashes because it compares replicas of the *same* chain; Process 2 cannot, because the proxy chain and observation chain are different chains by construction.

---

## 6. Authentication

### 6.1. JWT format

All authenticated endpoints require a JWT conforming to [RFC7519], signed with HS256 [RFC7518] using a per-deployment shared secret. The JWT MUST carry the following claims:

```json
{
  "iss": "<deployment identifier>",
  "sub": "<string>",
  "aud": "chain-api-user" | "chain-api-admin",
  "exp": 0,
  "jti": "<string>"
}
```

The `jti` claim is REQUIRED. See Section 10.5 for the replay-prevention procedure a conformant server MUST implement.

The `nbf` (not-before time) claim is OPTIONAL. A conformant server that receives a token carrying `nbf` MUST reject the token until the current time is at or after `nbf`.

This version does not use `iat`. The `jti` + `exp` pair, combined with the replay deny-list in Section 10.5, already carries the single-use and freshness contract on the wire, and the issuer-side `exp` cap (below) is enforceable at issue time without `iat`. A conformant v1 server MUST NOT require `iat` to be present on incoming tokens, and MUST ignore the value if it is present. Future minor versions MAY re-introduce `iat` for clock-skew diagnostics; such a re-introduction will be additive (SHOULD, not MUST) so that v1 issuers that omit the claim remain conformant.

Issuers SHOULD set `exp` no more than 3600 seconds (one hour) beyond the moment of issue. This upper bound, together with the replay deny-list procedure of Section 10.5, keeps each accepted token single-use within a bounded freshness window.

### 6.2. Audiences

Two audiences are defined in this version:

- **`chain-api-user`**: the `sub` claim is the user identifier whose chain the holder is authorized to read. The server MUST apply the subject binding procedure of Section 6.3 before authorizing the request.
- **`chain-api-admin`**: the `sub` claim is an operator identifier. The holder is authorized to read the deployment chain and any per-user chain.

Operational APIs unrelated to chain transparency — for example, usage metering for billing — are implementation-defined and out of scope for this specification. Deployments that need such APIs obtain usage data from their hosting provider's own metering surface (e.g., Cloud Monitoring, billing export) rather than from the proxy.

### 6.3. Subject binding for user endpoints

For an incoming request to an endpoint under `/api/v1/chain/u/{url_user_id}/...` presenting a JWT `J` such that `J.aud = "chain-api-user"`, the server MUST accept the request iff `J.sub = url_user_id`. The comparison is performed on the raw string values as defined in [RFC7519] Section 4.1.2; neither side is hashed or otherwise transformed prior to comparison. If `J.sub ≠ url_user_id`, the server MUST respond 403 Forbidden.

The chain identifier used for storage lookup (Section 3.2) is derived server-side as `HMAC-SHA-256(deployment_salt, url_user_id)` and is not exposed to the JWT issuer. This preserves the privacy property of Section 10.3: `deployment_salt` remains operator-private, and an attacker who compromises the JWT issuer cannot enumerate chain identifiers.

The procedure prevents a principal holding a valid JWT for one user from reading the chain of a different user by swapping the URL path segment.

### 6.4. Sidecar metadata

A deployment MAY persist additional proxy-side metadata associated with any `ObservedDeploymentEvent` entry (Section 4.12) that is served by the chain API alongside the entry but is NOT included in the hashed payload bytes. Sidecar metadata exists to carry operational fields — source IP, session identifier, correlation identifier, query shape — that the proxy observes but the replication-stream observer cannot, without violating the byte-level payload agreement of Section 5.5.

Sidecar metadata files are keyed by `(chain_id, entry_index)`. The storage format is implementation-defined; the reference implementation writes one JSON file per entry in a `sidecar/` directory parallel to the chain storage.

The chain API (Section 7) MAY include sidecar metadata in the response for an entry read. When included, it MUST be returned under a distinct top-level key (e.g., `"sidecar"`) so clients can cleanly separate hashed payload from non-hashed metadata. A client verifying the chain MUST NOT include sidecar contents in any hash computation — the predicate of Section 5.2.1 is evaluated only over the entry's serialized payload bytes.

Tampering with sidecar metadata does not invalidate the chain under Section 5.2.1 and will not be detected by full-chain verification. Operators who require integrity over sidecar contents MAY sign each sidecar record with a per-entry key derived from the entry hash (future work). This version of the specification defines sidecar as advisory, not normative; the security model does not depend on sidecar integrity.

---

## 7. HTTP API

A conformant chain API serves HTTP requests over TLS. Endpoints specified in this section MUST be exposed on a single base path and port. The reference implementation referenced in Appendix C uses port 9091; this is not normative.

All endpoints require authentication as specified in Section 6 via a JWT supplied in the `Authorization` header with the `Bearer` scheme.

### 7.1. Per-user chain endpoints

#### 7.1.1. GET /api/v1/chain/u/{user_id}/entries

Returns a paginated list of entries in the per-user chain identified by `HMAC-SHA-256(deployment_salt, user_id)` per Section 3.2.

Path parameter:

- `user_id`: the raw user identifier. The server hashes this value internally before chain lookup.

Query parameters:

- `cursor` (OPTIONAL, integer, default 0): the `index` value from which to begin returning entries.
- `limit` (OPTIONAL, integer, default 100, maximum 500): the maximum number of entries to return. Servers MUST reject values outside `[1, 500]` with `400 Bad Request`.

Response body (200 OK):

```json
{
  "chain_id":      "<hex>",
  "entries":       [
    {
      "version":        1,
      "index":          0,
      "timestamp":      0,
      "prev_hash":      "<hex>",
      "payload_type":   1,
      "payload":        { }
    }
  ],
  "next_cursor":   0,
  "head_hash":     "<hex>",
  "total_entries": 0
}
```

Entries in the response are returned with the payload deserialized as JSON for convenience. A verifier computing hashes MUST re-serialize entries per Section 4.1 and Section 4.9 before applying the algorithms in Section 5.

Response code 404 is returned if no chain exists for the given `user_id`.

#### 7.1.2. GET /api/v1/chain/u/{user_id}/head

Returns the current head hash of a per-user chain without returning the entries themselves.

Response body (200 OK):

```json
{
  "chain_id":        "<hex>",
  "head_hash":       "<hex>",
  "total_entries":   0,
  "last_updated_at": 0
}
```

### 7.2. Deployment chain endpoints

#### 7.2.1. GET /api/v1/chain/deployment/entries

Returns a paginated list of entries in the deployment chain. Pagination parameters follow Section 7.1.1. This endpoint requires a JWT with `aud = "chain-api-admin"` (Section 6.2).

#### 7.2.2. GET /api/v1/chain/deployment/summary

Returns a summary of the deployment chain.

Response body (200 OK):

```json
{
  "head_hash":     "<hex>",
  "total_entries": 0,
  "category_counts": {
    "admin_access":           0,
    "admin_lifecycle":        0,
    "config":                 0,
    "deploy":                 0,
    "schema":                 0,
    "system":                 0,
    "approved_access":        0,
    "egress":                 0,
    "user_erasure_requested": 0,
    "retention_sweep":        0,
    "verification_failure":   0,
    "nightly_verification":   0,
    "replica_reshuffle":      0
  }
}
```

`category_counts` MUST enumerate every category defined in Section 4.11; a conformant server returns zero for categories that have not yet appeared on the deployment chain rather than omitting the key. The set of keys and the set of `category` variants in Section 4.11 are normatively identical.

### 7.3. Erasure endpoint

#### 7.3.1. DELETE /api/v1/chain/u/{user_id}

Deletes a per-user chain in response to a user-initiated erasure request. The deletion MUST be recorded as a tombstone on the deployment chain, as specified in Section 8.1.

Authentication: the JWT MUST have `aud = "chain-api-user"` and MUST satisfy the subject binding procedure of Section 6.3. Erasure in this version of the specification is user-initiated only; an operator-initiated erasure path is deferred to a successor version that defines the required role-claim model.

Processing is synchronous: the server MUST commit the Section 8.1 tombstone to the deployment chain before deleting any data, and MUST NOT delete the per-user chain until the tombstone has durably committed. If the tombstone write fails, the server MUST return `503 Service Unavailable` and MUST NOT delete the per-user chain. The response body carries the real identity of the committed tombstone and is returned only after both the tombstone and the physical chain delete (local store and any durable replicas, per Section 8.1) have succeeded. If the physical delete fails after the tombstone has committed, the server MUST return `503 Service Unavailable` with a body naming the committed tombstone's identity so the deployment operator can complete the durable-tier cleanup without re-issuing the tombstone.

Response body (200 OK):

```json
{
  "tombstone_entry_id":        "<hex-encoded SHA-256, 64 characters>",
  "tombstone_deployment_chain_index": 0
}
```

Fields:

- `tombstone_entry_id` is the hex-encoded `entry_hash` of the tombstone `DeploymentEvent` on the deployment chain (Section 5.1). Together with `tombstone_deployment_chain_index`, it uniquely identifies the audit record.
- `tombstone_deployment_chain_index` is the zero-based index of the tombstone on the deployment chain.

After this response, subsequent GET requests on the same `user_id` MUST return 404.

---

## 8. Deletion and retention

### 8.1. User-initiated erasure

A user-initiated erasure is processed by the server as follows:

1. The server MUST append a tombstone `DeploymentEvent` to the deployment chain, populating the `user_erasure_requested` category fields as specified in Section 4.11.1.

2. The server MUST delete the entire per-user chain, including all replicas. Deployments that additionally maintain sidecar metadata (Section 6.4) for per-user chain entries MUST also delete those sidecar records. Deployments that do not maintain sidecar data for per-user chains satisfy the sidecar clause vacuously. This step MUST occur only AFTER step 1 has durably committed — see Section 7.3.1 for the ordering rationale.

3. The server MUST return the `tombstone_entry_id` and the `tombstone_deployment_chain_index` as a receipt, per Section 7.3.1.

Subsequent reads of the deleted chain MUST return 404. Deployment-chain entries that identify the user at table level (`category = "admin_access"`, Section 4.11) persist; these entries do not contain per-user data and are treated as controller-level processing records.

### 8.2. Retention sweeps

An implementation MAY run a scheduled retention process that deletes entries older than a configurable retention period. The retention process operates at per-chain granularity: a chain is selected for deletion when its oldest entry exceeds the retention threshold, and the chain is removed as a unit.

The retention threshold is a deployment-level configuration value expressed in whole days. The reference implementation (Appendix C) defaults to 365 days and permits per-deployment override via the `retention_days` configuration key. Operators SHOULD choose a value that balances regulatory storage-limitation obligations (e.g., [GDPR] Article 5(1)(e)) against operational needs for historical access visibility. Typical values observed in audit-log deployments range from 90 days (privacy-minimizing) through 7 years (financial-reporting retention); deployments subject to industry-specific controls (e.g., [HIPAA] §164.316(b)(2)(i) — 6 years; U.S. financial reporting — 7 years) SHOULD select a threshold that meets or exceeds the longest applicable requirement.

For each chain removed, the retention process MUST append a tombstone `DeploymentEvent` to the deployment chain, populating the `retention_sweep` category fields as specified in Section 4.11.2.

The deployment chain itself is NOT subject to retention in v1. Retention sweeps operate on per-user chains only; the `retention_sweep` tombstones they produce accumulate on the deployment chain and are not reaped. A successor version MAY introduce a deployment-chain retention policy, possibly in conjunction with the per-batch aggregate category discussed in the note below.

**Note.** The per-chain model chosen here records one tombstone per deleted chain. This matches how auditors reason about erasure — the interesting question is usually "was my chain deleted, and when," not "how big was the batch." A future minor release MAY introduce a complementary per-batch aggregate category (for example, `"retention_sweep_batch"`) that records window-level totals when per-chain volume becomes too high to browse; v1 does not define one.

### 8.3. Effect on verification

This version supports only full-chain deletion via the procedures of Section 8.1 and Section 8.2. A verifier that retrieves a chain applies the procedure of Section 5.2.2 directly. A chain that has been deleted responds to the GET endpoints of Section 7.1 with 404; no verification is performed against a deleted chain.

A future version of this specification MAY introduce fine-grained per-entry retention sweeps. In such a future version, a chain whose first entry has `index > 0` would be a valid chain whose verification uses an operator-issued head hash associated with the first available index as the initial `running_prev`. Conformant v1 implementations MUST treat partially-reaped chains as corrupt.

---

## 9. Versioning

This document specifies version 1.0.0 of Data Access Transparency. Future documents will follow semantic versioning:

- **Patch releases (1.0.x)** introduce clarifying language and informative updates. They MUST NOT introduce byte-level changes to any data structure or wire format defined in this document.
- **Minor releases (1.x.0)** MAY introduce backwards-compatible additions such as new optional payload members or new `category` values. Entries produced under a minor release MUST remain readable by verifiers conforming to an earlier minor release of the same major version.
- **Major releases (x.0.0)** MAY introduce backwards-incompatible changes. A major release MUST change the `version` octet (Section 4.2) so that entries produced under different major versions coexist unambiguously in a chain.

---

## 10. Security considerations

### 10.1. Threat model

The protocol specified in this document is designed to defeat the following classes of attack:

1. **Log tampering by the operator.** An operator attempting to rewrite, suppress, or fabricate entries after publication. The hash-chain structure (Section 5.1) and synchronous publication of chain heads ensure any such modification produces a chain that fails full-chain verification (Section 5.2).
2. **Historical rewriting.** An operator attempting to modify an entry at index N. Because every entry at index greater than N commits to the tampered entry via `prev_hash` (Section 4.5), such modification requires recomputing every subsequent entry AND publishing a new chain head that contradicts the previously-published head. Any previously-recorded head hash is evidence of the tampering.
3. **Proxy bypass by a privileged application-layer principal.** A principal with database credentials attempting to access data without the access being logged. Where the transparency proxy is the only network path to the database (Section 3.1), such access is not possible without modifying the deployment's network topology. Where a replication-stream observer is present (Section 3.3), a discrepancy between the proxy's chain and the observer's chain produces a `verification_failure` entry on the deployment chain.

The protocol specified in this document does NOT defeat the following classes of attack in this version:

1. **Simultaneous compromise of proxy and observer.** A single-observer deployment is defeated if the same adversary controls both the proxy and the observer. See Section 10.6.
2. **Forgery of accesses that produce no replication event.** A read-only query that produces no replication artifact is not directly cross-checked by the v1 observer.
3. **Cryptographic break of SHA-256 or HS256.** See Section 10.2 and Section 10.7.

The following are not threats this protocol addresses:

1. **Authorized access.** This protocol records accesses by principals holding valid credentials issued by the operator. It does not revoke or prevent such accesses.
2. **Semantic correctness of accesses.** This protocol records the fact and scope of an access. It does not evaluate whether the access was appropriate under any policy.

### 10.2. Hash primitive

This document specifies SHA-256 [FIPS180-4] as the sole hash primitive. At 128-bit classical collision resistance, SHA-256 is adequate for the per-user chain sizes anticipated in v1 (Appendix B.2); it is not, however, the strongest available choice for deployments with multi-decade retention horizons.

If SHA-256 is shown to be insecure, chains hashed under this document retain their v1 integrity properties under the assumptions existing at the time the entries were produced; a successor document using an alternative primitive will be required for new chains.

Candidate successor primitives considered for a future major version of this specification:

1. **SHA-384 [FIPS180-4].** A truncated SHA-512 output recommended by NIST for high-assurance settings (CNSA Suite). Offers ~192-bit classical collision resistance (~128-bit against a quantum collision search per Brassard–Høyer–Tapp), making it the most natural successor for deployments with long retention horizons. Entry envelope overhead increases by 16 octets (48-octet `prev_hash` instead of 32). Implementation risk is low because every SHA-512 implementation in practice also provides SHA-384.
2. **SHA-512 [FIPS180-4].** 256-bit classical collision resistance. On 64-bit platforms typically outperforms SHA-256 because it operates on 64-bit words natively. Envelope overhead is 32 octets per entry.
3. **SHA-3 / Keccak-256 [FIPS202].** A structurally distinct (sponge-based) hash, useful as a diversification hedge against unforeseen structural weaknesses in the SHA-2 family. Recommended only if a Merkle–Damgård-class weakness becomes material.
4. **BLAKE3.** Substantially faster than SHA-2 family on modern hardware and natively tree-structured. Attractive in combination with a Merkle-tree construction for the deployment chain (Appendix B.2). Note that BLAKE3 is not currently a FIPS primitive; selection would trade throughput against certification availability.

The primitive choice for a successor version is out of scope for this document. SHA-384 is, however, identified here as the leading candidate absent a specific reason to prefer an alternative.

### 10.3. HMAC salt disclosure

The per-deployment HMAC salt used to derive user identifiers (`HMAC-SHA-256(deployment_salt, user_id)` per Section 3.2) MUST be generated from a cryptographically secure random source and MUST be stored with access restricted to the proxy process. Disclosure of the salt permits an attacker to correlate chain identifiers with their plaintext user identifiers.

### 10.4. JWT signing key disclosure

The JWT signing key for a deployment MUST be generated from a cryptographically secure random source and MUST be stored with access restricted to the proxy process. Disclosure of the key permits an attacker to forge JWTs accepted by the proxy.

### 10.5. Token replay

A conformant server MUST reject any JWT whose `jti` claim it has already accepted within the `exp` window of a previously-accepted token. The server MAY implement this with an in-memory deny-list whose capacity is at least the expected number of distinct `jti` values the server sees in the longest permitted `exp` window (Section 6.1 caps this at one hour); entries MUST be retained at least until the associated token's `exp` has elapsed. Tokens lacking a `jti` claim MUST be rejected.

In deployments running more than one proxy replica behind a load balancer, replay prevention is local to each replica unless the deployment provides shared state across replicas (e.g., a Redis- or NATS-backed deny-list). Single-replica deployments — the common case for v1 — are fully covered by a per-process in-memory deny-list.

### 10.6. Observer compromise

This version's single-observer cross-check (Section 3.3) does not defeat an attacker who simultaneously compromises both the proxy and the observer. A multi-observer quorum with threshold signatures on chain heads is planned for a successor version of this specification.

### 10.7. Post-quantum security

This document specifies primitives (SHA-256, HMAC-SHA-256, HS256 JWTs) that are not post-quantum-secure. A post-quantum successor is out of scope for this document.

---

## 11. IANA considerations

This document has no IANA actions.

In the event of a successor version seeking IETF standards-track publication, registration of the following would be considered: a media type for serialized chain entries; a URI scheme or URN namespace for chain identifiers defined by this specification; a JWT "aud" value registry entry for the audience values defined in Section 6.2.

---

## 12. References

### 12.1. Normative references

**[RFC2104]** Krawczyk, H., Bellare, M., and R. Canetti, "HMAC: Keyed-Hashing for Message Authentication", RFC 2104, DOI 10.17487/RFC2104, February 1997.

**[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997.

**[RFC4122]** Leach, P., Mealling, M., and R. Salz, "A Universally Unique IDentifier (UUID) URN Namespace", RFC 4122, DOI 10.17487/RFC4122, July 2005.

**[RFC7518]** Jones, M., "JSON Web Algorithms (JWA)", RFC 7518, DOI 10.17487/RFC7518, May 2015.

**[RFC7519]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, DOI 10.17487/RFC7519, May 2015.

**[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017.

**[RFC8785]** Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, DOI 10.17487/RFC8785, June 2020.

**[FIPS180-4]** National Institute of Standards and Technology, "Secure Hash Standard", FIPS 180-4, August 2015.

### 12.2. Informative references

**[RFC6962]** Laurie, B., Langley, A., and E. Kasper, "Certificate Transparency", RFC 6962, DOI 10.17487/RFC6962, June 2013.

**[RFC8555]** Barnes, R., Hoffman-Andrews, J., McCarney, D., and J. Kasten, "Automatic Certificate Management Environment (ACME)", RFC 8555, DOI 10.17487/RFC8555, March 2019.

**[GDPR]** Regulation (EU) 2016/679 of the European Parliament and of the Council, "General Data Protection Regulation", April 2016.

**[AIACT]** Regulation (EU) 2024/1689 of the European Parliament and of the Council, "Artificial Intelligence Act", 2024.

**[HIPAA]** U.S. Department of Health and Human Services, "HIPAA Security Rule", 45 CFR Part 164, Subpart C.

**[SIGSTORE]** Newman, Z., Meyers, J., and S. Torres-Arias, "Sigstore: Software Signing for Everybody", 2022.

**[FIPS202]** National Institute of Standards and Technology, "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions", FIPS 202, August 2015.

---

## 13. Acknowledgements

This specification was developed alongside an open-source reference implementation released under AGPLv3 (writer) and Apache 2.0 (verifier). Structural feedback from reviewers encountering draft versions has shaped the organization of this document and is gratefully acknowledged.

---

## Author's address

Tiger Wang (Yun Wang)
San Francisco, CA, United States of America
Email: <yunwangt@gmail.com>

---

## Appendix A. Compliance mapping (informative)
This appendix relates elements of this specification to specific regulatory controls that implementers may need to satisfy. Conformance with this specification does not constitute legal compliance; legal evaluation is the responsibility of the deployment operator and its auditors.

### A.1. SOC 2 Common Criteria

| Control | Reference |
|---|---|
| CC6.1 (logical access) | `AccessEvent` entries (Section 4.10) record the authenticated actor for each access. |
| CC6.6 (access revocation) | `DeploymentEvent` entries with `category = "admin_lifecycle"` record revocation events. |
| CC7.2 (monitoring) | `DeploymentEvent` entries with `category = "nightly_verification"` record scheduled cross-replica checks. |
| CC7.3 (incident response) | `DeploymentEvent` entries with `category = "verification_failure"` record detected tampering. |

### A.2. GDPR [GDPR]

| Article | Reference |
|---|---|
| Article 5(1)(e), storage limitation | Retention sweeps and tombstones (Section 8.2). |
| Article 17, right to erasure | User-initiated erasure (Section 7.3.1 and Section 8.1). |
| Article 30, records of processing | Deployment chain entries (Section 4.11). |
| Article 32, security of processing | The chain structure (Section 5) is an appropriate technical measure. |

### A.3. HIPAA [HIPAA]

| Subsection | Reference |
|---|---|
| §164.312(b), audit controls | `AccessEvent` entries (Section 4.10). |
| §164.312(c)(1), integrity | Hash-chain construction (Section 5.1). |

### A.4. EU AI Act [AIACT] Article 12

`AccessEvent` entries with `actor_type = "agent"` and a non-empty `actor_label` satisfy the record-keeping requirement of Article 12(1) for database accesses made by an AI agent deployed behind a conformant proxy.

---

## Appendix B. Related work (informative)

This appendix elaborates the relationships summarized in Section 1.3.

### B.1. Byte-level reuse

A conformant implementation of this specification makes direct byte-level use of the following existing standards:

- **[RFC8785] JSON Canonicalization Scheme (JCS).** Section 4.9 defines payload canonicalization as a profile of JCS, with a documented deviation on member-name sort order.
- **[FIPS180-4] SHA-256.** Section 5.1 defines chain hashing in terms of SHA-256 as specified in FIPS 180-4.
- **[RFC7519] JSON Web Token (JWT).** Section 6 defines HTTP API authentication in terms of RFC 7519 JWTs signed with HS256 [RFC7518].

### B.2. Architectural pattern

The pattern of an append-only cryptographic log publicly verifiable by the affected party was established in Certificate Transparency [RFC6962] and is used in Sigstore [SIGSTORE]. This document applies the pattern to database access events. Two differences from [RFC6962] are noted:

1. The log data structure specified here is a hash chain, not a Merkle tree. Per-user chains are expected to be bounded in size and are expected to retain a hash-chain structure in successor versions; the Merkle proof machinery defined in [RFC6962] Section 2 is not required at that scale. A successor version of this specification MAY introduce a Merkle tree structure for the deployment chain specifically, whose growth is unbounded in the number of administrative events, in order to admit O(log n) inclusion proofs and external publication of deployment-chain heads to a public transparency log.

    Per-user chains are bounded in practice by the number of accesses against a single user's data over the product lifetime, which in typical deployments is on the order of dozens to low thousands of entries — the number of times a single user's profile is read, updated, exported, or deleted by application traffic and administrative actions. [RFC6962] targets a setting in which a single log must prove inclusion of one specific certificate among the full set of certificates ever issued by any certificate authority, a set whose cardinality is many orders of magnitude larger. The O(log n) inclusion-proof machinery of a Merkle tree is load-bearing at [RFC6962] scale and unnecessary at per-user-chain scale: O(n) full-chain verification of a hash chain of 10^3 entries on end-user hardware completes in milliseconds, while the additional implementation and specification cost of a Merkle tree — proof construction, proof serialization, tree reconstruction on verifier restart, consistency proofs across heads — would burden every conformant implementation without benefit at this scale. The deployment chain is the natural place for a Merkle tree in a successor version, because its growth is unbounded in the total number of administrative events across a deployment rather than per-user.
2. The verifying party is the end user affected by an access event, rather than a domain owner ([RFC6962]) or a software consumer (Sigstore). Verifier code is designed to run on the affected user's device; this document does not define a monitor role analogous to the role described in [RFC6962] Section 8.3.

### B.3. Protocol-as-trust-anchor principle

The principle that the specification, rather than any operator, serves as the arbiter of correctness is adopted from ACME [RFC8555]. No wire format, data structure, or procedure from [RFC8555] is reused; only the principle. Publication of this document under CC0 is intended to permit arbitrary independent implementation.

### B.4. Composition

The composition of a wire-protocol-transparent proxy that produces a per-user hash chain of every access, publishes chain heads synchronously, exposes them through a JWT-gated HTTP API, and is verified by the affected user in a browser, with an independent replication-stream observer performing cross-verification, is not known to appear as a published specification prior to this document.

---

## Appendix C. Reference implementations (informative)

As of this draft, the known reference implementations are:

- `chain-engine` — reference writer in Rust. Source: `server/crates/chain-engine/` in the reference-implementation repository. AGPLv3.
- `chain-store` — shared chain-storage library in Rust, consumed by the proxy. Source: `server/crates/chain-store/`. AGPLv3.
- `chain-verifier-wasm` — reference browser verifier, Rust compiled to WebAssembly. Source: `server/crates/chain-verifier-wasm/`. Apache 2.0.

### C.1. Conformance test vectors

A conformant v1 implementation MUST produce byte-identical chain entries and byte-identical head hashes as any other conformant v1 implementation, for the same inputs. Proving conformance in practice requires a shared set of **test vectors**: fixtures that pair a canonical input with its expected byte-level output.

A test vector is a self-contained record of the form:

```text
{
  "input":                   <entries as defined in Section 4>,
  "expected_serialized_hex": <octets produced by serialize(entries) per §4.1 and §4.9>,
  "expected_head_hex":       <SHA-256 of the last serialized entry per §5.1>
}
```

An implementer in any language reads the input, runs its own serialize + hash pipeline, and compares against the `expected_serialized_hex` and `expected_head_hex` fields. All vectors passing means the implementation is v1-conformant.

A minimum viable conformance set MUST cover at least the following normative requirements:

- Empty chain — head hash equals 32 octets of `0x00` per §5.1.
- Single-entry chain with each defined payload type (`AccessEvent` per §4.10, `DeploymentEvent` per §4.11, `ObservedDeploymentEvent` per §4.12).
- Multi-entry chain linked via `prev_hash` per §4.5; intermediate and final head hashes documented for incremental verification per §5.3.
- Canonicalization edge cases per §4.9 rules 1, 3, and 5: deliberately-unsorted member names; Unicode **string values** requiring NFC normalization (inputs use NFD; expected output uses NFC); Unicode **object member names** requiring NFC normalization (one companion vector in this set MUST use an NFD-encoded member name and yield the same `expected_head_hex` as the NFC-encoded input, exercising the member-name half of §4.9 rule 3 independently of the string-value half); payloads containing `null` at any depth (verifier MUST reject; at minimum one vector with a top-level `null` and one with a nested `null` inside `details` or `scope`).
- `AccessEvent.affected_user_ids` array-ordering rule per §4.10: two vectors whose inputs differ only in the order `affected_users` is supplied to the producer MUST yield identical `expected_serialized_hex` and identical `expected_head_hex`. A companion negative vector MUST exercise a producer that emits an unsorted or duplicate-bearing `affected_user_ids` array and document that a verifier rejects it as malformed.
- Cross-chain genesis head parity — a per-user chain at `n = 0` and the deployment chain at `n = 0` both produce the 32-octet `0x00` head per §5.1, proving the empty-chain convention holds uniformly across chain types (distinct from the single empty-chain case above because it forces implementations to exercise both `chain_id_user` and `chain_id_org` code paths on a genesis chain, catching any divergence in chain-type handling at initialization).
- Wire-format negative cases — verifiers MUST reject entries with `version ≠ 0x01` (§4.2), gaps in `index` (§4.3), `payload_length` > 2^20 (§4.7), or `payload_type` outside `{0x01, 0x02, 0x03}` (§4.6).
- Retention / prefix-reap scenario — chain whose first entry has `index > 0` with an operator-issued initial `running_prev` per §8.3.

**Runtime conformance (non-hash) vectors.** The appendix above focuses on byte-level hash fixtures. A complete conformance surface additionally exercises the §6 / §7 runtime contracts, which are not expressible as `(input, expected_hex)` tuples but are nonetheless normative. A minimum viable runtime set MUST cover:

- **JWT single-use within exp window** per §10.5: a replayed `jti` inside its `exp` window is rejected with HTTP 401, regardless of signature validity (§6.1).
- **Subject binding** per §6.3: a request to `/api/v1/chain/u/{url_user_id}/...` whose token's `sub` claim does not equal `url_user_id` returns HTTP 403 without any chain lookup.
- **Audience separation** per §6.2: a `chain-api-user` token cannot reach `/api/v1/chain/deployment/*` endpoints (returns HTTP 403), and a `chain-api-admin` token cannot reach `/api/v1/chain/u/{user_id}/*` user-scoped endpoints.
- **Erasure ordering** per §7.3.1 + §8.1: the `user_erasure_requested` tombstone MUST commit to the deployment chain before any per-user chain data is deleted; a tombstone-write failure MUST NOT delete per-user data (503 with disk untouched).

The reference-implementation repository intends to publish a conformance vector set at `server/crates/chain-engine/testdata/dat-v1-vectors/`. At the time of this draft, that directory is not yet populated. Until vectors are published, third-party implementations can validate against a running reference proxy, with the understanding that such validation is not a substitute for a committed fixture set. See the reference implementation's `server/SPEC-DELTA.md` for the commit plan.

No third-party implementations are known to the author at the time of this draft.

---

## Appendix D. Other applications of the chain format (informative)

This appendix is non-normative. It describes applications that reuse the chain format outside the server-side scope of this specification. Readers evaluating conformance with v1 of this specification can safely skip this appendix.

This specification defines a server-side data-access transparency protocol. The entry format (Section 4.1), payload canonicalization (Section 4.9), hash algorithm (Section 5.1), and validity predicate (Section 5.2.1) are defined in this specification with no dependency on where the chain is constructed. An application unrelated to a hosted database deployment MAY reuse those elements to produce a chain of its own events, and MAY use the reference browser verifier (Appendix C) to verify such a chain.

Applications that reuse the chain format in this manner are referred to in this document as **adopters**. An adopter is not a conformant implementation of v1: the wire semantics specified in this document — proxy placement (Section 3.1), HTTP API (Section 7), JWT authentication (Section 6), publication timing, and the replication-stream observer (Section 3.3) — do not necessarily apply in a non-server environment. An adopter conforms to those portions of the specification that it chooses to implement and documents its scope separately.

As of this draft, one adopter is known to the author:

- **Otis.** A macOS application that embeds an AI agent runtime. Otis records the runtime's own LLM API calls, actions taken against the host operating system, and context transmitted to the LLM as `AccessEvent` entries in a local per-user chain, using the format of this specification. Otis shares the entry format of Section 4.1 and the canonicalization of Section 4.9 with a conformant server. Otis does not implement Sections 3, 6, or 7 of this specification; it is not a conformant server.

Future versions of this specification, or a sibling specification, may formalize client-side usage of the chain format. Version 1 does not.

---

## Appendix E. Evaluating this specification (informative)

This appendix is non-normative. It is written for a reviewer — a regulator, a standards reader, an investor, a would-be implementer — trying to decide in a bounded amount of time whether v1 of this specification is something real. The intent is to make that judgment easy to reach without reading the whole document in order.

The argument the specification has to carry is simple: a data subject can walk the chain of accesses to their own data, on their own device, and detect silent tampering by the operator. Everything else — the binary envelope, the JCS rules, the JWT scheme, the GDPR-aware retention model — is apparatus supporting that one claim. If the reviewer comes away unconvinced that the claim holds, the specification has failed regardless of how precise its appendices look. If the claim holds, the rest is engineering.

A 90-minute read-through that exercises the claim end-to-end runs as follows:

1. **Sections 1 through 3 (Introduction, Terminology, Protocol overview) — approximately 15 minutes.** These establish scope, vocabulary, and the deployment shape. The reviewer should come away able to name the three parties (operator, data subject, observer) and state who holds the ability to verify a chain.
2. **Sections 4 and 5 (Chain entry format, Hash algorithm and verification) — approximately 20 minutes.** This is the cryptographic core. Section 5.2.1 states the chain validity predicate formally; Section 5.2.2 gives the verification procedure; Theorem 5.2 states the correspondence. A reviewer unwilling to read eight indented lines of pseudocode should stop here and assign someone who will.
3. **Hands-on check (the load-bearing step) — approximately 30 minutes.** Clone the reference implementation named in Appendix C. Run the chain engine against a trivial example. Then write roughly 50 lines in any language with SHA-256 and JSON support — Python and Go reference implementations are inlined in the server's `docs/chain-api.md` — to re-verify that chain independently. If the two agree, the specification does what it says. If they disagree, the specification is the arbiter per Section 1.3, and either the reviewer's code or the reference implementation has a bug to find.
4. **Appendix A (Compliance mapping) — approximately 10 minutes.** Verify that each regulatory control cited resolves to a concrete section of this specification rather than to aspirational text.
5. **Section 10 (Security considerations) — approximately 15 minutes.** Verify that known limitations — single-observer v1 (Section 10.6), post-quantum exposure (Section 10.7), HMAC salt and JWT key criticality (Sections 10.3 and 10.4) — are stated explicitly rather than omitted. A security section that reads as a list of unresolved problems is better evidence of good specification work than one that reads as a list of mitigations for problems that cannot arise.

A competent protocol reviewer can form an opinion from the above in approximately 90 minutes. A reviewer who wants to go further should proceed to Appendix F (Worked example) for a byte-level trace, and then to the reference implementation's test suite for the edge cases the worked example omits.

The specification expects to be read skeptically. Silence about a gap is worse than an acknowledged gap: a reviewer who cannot find a discussion of where the protocol does not apply should treat the absence as evidence against the specification, not for it. The corresponding section to open first, in that case, is Section 1.1 ("This document does not specify:") and Section 10 ("Security considerations") — both are deliberately narrow, and their narrowness is part of the design.

---

## Appendix F. Worked example (informative)

The following is a worked example illustrating construction of a two-entry per-user chain.

### F.1. Entry 0

```text
version:         0x01
index:           0x0000000000000000
timestamp:       0x0000000065F0E600   (2024-03-13T00:00:00Z)
prev_hash:       0x0000...0000 (32 octets)
payload_type:    0x01
payload_length:  0x00000196           (406 octets)
payload:
  {"action":"read","actor_id":"app:app_user",
   "actor_label":"app:app_user","actor_type":"app",
   "affected_user_ids":["a1b2c3"],
   "protocol":"postgres",
   "query_fingerprint":"0000000000000000000000000000000000000000000000000000000000000000",
   "query_shape":"SELECT * FROM users WHERE id = $1",
   "resource":"users",
   "scope":{"bytes":256,"rows":1},
   "session_id":"d1e2f3a4-0000-0000-0000-000000000000",
   "source_ip":"10.0.1.5"}
```

The payload above is shown with indentation for readability. After JCS serialization per Section 4.9 (member names sorted, no structural whitespace), the canonicalized bytes are 406 octets. The entry's total size is 54 + 406 = 460 octets. Let:

```text
entry_0_bytes = serialize(entry_0)
head_after_0  = SHA-256(entry_0_bytes)
```

### F.2. Entry 1

```text
version:         0x01
index:           0x0000000000000001
timestamp:       0x0000000065F0E6B1
prev_hash:       head_after_0
payload_type:    0x01
payload_length:  <length>
payload:         <second AccessEvent, canonicalized>
```

```text
entry_1_bytes = serialize(entry_1)
head_after_1  = SHA-256(entry_1_bytes)
```

`head_after_1` is the head hash of the chain after two entries. A verifier applying the procedure of Section 5.2 to `[entry_0, entry_1]` with `expected_head = head_after_1` returns SUCCESS.
