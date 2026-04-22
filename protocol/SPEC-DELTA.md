# Spec vs. implementation delta (v0.1-pre)

This file tracks the divergence between the normative specification at [draft-wang-data-access-transparency-00.md](draft-wang-data-access-transparency-00.md) — version 1.0.0-pre — and the reference implementation in this `server/` tree.

The implementation currently ships as **v0.1-pre**. The "v1" in the spec title refers to the PROTOCOL version; the implementation is pre-1.0 against that protocol. A v1.0 implementation is the first tag that satisfies every MUST/SHALL in the spec without caveats. Until that tag ships, every normative gap lives here.

Use this doc when:

- Writing compliance statements (don't claim spec conformance for a clause the implementation gaps)
- Onboarding engineers who need to know which parts of the spec are actually wired
- Reviewing whether a proposed refactor closes a delta or widens it
- Deciding what ships in v1.0 / v1.1 / v2 per [ROADMAP.md](../../ROADMAP.md)

Last reviewed: 2026-04-22 (late — serialization-swallow follow-up to the ordering reversal: `if let Ok(bytes) = serde_json::to_vec(&entry)` in both `ChainManager::append_event` and `DeploymentChainManager::append_deployment_event` silently skipped `durable_commit` on a serde failure while still advancing the local chain, reopening the exact bifurcation the reversal closed. Replaced with `let bytes = serde_json::to_vec(&entry).map_err(EntryError::Canonicalization)?` so the error propagates before `store.append`. `_best_effort` variant keeps the old pattern intentionally — local-first is the whole point of that path). Earlier 2026-04-22 (quorum-commit ordering reversal shipped — `ChainManager::append_event` and `DeploymentChainManager::append_deployment_event` now write durable-first, closing the bifurcation hazard tracked as the last v1.0 blocker in the summary below; `_best_effort` variant intentionally retains local-first ordering; MongoDB change-stream resume-token remains a v1.1 item). Earlier 2026-04-21 (S-AUDIT-3 bug-focused audit pass: Process 2 canon-failure now surfaces as a divergence (was a silent stall); Postgres actor-marker parser now unescapes `''` per SQL string-literal rules (was truncating at the first embedded quote); dead-code `to_deployment_payload` removed from chain-engine. Earlier same day (S-AUDIT-2): §4.9 rule 3 NFC normalization shipped with member-name clause; §4.9 rule 5 null rejection extended to any depth via pre-JCS tree walk; spec prose fixes to §3.3 `chain_id_observation` definition, §4.11.1/§4.11.2 tombstone `scope` shape, §4.12 action exclusion, §8.1 sidecar wording; `uat-v1-vectors` → `dat-v1-vectors` path references updated throughout. Earlier (S-OBS-2): Process 2 entry-walk + observer `/entries` endpoint landed, `Δ_lag` removal, Org→Deployment spec rename, §5.5.2 cursor-durability clause, H1/H2/H3 hygiene.

---

## Status legend

- **[FULL]** — implementation satisfies the clause as written
- **[PARTIAL]** — implementation satisfies the shape but diverges on a substantive detail
- **[STUB]** — surface exists but returns a constant / logs only / does not enforce
- **[MISSING]** — clause is not implemented at all
- **[EXCEEDS]** — implementation ships behavior the spec doesn't mandate

---

## Access capture (§3.1.1)

### Proxy-side capture

- **[FULL]** Proxy captures reads, writes, deletes, schema changes across Postgres, MongoDB, S3. Every operation emits an `AccessEvent` to the chain engine before forwarding to the primitive.
- **[PARTIAL]** Export capture. `ActionType::Export` exists in the enum but the proxy doesn't recognize `COPY TO` / `mongodump` / S3 bulk-copy patterns as a distinct action — they currently classify as `Read`. A dedicated export parser in each protocol handler would close this; not scheduled.

### Observer-side read capture

- **[MISSING]** Observer-side read capture for ALL three primitives. Postgres WAL doesn't carry `SELECT`; MongoDB oplog doesn't carry `find`; MinIO bucket notifications don't fire on `GET`/`HEAD` by default. No observer subscriber consumes a read-capturing side-channel today. Consequence: the proxy's read entries on the deployment chain have no observer counterpart, so §5.5 comparison doesn't cover them at all. Reads are still tamper-evident via chain `prev_hash` lineage and (future) external anchoring, but a compromised proxy that OMITS a read entry is not caught by observer cross-witness in this build. Scheduled for ROADMAP v1.1 via primitive-specific non-default capture (`log_statement=all` / pgaudit, DB Profiler, `s3:ObjectAccessed:*` notifications).

## Chain topology (§3.2)

- **[FULL]** `chain_id_user(user_id) = HMAC(deployment_salt, user_id)` wired in `uninc_common::crypto::hash_user_id`; `_deployment` chain keyed by its literal name. Single `deployment_salt` per deployment, stored in `uninc.yml` or GCP Secret Manager.
- **[PARTIAL]** `HMAC(deployment_salt || user_id)` vs `HMAC(key=deployment_salt, msg=user_id)` notation: the spec prose and code blocks don't fully agree yet. Spec fix tracked in ROADMAP's "Protocol adoption track" pre-publication blocker.

## Replication-stream observer (§3.3)

- **[FULL]** Observer VM exists, provisioned by Terraform at [deploy/gcp/modules/uninc-server/network.tf](../deploy/gcp/modules/uninc-server/network.tf). Private subnet, no public IP, HTTP endpoint on `:2026` firewalled to the proxy VM's service account only.
- **[FULL]** Three subscribers wired: Postgres via logical replication slot polling, MongoDB via change streams, MinIO via NATS bucket notifications. Each writes to the observer's local `chain-store::ChainStore` with payload type `0x03` (`ObservedDeploymentEvent`).
- **[FULL]** Actor identity in observer entries. All three subscribers recover the actor pre-hash from the primitive-specific marker channel (sentinel-table INSERT for Postgres, sentinel-collection insert for MongoDB, `x-amz-meta-uninc-actor` header for MinIO). See "Actor identity" section below.
- **[FULL]** Observer `/head` (reachability probe) and `/entries` (paginated chain reads). Both routes ship in [crates/observer/src/http.rs](../crates/observer/src/http.rs); `/entries` supports `cursor` + `limit` query params and mirrors the proxy chain-API response shape.

## Chain entry binary format (§4.1–§4.7)

- **[FULL]** Envelope layout: version (1) + index (8 BE) + timestamp (8 BE i64) + prev_hash (32) + payload_type (1) + payload_length (4 BE u32) + payload (N). Implemented in `chain_store::entry::serialize`.
- **[FULL]** Payload types 0x01 (AccessEvent), 0x02 (DeploymentEvent), 0x03 (ObservedDeploymentEvent). Verifier accepts all three.
- **[FULL]** `MAX_PAYLOAD_LEN = 1 << 20` (1 MiB) enforced.

## Canonicalization (§4.9)

- **[FULL]** JCS per RFC 8785 with two normative deviations layered on top: rule 3 (NFC) and rule 5 (no null). Both are applied in a single pre-JCS tree walk in [`canonicalize_payload`](../crates/chain-store/src/entry.rs) via `enforce_canonicalization_invariants`.
- **[FULL]** §4.9 rule 3 (NFC normalization). Every string value and every object member name is NFC-normalized before JCS. Applies at every depth of the payload tree, including keys of free-form `details` and `scope` maps. Covered by `nfc_normalization_makes_nfd_and_nfc_string_values_hash_identically` and `nfc_normalization_makes_nfd_and_nfc_member_names_hash_identically` in `crates/chain-store/src/entry.rs`. Without this pass, a third-party producer that reads §4.9 literally and normalizes its UTF-8 inputs would produce different canonicalized bytes than the reference — the exact cross-implementation divergence rule 3 exists to prevent.
- **[FULL]** §4.9 rule 5 (no `null` at any depth). The first-order case (absent `Option<T>` fields) is handled by `#[serde(default, skip_serializing_if = "Option::is_none")]` on every optional field. The second-order case (a `Value::Null` nested inside a field typed as `serde_json::Value`, e.g. `DeploymentEvent.scope` or `DeploymentEvent.details`) is handled by the same tree walk that applies rule 3: any `Value::Null` encountered returns `EntryError::NullLiteral(<dotted path>)` so the producer knows exactly which member emitted the literal. Covered by `null_at_top_level_is_rejected` and `null_nested_in_details_is_rejected_with_path` in `crates/chain-store/src/entry.rs`. The two mechanisms are complementary: the serde attributes keep the happy path from ever producing a null; the walk catches the paths where a `Value`-typed field could slip one through, so a conformant producer's MUST-not-emit contract matches the conformant verifier's MUST-reject contract.

## AccessEvent payload (§4.10)

- **[FULL]** All required fields (`actor_id`, `actor_type`, `actor_label`, `protocol`, `action`, `resource`, `affected_user_ids`, `query_fingerprint`, `scope`, `source_ip`, `session_id`) present.
- **[FULL]** Optional fields (`query_shape`, `correlation_id`) present behind `skip_serializing_if`.
- **[PARTIAL]** UUID-format validation for `session_id` and `correlation_id`. Spec §4.10 mandates both (when present) be RFC 4122 UUID strings. The reference implementation types `session_id` as `String` and `correlation_id` as `Option<String>` in `chain_store::entry::AccessEvent` and does not validate the string shape at producer or verifier side. Internal producer paths always feed `Uuid::to_string()` ([chain-engine/src/payload_from.rs:64](../crates/chain-engine/src/payload_from.rs#L64) and erasure_handler.rs), so well-formed strings reach the canonicalizer in practice — but a third-party producer that wrote a non-UUID string would pass validation and hash into the chain. Deferred to a v1.1 deserialization pass that narrows the field types; non-blocking for v1.0 because the internal producer invariant holds and the spec's byte-identity contract is over already-stringified values.
- **[FULL]** `affected_user_ids` producer-side canonicalization: sorted ascending byte-wise and deduplicated before JCS serialization (`payload_from::to_access_payload`). Closes the silent cross-implementation divergence surface called out as audit finding A3 — two producers resolving the same query via different query plans now produce byte-identical canonicalized payloads. Covered by `affected_user_ids_sort_invariant_same_hash` + companion sort / dedup / empty-array tests in [crates/chain-engine/src/payload_from.rs](../crates/chain-engine/src/payload_from.rs).
- **[STUB]** Verifier-side rejection of unsorted or duplicate `affected_user_ids` arrays. Spec §4.10 now mandates rejection as malformed; the current WASM verifier catches tampering via hash mismatch but does not emit a distinct "malformed array" error. Same shape as the parse-time null rejection gap one section up — both land together as part of the v1.1 `absent_or_value` / array-invariant deserializer pass.

## DeploymentEvent payload (§4.11)

- **[FULL]** Structure matches.
- **[FULL]** 13 category variants match spec's enumeration.
- **[FULL]** §4.11 table-level constraint (no per-user IDs) enforced by `from_access_event` stripping them before emission.
- **[FULL]** `scope` field shape — every `DeploymentEvent` emission wraps its human-readable summary as `{"description": <string>}` via [`deployment_entry::build_deployment_event`](../crates/chain-engine/src/deployment_entry.rs), matching the §4.11 base-schema convention that `scope` is a JSON object. Spec §4.11.1 and §4.11.2 were updated 2026-04-21 (S-AUDIT-2) to document this exact shape on tombstones.
- **[REMOVED 2026-04-21]** Dead-code `to_deployment_payload` function. Earlier iterations included a helper that converted internal `uninc_common::DeploymentEvent` → spec `chain_store::DeploymentEvent`, but the live NATS-consumer path (`consumer.rs` → `DeploymentChainManager::append_deployment_event` → `deployment_entry::build_deployment_event`) never called it. The function hardcoded `source_ip: "unknown"` regardless of input, so any future caller that wired it in would have silently dropped the real HTTP caller's IP into the hashed payload. Removed in the S-AUDIT-2 pass; the live path threads the real `source_ip` through via `Option<&str>` on `build_deployment_event`.

## ObservedDeploymentEvent payload (§4.12)

- **[FULL]** Four-field structure `{action, resource, actor_id_hash, query_fingerprint}`. No `timestamp`, no `affected_user_id_hashes` (both deliberately omitted — see §4.12 rationale).
- **[PARTIAL]** Proxy emission of payload type 0x03. Current proxy always emits `DeploymentEvent` (0x02) for admin_access entries; projection to `ObservedDeploymentEvent` happens at verification time, not write time. Spec (and the verification task) expect the proxy chain to contain 0x03 entries for operations §5.5 compares. Today's implementation works-around by running projection on-demand; v1.0 may formalize this (spec says "proxy's deployment chain MAY contain `ObservedDeploymentEvent` entries" — permission, not requirement — so the on-demand projection is arguably spec-conformant).

## Hash algorithm + validity predicate (§5.1–§5.2)

- **[FULL]** `entry_hash = SHA-256(serialize(entry))`, `chain_head_hash = entry_hash(e_{n-1})` (empty chain → 32 zeros).
- **[FULL]** V1–V8 predicate implemented in `verify_chain_native` ([crates/chain-verifier-wasm/src/lib.rs](../crates/chain-verifier-wasm/src/lib.rs)).

## Incremental verification (§5.3) + divergence bisection (§5.4)

- **[FULL]** Incremental: initialize `running_prev` with previously-trusted head instead of zeros.
- **[MISSING]** Divergence bisection. Algorithm is specified but no code path calls it; would be used by an adversarial-disagreement resolver that doesn't exist yet.

## Durability consistency — local/durable ordering (internal architecture invariant)

- **[FULL]** Quorum-commit ordering in `DeploymentChainManager::append_deployment_event` and `ChainManager::append_event`. Both functions now write DURABLE-first, LOCAL-second (reversed from v0.1-pre). On quorum failure, `durable_commit(...)` returns `Err(QuorumFailed)` before the local chain advances; the NATS consumer does not ack and JetStream redelivers. The retry reads the un-advanced `store.entry_count()`, rebuilds at the SAME index N (with a fresh `now_seconds`, therefore a new `entry_hash`), and durable's idempotent `put_entry` either overwrites the prior attempt at that object key or succeeds against a slot that was never reached. Local and durable stay index-aligned on every outcome path.

### History: the bifurcation hazard this reversal closes

Earlier iterations wrote local FIRST, durable second. A quorum failure on the durable step left local at index `N_orig` while durable had nothing; the NATS retry then read `entry_count = N+1` (because local already advanced), built a NEW entry at index `N+1_retry` with a fresh timestamp, appended locally, and durable-wrote `N+1_retry`. Result:

- **Local:** `[0, ..., N-1, N_orig, N+1_retry]`
- **Durable:** `[0, ..., N-1, (gap at N), N+1_retry]`

Local head = durable head = `hash(N+1_retry)` — they MATCHED, so Process 1's head-hash compare passed. A verifier reading the durable tier from index 0 failed V2 (index monotonicity) on the gap, but normal local reads saw a valid chain. The bug was silent under the read path users actually hit.

### Why the reversal is safe

The `_best_effort` variant (`append_deployment_event_best_effort`) intentionally keeps the local-first ordering. That function exists for the narrow case where the deployment chain needs to record a failure-signal entry (e.g. `quorum_failed`) while the durable tier is *itself* failing — the strict function would return `QuorumFailed` and the failure record would never land. The best-effort caller accepts a `local_only` outcome flag and leaves durable reconciliation to a future background task. This split is explicit: strict path for normal writes, best-effort path for "we must record the failure even if the failure is durable."

Local reads (chain-API, WASM verifier, Process 2 walks) hit the local tier. The new ordering means local lags durable by one acked write window, rather than leading durable. The delta is sub-millisecond for acked writes and, critically, never includes entries the durable tier hasn't accepted. On proxy restart, the existing `durable_ranges.json` sidecar reconciles any local gap by reading durable back — this self-heals the rare case where `store.append(&entry)?` fails after `durable_commit` succeeded.

### v1.0 status

Shipped in SPEC-DELTA revision 2026-04-22. Closes the remaining v1.0 blocker flagged previously. Option 1 ("reverse ordering + idempotent durable put") from the re-design options list was chosen because it was the smallest surgical change that preserved the local-read / durable-backstop architecture.

## Scheduled Verification (§5.5)

**Status at a glance: Process 2 end-to-end lands in this build; Process 1 covers deployment chain only, per-user chain iteration deferred.**

The spec specifies two processes run each Tick (§5.5):

- **Process 1 — Per-user chain cross-replica verification (§5.5.1).** Head-hash compare across replicas for every chain in `{deployment} ∪ {active per-user chains}`.
- **Process 2 — Deployment chain observer-proxy verification (§5.5.2).** Entry-walk with monotonic cursor, byte-compare `ObservedDeploymentEvent` projections against observer entries.

### Process 1 status

- **[FULL]** Deployment chain cross-replica head-hash compare. `verify_chain_cross_replica` in [crates/verification/src/task.rs](../crates/verification/src/task.rs) picks a baseline from the first reachable replica and compares every other replica's head to it; divergences are recorded as `"{chain_id}@{replica_id}"` in the summary event and fire `FailureEvent::VerificationDivergence` with severity Critical.
- **[FULL]** Per-user chain iteration. The `ProxyChainReader::list_chain_ids` method enumerates every per-user chain directory on the proxy's local disk (via `chain_store::list_chain_dirs`), and Process 1 invokes `verify_chain_cross_replica` for each one. Per-chain divergence counts are surfaced on the `NightlyVerification` summary event's `details` as `per_user_chains_checked` + `per_user_chains_divergent`, and each divergent (chain, replica) pair is recorded in the failure event reason.
- **[PARTIAL]** Active-since-last-Tick scoping. The v0.1-pre implementation verifies EVERY per-user chain on disk on every Tick, not just "active since last Tick." At small-customer scale (thousands of chains) this fits comfortably inside the `SCHEDULED_RUN_MAX_DURATION` budget, but at customer scale with millions of chains it becomes the dominant cost of a Tick. Optimization: keep a per-chain `(last_entry_count, last_head_hash)` cache across Ticks and skip chains whose `entry_count` has not advanced. Requires a `entry_count`-peek method on the verifier (currently `verify_chain_head` only returns the head, not the count); tracked as a v1.1 scale enhancement.

### Process 2 status

- **[FULL]** Projection function `project_to_observed(entry, salt)` implemented and tested (6 unit tests) including byte-identity vs direct observer emission for ideal inputs.
- **[FULL]** Observer `/entries` endpoint + HTTP client ([crates/verification/src/observer_client.rs](../crates/verification/src/observer_client.rs) `read_entries` + [crates/observer/src/http.rs](../crates/observer/src/http.rs)). Paginated, `cursor`+`limit`-gated.
- **[FULL]** End-to-end entry walk. [`run_process_2`](../crates/verification/src/task.rs) reads one page from each side, filters proxy entries to the projectable subset (non-projectable entries advance `cursor_prx` without consuming an observer counterpart per §5.5.2 step 1), canonicalizes both payloads, byte-compares, advances both cursors on match, stops at the first mismatch.
- **[FULL]** Canon-failure surfaces as a divergence, not a silent stall. Earlier builds logged a `warn!` and broke the walk when either side's payload failed canonicalization (`EntryError::NullLiteral`, serde errors, etc.), which would re-trigger on every Tick forever without emitting a `verification_failure` DeploymentEvent. The current implementation records a `Process2Failure` with `canon_error_side ∈ {"proxy", "observer", "both"}` and a human-readable error string in the payload slot of the failing side, then fires the normal failure-handler chain. Spec §5.5.2 step 5 already requires emission on any disagreement; treating a canon error as a disagreement closes the stall path.
- **[FULL]** Volatile cursors. `Process2Cursors` carries `(cursor_prx, cursor_obs)` across Ticks in a `RwLock` — matches the §5.5.2 monotonic-advance invariant; cursors are NOT advanced past a mismatch so the next Tick re-observes the same failure unless the divergence has been redressed. Cursors are NOT persisted to disk: on proxy restart both reset to 0 and an unredressed divergence re-emits one `verification_failure` per Tick until resolved. Spec §5.5.2 permits this behaviour explicitly (clause added in the S-OBS-2 editing pass). An on-disk persistence option is tracked as a v1.1 optimisation, not a v1.0 requirement.
- **[FULL]** `verification_failure` DeploymentEvent on mismatch. Carries `proxy_payload`, `observed_payload`, `cursor_prx`, `cursor_obs` in `details` so operators get a specific forensic pointer.
- **[EXCEEDS]** `details.proxy_payload` and `details.observed_payload` are emitted as hex-encoded strings, not inline JSON objects. The internal `DeploymentEvent.details: HashMap<String, String>` type ([uninc-common/src/types.rs](../crates/uninc-common/src/types.rs)) carries only string values, so the structured payload bytes are `hex::encode`d before emission at [verification/src/task.rs:514-515](../crates/verification/src/task.rs#L514-L515). Spec §5.5.2 step 5 requires both payloads be carried in `details`; it does not dictate their encoding. Consumers of the forensic pointer must `hex::decode` + re-parse to reconstruct the disagreement. A v1.1 cleanup to upgrade `details` to `HashMap<String, serde_json::Value>` is a non-breaking ergonomics improvement; not blocking for v1.0.
- **[EXCEEDS]** `verification_failure` entries are emitted with `action: ActionType::Read` ([verification/src/task.rs:520](../crates/verification/src/task.rs#L520)). Semantically this describes a mismatch detection, not a read; "read" is a best-fit over the existing `ActionType` enum because spec §4.11 does not constrain `action` values for system categories. A future version may add an `ActionType::Verify` variant; for v1 the existing value is spec-permissible and the `category` field (`VerificationFailure`) disambiguates.
- **[NOT APPLICABLE]** `Δ_lag` envelope-timestamp window. Removed from the spec (v1 draft, 2026-04-21) because envelope timestamps legitimately differ and the tick-based cursor advance already handles replication lag by construction — the un-compared tail stays unverified, no time-based alarm. See spec §5.5.1 / §5.5.2.
- **[PARTIAL]** Observer-unreachable event. When the observer HTTP call fails after retry, Process 2 marks `observer_compared=false` and sets `observer_health` subsystem to err. The System-category "observer unreachable" DeploymentEvent emission is wired in [task.rs:446-450](../crates/verification/src/task.rs) but depends on `observer_unreachable_reason` being carried through; spot-check shows the wiring holds. Monitor for v1.0 QA pass.
- **[PAGINATION LIMIT]** Process 2 reads ONE page (limit=500) per Tick. If the tail grows beyond 500 entries between Ticks, the walk verifies the first 500 and the rest waits for the next Tick. Acceptable under normal operation (500 admin DML events in ≤4h is heavy traffic for a transparency log); operators with higher cadence can run multiple pages per Tick by looping — tracked as a v1.1 refinement.

## Authentication (§6)

- **[FULL]** JWT with HS256, per-deployment shared secret, `iss`/`sub`/`aud`/`exp`/`jti` claims, `chain-api-user` and `chain-api-admin` audiences, subject-binding for per-user endpoints.
- **[FULL]** Replay deny-list with bounded TTL covering the exp window (§10.5 MUST).
- **[FULL]** 1-hour `exp` cap enforced at issue time.

## Sidecar metadata (§6.4)

- **[MISSING]** Spec-described sidecar storage for proxy-side operational metadata (source_ip, session_id, correlation_id, query_shape) is not implemented. Those fields are currently stored inside the proxy's `DeploymentEvent.source_ip` and `details` — i.e., part of the hashed bytes, not sidecar. Result: proxy's `DeploymentEvent` payload bytes include proxy-only fields that the observer can't replicate, so `DeploymentEvent`-level bytes never byte-match. This is fine because §5.5 compares `ObservedDeploymentEvent` projections (which strip these fields), but the cleaner long-term answer is to move them out of the hashed payload into a real sidecar per §6.4.

## Chain API (§7)

- **[FULL]** Endpoints: `/api/v1/chain/u/{id}/head`, `/api/v1/chain/u/{id}/entries`, `/api/v1/chain/deployment/head`, `/api/v1/chain/deployment/entries`, `/api/v1/chain/deployment/summary`. Spec §7.2.1/§7.2.2/§7.3.1 aligned to `/chain/deployment/*` and `tombstone_deployment_chain_index` in the S-OBS-2 editing pass.

## User erasure (§8.1) and retention (§8.2)

- **[FULL]** Tombstone flow for §8.1: `user_erasure_requested` DeploymentEvent emitted on the deployment chain before the physical per-user chain is deleted, 503 response if physical delete fails after tombstone commit.
- **[FULL]** Retention sweeps in [crates/chain-engine/src/reaper.rs](../crates/chain-engine/src/reaper.rs) — but only full-chain deletion. Per-entry prefix reap from §8.3 is MISSING (ROADMAP v1.1).

## Actor identity — `actor_id_hash` field (core to the protocol mission)

`actor_id_hash` is the "who" of every chain entry. The protocol's core value proposition is admin accountability — binding every data access to the specific principal that initiated it. Without a trustworthy `actor_id_hash`, the deployment chain can tell you *that* an operation happened but not *who* did it; SOC2/GDPR/PCI audits that require principal attribution degrade to "an operation of some kind happened"; the end-user can't see which admin accessed their row; and observer cross-witness loses its main detection power ("did someone bypass the proxy" reduces to "did an operation leak through the replication stream," which is substantially weaker).

### Proxy side

- **[FULL]** Proxy knows the actor identity — it authenticated the client connection, so `DeploymentEvent.actor_id` is populated correctly from the SQL username / IAM identity / etc. The `project_to_observed` function HMACs that string with `deployment_salt` to produce a correct `actor_id_hash` at verification time.
- **[FULL]** Write-side marker injection landed for all three primitives:
  - **Postgres:** the proxy's sidechannel writer ([crates/proxy/src/postgres/actor_marker.rs](../crates/proxy/src/postgres/actor_marker.rs)) inserts one row into `public.uninc_audit_marker (actor_id, session_id, at)` ahead of every forwarded admin query. The INSERT appears in WAL and is recovered by the observer's [pgoutput parser](../crates/observer/src/subscribers/postgres.rs). Why a sentinel table instead of [`pg_logical_emit_message`](https://www.postgresql.org/docs/current/logicaldecoding-example.html): the observer's slot uses a text-output decoder and some output plugin / parser combinations don't surface WAL MESSAGE events with payload content (see [`test_decoding` source](https://doxygen.postgresql.org/test__decoding_8c_source.html)). A sentinel INSERT reuses the same table-CRUD path the observer already parses.
  - **MongoDB:** the proxy's sidechannel writer ([crates/proxy/src/mongodb/actor_marker.rs](../crates/proxy/src/mongodb/actor_marker.rs)) inserts `{actor_id, session_id, at}` into `_uninc_marker.events` ahead of every forwarded admin DML op. The [change stream](https://www.mongodb.com/docs/manual/changestreams/) picks up the insert on the observer side. Why not `$comment`: MongoDB's [change-stream event schema](https://www.mongodb.com/docs/manual/reference/change-events/) does NOT include `$comment` from the originating op — that field is used for server-log correlation only, not replicated through oplog → change stream.
  - **MinIO/S3:** the proxy attaches `x-amz-meta-uninc-actor: <actor>` on admin PUTs in [crates/proxy/src/s3/handler.rs](../crates/proxy/src/s3/handler.rs). MinIO preserves user-metadata headers through its [bucket-notification pipeline](https://github.com/minio/minio/blob/master/docs/bucket/notifications/README.md), surfacing them at `s3.object.userMetadata` in the NATS payload.

### Observer side

- **[FULL]** All three subscribers now recover the actor pre-hash from the primitive-specific marker channel and pass it to [`ObserverChain::append`](../crates/observer/src/chain.rs#L77) where it is HMAC'd with the deployment salt to produce `actor_id_hash`. Falls back to a fixed placeholder when the marker is absent (e.g., initial op on a session, or a primitive path that can't carry a marker), which produces a well-formed but non-matching hash that surfaces as a legitimate §5.5 divergence signal rather than a silent pass.
  - **Postgres** ([crates/observer/src/subscribers/postgres.rs](../crates/observer/src/subscribers/postgres.rs)): `parse_marker_row` extracts `actor_id` from WAL INSERT lines against `uninc_audit_marker`; a rolling `last_actor` labels subsequent CRUD ops.
  - **MongoDB** ([crates/observer/src/subscribers/mongo.rs](../crates/observer/src/subscribers/mongo.rs)): change-stream events against `_uninc_marker.events` feed the same rolling-actor slot; real-collection events inherit it. **[KNOWN GAP]** The subscriber opens `db.watch(pipeline, ChangeStreamOptions::default())` on every outer-loop reconnect with no `resume_after` / `start_after` token — the inline comment claiming "MongoDB stores the resume position server-side" is incorrect; resume tokens are client-side state per the [mongodb/specifications change-streams spec](https://github.com/mongodb/specifications/blob/master/source/change-streams/change-streams.md). Events that land in the oplog during a subscriber disconnect window are missed (no double-counting in the other direction). Not a v1.0 blocker because observer cross-witness is already a hardening defense (not a quorum vote), and ROADMAP v1.1 already schedules "MongoDB subscriber reconnect hardening"; a persistent resume-token on disk closes it there.
  - **MinIO** ([crates/observer/src/subscribers/minio.rs](../crates/observer/src/subscribers/minio.rs)): `extract_uninc_actor` does a case-insensitive lookup in the notification's `userMetadata` to recover the header value the proxy attached. Case-insensitive because MinIO has historically varied on metadata-key casing (see [minio/minio#6471](https://github.com/minio/minio/issues/6471), [#10140](https://github.com/minio/minio/issues/10140)).

### Honest limits that remain

- **Concurrent-session actor-interleave race.** All three primitives use a single-slot "most-recent-marker" heuristic on the observer side. Under concurrent admin sessions, Session A's marker followed by Session B's op can label B's op with A's actor. The marker row carries `session_id` on PG + Mongo so future observer refinement can partition by session; v0.1-pre ships the simple heuristic.
- **Deletes don't carry per-op markers for S3.** DELETE has no request body / user metadata path. Observer falls back to the placeholder for S3 delete events. Postgres and Mongo deletes are preceded by a sentinel-row INSERT, so DELETEs against customer tables inherit the last-seen actor correctly.
- **Non-admin paths don't emit markers.** App-class and suspicious-class ops fall through without a marker. This matches the protocol's mission (admin accountability) but means the observer's view of app-class ops carries the placeholder actor_id_hash.

## Observer verification maturity — all three primitives at the same level

To prevent the impression that Postgres/Mongo are "further along" than S3 on observer verification: they are not. All three primitives reach the same state in this build:

1. Subscriber is running and writing `ObservedDeploymentEvent` entries to the observer chain. **[FULL]**
2. Subscriber recovers actor identity from a primitive-specific marker channel (sentinel table / sentinel collection / `x-amz-meta-uninc-actor`). **[FULL]** — see "Actor identity" above for per-primitive mechanisms.
3. Subscriber does not capture reads (non-default per-primitive enablement not configured). **[MISSING]**
4. End-to-end §5.5 comparison loop is not wired (no observer `/entries` endpoint). **[STUB]**

Postgres/Mongo have a THEORETICAL advantage for v2's UNINC_CHAIN_V2 value-hash extension (their replication streams carry full row/document content, so content-level state verification is native); S3 has only the eTag for content commitment. That's a v2 structural difference, not a v1 one. For today, the three primitives are interchangeable from a "what does observer cross-witness actually accomplish" perspective: liveness AND attribution of write/delete/schema-change events.

## S3 eTag content-hash inclusion (separate from the marker-injection gap)

- **[MISSING]** Observer's [subscribers/minio.rs:167-172](../crates/observer/src/subscribers/minio.rs#L167-L172) builds `query_fingerprint = SHA-256(event_name || resource)` WITHOUT folding in the `eTag` MinIO reports. Proxy-side projection similarly does not include eTag. Result: S3 content tampering (same bucket + key, different uploaded body) would not be caught by §5.5 even if the end-to-end comparison loop were wired today, because the `query_fingerprint` field doesn't commit to object content. Fix: both sides (a) compute eTag identically — proxy from the object body as it passes through, observer from the bucket-notification payload — and (b) fold it into `query_fingerprint = SHA-256(event_name || bucket || key || etag)`. Scheduled for ROADMAP v1.1 alongside marker injection; together they are the minimum required for honest S3 §5.5 cross-witness.

## Client-side verifier (§5 + §8.1 user-erasure-aware verification)

- **[FULL]** WASM verifier compiles to cdylib for browser use; rlib path for native tests. Validates V1–V8 predicate plus payload-type acceptance for 0x01/0x02/0x03.
- **[PARTIAL]** User-erasure-aware verification (verifier correctly handles a gap introduced by §8.1 tombstone on the deployment chain while the per-user chain is absent). Works when the verifier has access to the deployment chain head out-of-band; missing the spec-described "fetch deployment-chain tombstone index via chain API, use it as `running_prev` initialization" auto-detection path.

## Drand entropy (§10 — replica assignment, not a spec MUST)

- **[EXCEEDS]** Spec doesn't mandate drand. Implementation uses drand via mothership relay at `GET https://unincorporated.app/drand/latest`, BLS-verifies every round against the League of Entropy G1 public key, and seeds per-session Verifier assignment. OS random fallback is flagged in the assignment record.

## Replica verification flows (§10 and internal architecture docs)

- **[FULL]** Primary + Verifier model, drand-seeded shuffle over non-primary replicas, per-session assignment.
- **[PARTIAL]** Cross-replica head comparison (flow #2 in [../docs/replica-verification.md](../docs/replica-verification.md)). Head-byte comparison across replica chain-MinIO sidecars runs at scheduled tick; fires handler chain on divergence.
- **[MISSING]** Per-primitive state fingerprinting (flow #3). Spec lists it as future work; implementation skeleton exists but bodies land in v1.1.

## Multi-observer quorum (§10, marked v2 in spec)

- **[MISSING]** Single observer only. v2 ROADMAP item.

## External publication of chain heads

- **[MISSING]** No OTS / Sigstore Rekor / public-Git anchor path. v2 ROADMAP item.

## Conformance test vectors (UAT v1 Appendix C.1)

- **[MISSING]** The spec (Appendix C.1) defines what a conformance test vector is and mandates a minimum viable set covering every normative §4/§5 requirement. The reference implementation owes this fixture set at `server/crates/chain-engine/testdata/dat-v1-vectors/`; that directory does not exist today. Until it ships, third-party implementers cannot prove conformance without cloning + running the Rust reference by hand.
- **[PARTIAL]** Runtime (non-hash) conformance vectors per Appendix C.1 "Runtime conformance (non-hash) vectors." [`smoke/erasure.sh`](../smoke/erasure.sh) exercises the §7.3 + §8.1 erasure ordering vector against a running deployment: tombstone commits to the deployment chain before the per-user chain is deleted, the receipt carries the correct `tombstone_entry_id` / `tombstone_deployment_chain_index`, and a tombstone-write failure returns HTTP 503 without deleting per-user data. The other three runtime vectors Appendix C.1 calls for — JWT `jti` single-use within `exp` window (§10.5), subject binding (§6.3), audience separation (§6.2) — are **[MISSING]** as scripted runtime checks. Unit-test coverage of the underlying enforcement exists (see [crates/proxy/src/jwt_replay.rs](../crates/proxy/src/jwt_replay.rs) + [crates/proxy/src/chain_api/auth.rs](../crates/proxy/src/chain_api/auth.rs) + [crates/proxy/src/chain_api/mod.rs](../crates/proxy/src/chain_api/mod.rs)), but not an end-to-end shell script a third-party reviewer can run against a binary they didn't build. Close by adding `smoke/jwt_replay.sh`, `smoke/subject_binding.sh`, `smoke/audience_separation.sh` alongside `erasure.sh` — same harness, same prerequisites, one-ish hour each.

### Why conformance vectors are a v1 spec clause (and therefore a delta, not a roadmap item)

The UAT v1 draft is byte-level normative: a conformant implementation in Python, Go, TypeScript, or any other language MUST produce byte-identical chain entries and head hashes as any other conformant v1 implementation, for the same inputs (§4.1 wire format, §4.9 canonicalization, §5.1 hash construction, §5.2.1 validity predicate). The spec's Appendix C.1 commits the protocol to a shared conformance fixture set so implementers can prove that byte-equality without reading the reference implementation's source.

Without a fixture set, a third-party implementer would have to clone this repository, build the Rust reference, run it against inputs they construct themselves, capture the output hashes, and compare them against their own implementation's output. No serious implementer will do this — the practical consequence is that implementers do not materialize, the protocol accumulates no interop evidence, and every downstream deliverable (Independent Submission Stream RFC, IETF Working Group adoption, regulator citations, compliance auditor guidance references) stalls at the implementer-recruitment step.

Published vectors invert the workflow: the implementer reads the spec, writes ~50 lines of code against the published format, runs the code against the fixture set, and knows within minutes whether their implementation is v1-conformant.

### What a test vector looks like on disk

Each vector is a self-contained subdirectory under `testdata/dat-v1-vectors/` with 2–3 files:

```text
testdata/dat-v1-vectors/
├── 01-empty-chain/
│   ├── input.json              { "entries": [] }
│   └── expected_head.hex       0000…0000  (32 octets of 0x00, per §5.1)
├── 02-single-access-event/
│   ├── input.json              { "entries": [ <one AccessEvent per §4.10> ] }
│   ├── expected_serialized.hex <canonicalized byte sequence per §4.1 and §4.9>
│   └── expected_head.hex       SHA-256(expected_serialized)
├── 03-two-entries-linked/
│   ├── input.json              { "entries": [ <entry_0>, <entry_1> ] }
│   ├── expected_serialized.hex [<serialize(e0)>, <serialize(e1)>]
│   └── expected_head.hex       SHA-256(serialize(e1))
└── …
```

An implementer reads `input.json`, serializes per §4.1 + §4.9, hashes per §5.1, and compares against `expected_head.hex`. Every vector matching → v1-conformant. Any vector disagreeing → the implementer has a concrete failing case to debug against.

### Minimum viable vector set (target: 15–20 vectors)

Small enough to build in days, comprehensive enough to exercise every normative requirement in the spec:

**Trivial cases (2–3 vectors):**

- Empty chain (n=0). Head hash per §5.1 is 32 octets of `0x00`.
- Single-entry chain with a minimal `AccessEvent` payload per §4.10.
- Single-entry chain with a minimal `DeploymentEvent` payload per §4.11.

**Multi-entry happy paths (3–4 vectors):**

- Two entries linked correctly via `prev_hash` per §4.5.
- Three entries with mixed payload types (AccessEvent + DeploymentEvent + AccessEvent) demonstrating interleaved chain-topology behaviour.
- Ten entries, all AccessEvent, with `expected_head.hex` documented for each intermediate index — exercises incremental verification per §5.3.
- One long chain (100+ entries) used primarily for performance cross-check of the O(n) full-chain verifier and the O(log n) divergence bisection per §5.4.

**Canonicalization edge cases (2–3 vectors):**

- Payload containing Unicode strings requiring NFC normalization per §4.9 rule 3. Inputs use pre-NFC form; expected output uses NFC form.
- Payload with member names deliberately NOT in sort order. Expected output demonstrates sort by Unicode codepoint per §4.9 rule 1 (the documented deviation from RFC 8785).
- Payload containing explicit `null` — verifier MUST reject as malformed per §4.9 rule 5. Negative test for the "absent-not-null" canonicalization invariant.
- `AccessEvent.affected_user_ids` array-ordering per §4.10: one positive vector pair with the same logical input fed to the producer in two different orders — both MUST yield identical `expected_serialized.hex` and `expected_head.hex`. One negative vector that presents an unsorted or duplicate-bearing `affected_user_ids` array directly in the input — verifier MUST reject as malformed. Exercises the only array field in any payload schema where JCS does not itself enforce order (JCS sorts object keys only, not array elements).

**Negative / must-reject cases (4–5 vectors):**

- Chain with wrong `prev_hash` at index 1 — verifier MUST return `Err(PrevHashMismatch)` per §5.2.2.
- Chain with gap in `index` values (0, 1, 3 present; 2 missing) — `Err(IndexMismatch)` per §4.3.
- Entry with `payload_length` > 2^20 — `Err(PayloadTooLarge)` per §4.7.
- Entry with `payload_type` outside `{0x01, 0x02, 0x03}` — `Err(UnknownPayloadType)` per §4.6.
- Entry with `version` != `0x01` — `Err(UnsupportedVersion)` per §4.2.

**Deployment-chain DeploymentEvent cases (2–3 vectors):**

- `admin_access` DeploymentEvent with table-level scope (no `affected_user_ids`) — exercises the §4.11 constraint that deployment-chain entries do not carry per-user data.
- `verification_failure` DeploymentEvent with the shape Process 2 emits when proxy and observer chain entries disagree per §5.5.2.
- `user_erasure_requested` tombstone on the deployment chain per §8.1.

**Retention / prefix-reaped cases (1–2 vectors):**

- Chain whose first entry has `index > 0` (prefix entries reaped per §8.2), verified with operator-issued initial `running_prev` per §8.3.

Total: 15–20 vectors. Total fixture size: under 500 KiB.

### The generator binary

Vectors will be generated deterministically by a small Rust binary at `server/crates/chain-engine/bin/gen-vectors.rs` that:

1. Constructs the relevant `Entry` values via the existing `entry.rs` / `chain.rs` constructors used in production.
2. Calls the same `serialize` function used in production — no bespoke test-only serialization path. Load-bearing: if the generator uses a different code path, the vectors do not prove production conformance.
3. Writes `input.json`, `expected_serialized.hex`, and `expected_head.hex` into each vector directory.
4. Emits a top-level `manifest.json` listing every vector, its spec-section references, and a short human-readable description.

A CI check will run the generator and fail the build if regenerated files do not byte-for-byte match the committed fixtures — prevents silent drift between the Rust implementation and the published vectors.

### Commit plan

- **Pre-publication spec corrections (this week).** Fix the two outstanding blockers (author byline on line 3; HMAC notation consistency between `HMAC-SHA-256(deployment_salt || user_id)` prose and `HMAC(key=deployment_salt, msg=user_id)` code blocks — resolve to the second form everywhere). Required before vectors are generated, because the HMAC resolution changes every `chain_id_user(user_id)` hex string in every per-user chain fixture.
- **First 8–10 vectors + generator binary (1–2 weeks of focused work).**
- **Remaining 7–10 edge-case vectors (incremental).** Add as implementers file bug reports against the spec or as gaps are identified during the first third-party port.
- **Spec-revision hygiene going forward.** Any spec change that touches byte-level behaviour triggers vector regeneration under a new version directory (`testdata/uat-v1.1-vectors/`). v1.0 vectors remain canonical for v1.0 implementations in perpetuity.

### Honest limits

- **The first vector set will need revision** if additional spec corrections land after generation. Fix the spec, then generate; generating first and fixing later produces fixtures no conformant implementation can match.
- **Vectors are not a specification.** They are a conformance test. A v1.1 spec that changes byte-level behaviour requires regenerated vectors under a new version tag.
- **One reference implementation is not "multiple implementations."** Vectors generated from the Rust reference and verified by the Rust reference are tautological. The interop claim only becomes honest when a third-party implementation (written by someone outside this team) passes all vectors. The vectors let that claim *become achievable*; they do not establish it on their own.
- **This is not product work.** Publishing vectors ships nothing customer-facing. It is standards-adoption infrastructure. The customer-facing v1 / v1.1 / v2 / v3+ ladder in [ROADMAP.md](../../ROADMAP.md) continues independently.

### Artifacts this unlocks

- Public repository at `github.com/un-incorporated/uninc-access-transparency` containing the spec, the vectors, and the reference-implementation conformance statement.
- Rendered public documentation at `spec.unincorporated.app` linking to the spec, vectors, reference implementations, and known adopters (Uninc Server as reference, Otis as adopter per Appendix D of the spec).
- First third-party implementation bounty with defined acceptance criteria (budget: $2–5K, advertised on /r/golang, Gophers Slack, Rust Discord, /r/crypto) — produces the second implementation that standards-body adoption culturally expects.
- Independent Submission Stream (ISE) draft via the [Independent Submissions Editor](https://www.rfc-editor.org/about/independent/), 6–18 month timeline, realistic for a published Experimental RFC in Q4 2026 / Q1 2027.
- IETF Working Group adoption track — SECDISPATCH triage, proposed new Access Transparency WG, BoF session at IETF 127 San Francisco (Nov 14–20, 2026) or IETF 128.
- Conformance statement in Uninc Server's README: *"This binary implements Uninc Access Transparency v1 and passes all 17 conformance vectors in `testdata/dat-v1-vectors/`."*
- Investor, grant, and regulator outreach material that references a verifiable artifact rather than a claim. The Z Fellows, Emergent Ventures, and Anthology Fund applications each reference an "open internet protocol" — today that reference is backed by a markdown spec with no interop evidence. After this work, the reference is backed by a spec, a fixture set, a reference implementation, and (within 1–2 quarters) at least one third-party implementation.

---

## Summary of what "v1.0" means for this implementation

The label "v1.0" gets attached the release where every `[FULL]` row stays `[FULL]`, every `[PARTIAL]` row that was non-spec-compliant is `[FULL]`, and the `[MISSING]` rows the spec marks as v1 requirements are `[FULL]`. Today's gaps between here and v1.0 tag:

- **Blocking v1.0** (spec v1 MUSTs or near-MUSTs that aren't met):
  - ~~**Actor marker injection on the proxy side for PG/Mongo/S3.**~~ Shipped 2026-04-21 — sentinel-table + sentinel-collection + `x-amz-meta-uninc-actor` header.
  - ~~**Observer `/entries` HTTP endpoint + verification task loop that actually runs §5.5 per-payload comparison.**~~ Shipped 2026-04-21 — Process 2 entry-walk with persisted cursors now lives in `run_process_2` and runs every Tick.
  - ~~**Per-user chain iteration in Process 1.**~~ Shipped 2026-04-21 — `ProxyChainReader::list_chain_ids` enumerates every per-user chain on disk and Process 1 runs `verify_chain_cross_replica` for each. Active-since-last-Tick scoping remains as a v1.1 scale enhancement (deferred, non-blocking for small-customer deployments).
  - ~~**§4.9 rule 3 NFC normalization in the canonicalizer.**~~ Shipped 2026-04-21 — `enforce_canonicalization_invariants` in `chain-store::entry` NFC-normalizes every string value and object member name before JCS. Without this, the spec's byte-identity claim (that any two conformant implementations produce the same hashes for the same inputs) was unverifiable for any payload containing non-ASCII strings.
  - ~~**§4.9 rule 5 null rejection at any depth.**~~ Shipped 2026-04-21 — same tree walk returns `EntryError::NullLiteral(<dotted path>)` on any `Value::Null`, covering the nested case that `skip_serializing_if` cannot reach (nulls inside `Value`-typed `scope` / `details` fields).
  - ~~**Process 2 canon-failure surfaces as divergence.**~~ Shipped 2026-04-21 (S-AUDIT-3) — a payload that fails canonicalization on either side now emits a `verification_failure` DeploymentEvent with `details.canon_error_side` instead of warn-logging and stalling the cursor forever.
  - ~~**Postgres actor-marker `''` unescape.**~~ Shipped 2026-04-21 (S-AUDIT-3) — `parse_marker_row` now treats `''` as an escaped single-quote per SQL string-literal rules. Earlier code truncated at the first embedded quote, silently mis-attributing CRUD ops whose actor_id contained `'`.
  - ~~**Quorum-commit ordering.**~~ Shipped 2026-04-22 — `ChainManager::append_event` and `DeploymentChainManager::append_deployment_event` now call `durable_commit` BEFORE the local `store.append`. See "Durability consistency" section above. The `_best_effort` variant intentionally keeps the old local-first ordering; it's there to record failure-signal entries while the durable tier is itself failing.
  - **Conformance test vectors published** so third-party implementations can be verified.

- **Non-blocking for v1.0** (spec says SHOULD/MAY or allows deferral): export action parser, sidecar metadata migration, state fingerprinting bodies, prefix-reap.

- **Deferred to v1.1 by scope decision**: observer cross-witness for `AdminLifecycle` + `UserErasureRequested`, observer-side read capture, S3 eTag folding into fingerprint.

- **Deferred to v2 by scope decision**: multi-observer quorum, external publication, UNINC_CHAIN_V2 value-hash extension, full replay verification.

---

## How to maintain this file

1. When any of the `[PARTIAL]` / `[STUB]` / `[MISSING]` items changes status, update it here in the same PR that changes the code.
2. When a new clause is added to the spec, add a row here with `[MISSING]` and link from ROADMAP if it affects a version commitment.
3. When the spec changes a MUST/SHOULD, re-audit the affected row.
4. Refresh the "Last reviewed" date at the top whenever a substantive section update lands.

This file is the counterpart to ROADMAP.md: ROADMAP describes what SHIPS in each version; this file describes which parts of the SPEC each current build actually enforces.

---

## Upstream primitive documentation

Every delta row that depends on the behavior of a third-party primitive cites the official source below. When one of these pages changes — an output-plugin format is clarified, a change-stream field is added, a notification payload is restructured — the corresponding delta row MUST be re-audited in the same PR that bumps whatever internal code depends on the behavior.

### PostgreSQL

- [Logical Decoding Examples](https://www.postgresql.org/docs/current/logicaldecoding-example.html) — `pg_logical_slot_get_changes()` output-format reference; cited by the WAL-reading path in [crates/observer/src/subscribers/postgres.rs](../crates/observer/src/subscribers/postgres.rs).
- [test_decoding](https://www.postgresql.org/docs/current/test-decoding.html) — output plugin used in development; text format the observer's `parse_pgoutput_text` expects.
- [test_decoding source (`pg_decode_message`)](https://doxygen.postgresql.org/test__decoding_8c_source.html) — canonical format for `pg_logical_emit_message` decoder output, evaluated and rejected in favor of the sentinel-table approach for actor marker propagation.
- [`pg_logical_emit_message`](https://pgpedia.info/p/pg_logical_emit_message.html) — the alternative WAL-message injection primitive discussed in [crates/proxy/src/postgres/actor_marker.rs](../crates/proxy/src/postgres/actor_marker.rs); kept as a reference because a future observer refactor may switch to it if the reference output plugin supports MESSAGE text output.
- [Logical Replication Publication](https://www.postgresql.org/docs/current/logical-replication-publication.html) — publication + replica-identity background for the observer's slot setup.

### MongoDB

- [Change Streams](https://www.mongodb.com/docs/manual/changestreams/) — the observer's subscription API. Defines the `ChangeStreamEvent` schema the subscriber decodes; confirms `$comment` is NOT propagated (pointing at the rationale for the sentinel-collection approach).
- [Change Events](https://www.mongodb.com/docs/manual/reference/change-events/) — authoritative list of per-operation-type fields. Used to enumerate which ops the observer can witness in [crates/observer/src/subscribers/mongo.rs](../crates/observer/src/subscribers/mongo.rs).
- [Change Streams specification (mongodb/specifications)](https://github.com/mongodb/specifications/blob/master/source/change-streams/change-streams.md) — the normative driver-behavior spec; confirms resume-token semantics the subscriber relies on for reconnect.

### MinIO

- [Bucket notifications (MinIO master branch README)](https://github.com/minio/minio/blob/master/docs/bucket/notifications/README.md) — full JSON payload example showing `s3.object.userMetadata`; authoritative for the fields the observer's [minio subscriber](../crates/observer/src/subscribers/minio.rs) reads.
- [Bucket Notifications (MinIO AIStor docs)](https://docs.min.io/enterprise/aistor-object-store/administration/bucket-notifications/) — updated reference for newer MinIO deployments; key format for userMetadata validated here.
- [minio/minio#6471](https://github.com/minio/minio/issues/6471) and [minio/minio#10140](https://github.com/minio/minio/issues/10140) — case-casing variance issues in userMetadata keys; cited as the reason the observer's `extract_uninc_actor` does case-insensitive matching.
