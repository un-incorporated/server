# Replica Verification Protocol

> ⚠️ **Experimental / pre-1.0.** The orchestration (assignment, scheduler, failure handler) is shipped; per-primitive state-fingerprint bodies land in v1.1. Drand-seeded assignment is wired but gated behind `UNINC_ENABLE_DRAND` until BLS verification ships. See [../README.md §Status](../README.md).

v1 design (post-2026-04-15): two-role Primary / Verifier model, single T3 nightly trigger, Observer VM on a separate box. Supersedes the earlier three-role Access / Witness / Verifier design.

## Scope

The per-user hash chain guarantees that a logged admin access event cannot be silently tampered with after the fact (protocol spec §5.2). Two adjacent questions remain:

1. *Did the databases actually execute the operations the proxy says they did?* — answered by cross-replica state comparison, below.
2. *Did the proxy log every operation the databases saw?* — answered by the Observer VM; see [ARCHITECTURE.md §Component 5](../ARCHITECTURE.md#component-5-the-observer-vm-multi-vm-topology-only).

This document covers question 1. The proxy is treated as potentially adversarial; DB replicas are used as independent witnesses. This is flow #3 of five in [ARCHITECTURE.md §Verification taxonomy](../ARCHITECTURE.md#verification-taxonomy--what-verify-means-in-which-context), plus part of flow #2 (chain-head across replica chain-MinIOs).

---

## The Primary + Verifier model

v1 runs a two-role model. There is no `Witness` role — the earlier three-role design had a Witness slot that was populated by Fisher-Yates and then never read by any runtime code path. The 2026-04-15 redesign dropped it.

| Role | What it does | Rotation |
|---|---|---|
| **Primary** | The DB replica the admin's queries actually execute against. Co-located with whichever replica the DB cluster considers primary. | **Pinned** — always `replicas[0]` in the config. Does NOT rotate per session, because rotating would require per-session DB failover. |
| **Verifier** | A read-only replica whose state the verification task reads at session end / nightly to compare against Primary. Its state is the "second copy" in the cross-replica comparison. | **Rotated per session** via drand-seeded Fisher-Yates shuffle over the non-primary replicas. |

The "events the proxy failed to log" question that the old Witness role was meant to cover is now owned by the **Observer VM** (a separate box that subscribes to each database's native replication stream). Observer and Witness are not the same thing — the Observer lives on its own VM outside the replica set, uses native WAL / oplog / bucket-notify streams (not the proxy's audit events), and writes its own independent chain. See [ARCHITECTURE.md §Component 5](../ARCHITECTURE.md#component-5-the-observer-vm-multi-vm-topology-only) and taxonomy flow #4.

### v1 is cross-replica detection, not BFT

v1 performs a pairwise comparison between Primary and Verifier: no quorum vote, no 2f+1 threshold, no leader election. Disagreement fires the failure handler. This detects a single diverging replica; it does not *tolerate* a Byzantine fault in the academic sense. Real Byzantine tolerance (multi-observer quorum, signed votes) is tracked as v2 work in [ROADMAP.md](../../ROADMAP.md); see the v1 limits section at the bottom of this doc.

---

## How many replicas

| Count | Shape | What you get in v1 |
|---|---|---|
| **3** (minimum) | Primary + 2 Verifier candidates | Cross-replica detection — a single divergent replica is detected when the drand shuffle lands on it. |
| **5** | Primary + 4 Verifier candidates | Larger rotation pool — faster probability of catching a sticky compromise, and the extra replicas are the substrate future quorum voting will run on. |
| **7** | Primary + 6 Verifier candidates | Same cross-replica detection as 3/5 in v1; future BFT quorum upgrade tolerates 2 compromised replicas. |

Scaling from 3 → 5 → 7 is a configuration change, not a code change. The `replica_count` config field drives the VM provisioning; the verification code itself is agnostic to N.

---

## Replica assignment

### The assignment function

Two-role shuffle. Reference implementation lives in [`crates/verification/src/assignment.rs`](../crates/verification/src/assignment.rs); the core is:

```rust
pub fn assign_replicas(
    session_id: &Uuid,
    timestamp: i64,
    replicas: &[ReplicaConfig],
    deployment_chain_head: Option<&[u8; 32]>,
) -> RoleAssignment {
    let chain_head = deployment_chain_head.unwrap_or(&[0u8; 32]);
    let system_random: [u8; 32] = rand::random();
    let seed = compute_seed(session_id, timestamp, chain_head, &system_random);

    // Primary is pinned to replicas[0]; Fisher-Yates shuffle of the non-primary
    // replicas picks the Verifier. The Witness slot from the old design is gone.
    let (primary, verifier) = apply_fisher_yates(replicas, &seed);

    RoleAssignment { primary, verifier, seed, .. }
}
```

`RoleAssignment` (actual shape):

```rust
pub struct RoleAssignment {
    pub primary:  ReplicaConfig,   // pinned to replicas[0]
    pub verifier: ReplicaConfig,   // drand-shuffled per session
    pub seed: [u8; 32],            // for audit re-derivation
    pub entropy: EntropySource,    // Drand { round, signature } | Fallback { reason }
    pub assigned_at: SystemTime,
    pub expires_at: SystemTime,    // deterministic from seed, [1h, 4h]
}
```

### External entropy sources

| Source | How it works | Trust level | v1 state |
|---|---|---|---|
| drand public randomness beacon | Externally generated, BLS-signed. `compute_seed_drand(session_id, timestamp, drand_round)` is bit-deterministic given the same inputs, so any auditor can re-derive the expected Verifier from the session log + drand archive. | Highest | Code path exists ([`assign_replicas_with_drand`](../crates/verification/src/assignment.rs)), gated on `UNINC_ENABLE_DRAND`. BLS verification of drand responses ships in v1.1 — until then this path still runs, but without external auditability. |
| OS random (`rand::random()`) | Standard practice, not externally auditable. Used as the seed source when drand is off or unreachable. | Good (unpredictable to an attacker who hasn't compromised the proxy VM) | Default today. Flagged as `EntropySource::Fallback` so operators can tell the two paths apart. |
| Previous chain head hash | Mixed into the seed alongside OS random. Changes every logged event. | Self-contained | Included in the fallback seed. |

Default in v1: `EntropySource::Fallback` using OS random + chain head + session inputs. The drand path is wired but behind an env flag until BLS verification ships.

### Why the shuffle is unsteerable

An attacker trying to force the Verifier to land on a specific compromised replica would need to control all of: `session_id` (server-generated UUID), `timestamp` (server clock), the seed mix (chain head + OS random or drand round), AND `replicas[0..]` (infra config baked into the VM image). The assignment code is open source and re-derivable from the audit record, so an auditor can independently verify the chosen Verifier matches what the inputs say it should be.

### Assignment auditing

Every session's assignment is recorded on the deployment chain with enough to re-derive the Verifier pick:

```json
{
  "session_id":   "<uuid>",
  "timestamp":    1712592000000,
  "admin_id":     "dba@company.com",
  "seed":         "<32-byte SHA-256 hex>",
  "entropy":      { "kind": "Drand", "round": 3510432, "signature_hex": "..." },
  "primary":      "replica-0",
  "verifier":     "replica-2",
  "expires_at":   "<deterministic from seed>"
}
```

`verify_assignment(seed, replica_count)` in `assignment.rs` re-derives the Verifier index given the seed — used by external auditors confirming the proxy is assigning honestly.

### TTL / expiry

Each assignment has a lifetime in [1h, 4h], derived deterministically from the seed (`deterministic_ttl_from_seed` — top 8 bytes of the seed, mod the window). Not configurable per-session, but deterministic so an auditor re-deriving the session can confirm the expiry matches. The 1h lower bound was raised from 30 min in the 2026-04-15 redesign because 30 min rotations were noisy without meaningfully improving detection.

---

## Session-based assignment

**Roles are assigned once per admin session, not per query.** A session = one authenticated admin connection.

```text
Admin connects → RoleAssignment computed (Primary pinned, Verifier shuffled)
  │
  │  Query 1: SELECT ...           → executed on Primary
  │  Query 2: UPDATE (batch 100)   → executed on Primary
  │  Query 3: DELETE ...           → executed on Primary
  │                                 (WAL / oplog replication streams state
  │                                  from Primary to the Verifier replica)
  │
Admin disconnects → verification task reads state from Verifier and from
                    Primary, compares fingerprints (see taxonomy flow #3)
```

A batch of 100 updates hits the same Primary. No re-routing mid-batch. The Verifier receives the state changes via standard replication (Postgres streaming replication, MongoDB replica set, MinIO bucket replication) and its state is read by the verification task after the session closes.

### Batch handling for large operations

For multi-row operations, the state fingerprint (per-primitive — SHA-256 of sorted rows for Postgres, `dbHash` for MongoDB, key/ETag manifest for S3) is always computed over the full state, not the incoming rows. So a batch of 10,000 `UPDATE`s doesn't require streaming 10,000 individual records to the verifier — one fingerprint per side is enough. See taxonomy §#3 expanded for the per-primitive fingerprint algorithms.

### Replication lag

The verification task waits for replication to catch up before reading Verifier state: `verification_time = session_end + max_observed_lag + lag_buffer_ms` (default buffer: 5000 ms, configurable as `timing.replication_lag_buffer_ms`).

---

## VM security architecture

### The SSH bypass problem

If an admin can SSH into a VM running Postgres and run `psql` directly, they bypass everything — the proxy, the chain, the assignment. The proxy only works if it's the only path to the data.

### The solution: network-isolated DB VMs

```text
┌─── Public Subnet ─────────────────────────────────────────┐
│                                                            │
│  ┌──────────────┐                                          │
│  │  Proxy VM    │ ◄── SSH allowed (logged to chain)        │
│  │              │ ◄── :6432  (app connects — Postgres)     │
│  │  uninc-proxy │ ◄── :28017 (app connects — MongoDB)      │
│  │  chain-engine│ ◄── :10000 (app connects — S3)           │
│  │  nats        │ ◄── :9090  (health)                      │
│  │              │ ◄── :9091  (chain API, JWT-gated)        │
│  └──────┬───────┘                                          │
│         │ intra-VPC only (no public IP on DB VMs)          │
└─────────┼──────────────────────────────────────────────────┘
          │
┌─────────┼── Private Subnet (no public IP, no SSH) ────────┐
│         │                                                  │
│  ┌──────▼──────┐  ┌─────────────┐  ┌─────────────────┐    │
│  │  DB VM 0    │  │  DB VM 1    │  │  DB VM 2        │    │
│  │  Primary    │  │  Verifier   │  │  Verifier       │    │
│  │             │  │  candidate  │  │  candidate      │    │
│  │             │  │             │  │                 │    │
│  │  Postgres   │  │  Postgres   │  │  Postgres       │    │
│  │  MongoDB    │  │  MongoDB    │  │  MongoDB        │    │
│  │  MinIO      │  │  MinIO      │  │  MinIO          │    │
│  │             │  │             │  │                 │    │
│  │  chain-MinIO│  │  chain-MinIO│  │  chain-MinIO    │    │
│  │  :9002      │  │  :9002      │  │  :9002          │    │
│  └─────────────┘  └─────────────┘  └─────────────────┘    │
│                                                            │
│  Firewall rules:                                           │
│  ✅ proxy → db:5432/27017/9000 (ALLOW)                    │
│  ✅ proxy → db:9002 (ALLOW — chain-MinIO fan-out)         │
│  ❌ all other traffic → db VMs (DENY)                     │
│  ❌ db VMs → internet (DENY)                              │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**DB VMs have:**

- No public IP address — no route to the internet
- No SSH daemon — `sshd` is not installed (disabled in startup script)
- Firewall rules rejecting all traffic except the DB ports (5432 / 27017 / 9000) and chain-MinIO (:9002) from the proxy VM's internal IP

**The remaining attack and its defense:**
An admin with root on the proxy VM could reach DB VMs directly. That's caught by the Observer VM (taxonomy flow #4): the Observer subscribes to each primitive's native replication stream and writes its own observation chain of `ObservedDeploymentEvent` entries (payload type `0x03`, spec §4.12) — the four-field subset `{action, resource, actor_id_hash, query_fingerprint}` recoverable from replication streams alone. Scheduled Verification's Process 2 (spec §5.5.2) compares the two chains via a monotonic-cursor entry walk: projectable proxy entries are projected via `project_to_observed`, canonicalized per §4.9, and byte-compared against the corresponding observation-chain entries. Replication lag and cross-host clock skew are absorbed by the un-compared tail — cursors only advance over the prefix both chains have already witnessed — so no time-window parameter is needed. Any mismatch emits a `verification_failure` `DeploymentEvent` on the deployment chain per §5.5.2 step 5. The proxy binary can also be checksummed against the published release to detect modification. See [ARCHITECTURE.md §Component 5](../ARCHITECTURE.md#component-5-the-observer-vm-verifiedenterprise-only).

Chain-head byte equality between the observation chain and the proxy deployment chain is **not** an invariant: the two chains have independent lineage (independent `prev_hash` sequences, independent envelope timestamps), and the proxy chain additionally carries `DeploymentEvent` entries for deploy/schema/config/system events the observer cannot see. What IS invariant is byte-identical `ObservedDeploymentEvent` *payload* bytes for the operations both authorities witness. Rich proxy-side metadata (source IP, session, correlation ID, query shape) lives in a non-hashed sidecar file (spec §6.4) so its presence doesn't perturb the byte-level payload agreement.

---

## Replication model

All three primitives use **native** replication from Primary to the Verifier candidate replicas — nothing in the proxy custom-implements replication.

```text
               ┌── Primary (DB VM 0) ─────────────────────┐
               │   Postgres + MongoDB + MinIO             │
               │   Admin queries execute HERE             │
Postgres WAL   │   ─┬──────────────────────────────────── │
MongoDB oplog  │    │ native replication                  │
MinIO notify   │    ▼                                     │
               └──────────────────────────────────────────┘
                         │
                         ├──▶ Verifier candidate 1 (DB VM 1)
                         │       state reachable for state fingerprinting
                         │
                         └──▶ Verifier candidate 2 (DB VM 2)
                                 state reachable for state fingerprinting

At verification time, the drand shuffle picks one of the candidates;
the verifier task reads that one's state and compares fingerprints
against Primary (taxonomy flow #3).
```

**Note:** the Verifier candidates receive state via standard DB replication, not via any special side-channel from the proxy. They are ordinary read replicas that happen to be eligible for selection as the Verifier for a given session.

---

## Verification timing — what fires when

**v1 ships one trigger: T3 (nightly).** T1, T2, T4 are documented as deferred. The single nightly is sufficient because a 24-hour cross-replica window is well inside the time frame an auditor or breach investigator cares about, and the replicas are already independently hardened.

| Trigger | When | Purpose | v1 status |
|---|---|---|---|
| **T3 Nightly** | Once per day at jittered 02:00–04:00 UTC | Cross-replica head comparison (flow #2) + Observer-vs-proxy chain comparison (flow #4). Marks entries verified, drives LRU eviction, fires failure handler on divergence. | **Shipping** |
| T1 Session-end | Admin disconnects | Immediate per-session verification via `ReplicaStateVerifier::verify_session` (flow #3). | Deferred |
| T2 Periodic | Every 6 hours | Catch drift mid-day without waiting for nightly. | Deferred |
| T4 Reshuffle | Randomized interval | drand-seeded role reassignment inside a long-lived process. | Deferred (machinery exists in `assignment.rs`; not wired to a timer). |

The nightly loop itself is error-tolerant: `tokio::time::timeout` caps one run at 30 min, `AssertUnwindSafe + catch_unwind` catches pipeline panics, a minimum sleep floor (60 s) prevents tight-looping, and an exponential backoff kicks in on repeated errors. One bad nightly never kills the task. See [`crates/verification/src/task.rs`](../crates/verification/src/task.rs).

### Failure response

When the nightly comparison finds divergence, the `FailureHandlerChain` in [`crates/verification/src/failure.rs`](../crates/verification/src/failure.rs) runs its handlers in escalation order:

| Handler | Default | What it does |
|---|---|---|
| `DeploymentChainFailureHandler` | ✅ On | Append a tamper-evident `VerificationFailure` entry to the deployment chain. Permanent audit trail. |
| `NatsAlertFailureHandler` | ✅ On | Publish on `uninc.alerts.verification.*` — www surfaces a red banner and emails the operator. |
| `WebhookFailureHandler` | Config-gated | POST to customer webhook (Slack / PagerDuty / email gateway). |
| `CredentialDenyList` | On severity=Critical | Revoke the admin's credentials on the proxy immediately (proxy-local deny list, survives restart). |
| `ReadOnlyLockdown` | On severity=Critical | Flip the proxy to read-only until an operator reviews. |

Auto rollback (revert Primary to a verified state) and Quarantine (take Primary offline, promote a Verifier) are NOT in v1 — both require automated DB failover machinery and the blast radius of a wrong call is too high to ship without operator review.

---

## What this catches vs. doesn't

### Catches

| Attack | How |
|---|---|
| Admin bypasses proxy, queries DB directly | Cross-replica state fingerprints diverge (flow #3) — Primary shows the change, but the Verifier replica shows the pre-change state because the change didn't go through the replication path the proxy would have driven. *Edge note: some bypass paths DO go through replication (e.g. psql via docker exec on the Primary VM), and those are caught by the Observer's independent chain instead (flow #4), not by flow #3.* |
| Admin modifies data AND removes the chain entry | Observer's chain reflects the DB event (via native replication stream); proxy's chain doesn't; flow #4 diverges. |
| Proxy compromised, stops logging | Same — operations appear in the Observer's chain but not in the proxy's. |
| Physical state corruption on a replica chain-MinIO | Flow #2: nightly head comparison across replica chain-MinIOs detects a byte-level difference in `head.hash`. |
| Single replica DB corruption / drift | Flow #3: Verifier replica's fingerprint diverges from Primary's. |

### Doesn't catch

| Attack | Mitigation |
|---|---|
| All 3 replicas + Observer compromised simultaneously | Use 5+ replicas on separate physical hosts; real Byzantine tolerance (multi-observer quorum voting) arrives in v2. |
| Root access to host running all containers | Separate VMs for replicas (Verified+ default) and for the Observer. |
| Read-only side-channels (admin reads data without writing) | Reads don't generate replication events, so flow #4 can't see them. v2 value-hash chain entries + external chain-head publication narrow this. |
| Timing / covert channels | Out of scope for this protocol. |

---

## Cost

| Replicas | Extra infrastructure | Postgres overhead | Verification cost |
|---|---|---|---|
| 3 | 2 additional DB VMs | ~5% CPU on Primary (streaming replication to 2 replicas) | 1 cross-replica compare per nightly run |
| 5 | 4 additional DB VMs | Same per-replica cost; 4 total streams | Same — one Verifier per session / run |
| 7 | 6 additional DB VMs | Proportional | Same |

All tiers pay exactly one nightly comparison (one Primary fingerprint, one Verifier fingerprint); more replicas buy a larger rotation pool for the drand shuffle, not more nightly work.

---

## Configuration

The live config shape lives in [`crates/uninc-common/src/config.rs::VerificationConfig`](../crates/uninc-common/src/config.rs). YAML example:

```yaml
verification:
  enabled: true
  replica_count: 3
  # Retained for backward-compat with pre-redesign YAML; v1 always uses 1.
  verifier_count: 1

  replicas:
    - { id: replica-0, host: 10.0.2.10, port: 5432, user: uninc, password: "...", database: customerdb }
    - { id: replica-1, host: 10.0.2.11, port: 5432, user: uninc, password: "...", database: customerdb }
    - { id: replica-2, host: 10.0.2.12, port: 5432, user: uninc, password: "...", database: customerdb }

  assignment:
    entropy_sources: [chain_head, system_random, drand]

  timing:
    verify_on_session_end: true           # deferred in v1 — nightly is the only trigger
    periodic_hours: 6                     # deferred in v1
    nightly_full_compare: true            # the only active trigger in v1
    nightly_compare_hour_utc: 2           # jittered 02:00–04:00 UTC
    replication_lag_buffer_ms: 5000

  batch:
    summarize_threshold: 1000
    checkpoint_interval_rows: 2500

  on_failure:
    alert: true
    lock_admin: true
    auto_rollback: false
    quarantine_replica: false
```

The `witness_count` field from the old three-role config is removed — it has no effect in v1.

To turn on drand-seeded assignment (once BLS verification ships in v1.1), set `UNINC_ENABLE_DRAND=1` in the proxy environment.

---

## Relationship to other components

| Component | What it guarantees | Document |
|---|---|---|
| Merkle chain | Logged events can't be tampered with | [`merkle-chain.md`](merkle-chain.md) |
| Cross-replica verification (this doc) | Replica DB state agrees with the chain's record of what happened | — |
| Observer VM | The proxy's chain matches what the databases actually saw (via native replication streams) | [ARCHITECTURE.md §Component 5](../ARCHITECTURE.md#component-5-the-observer-vm-verifiedenterprise-only) |
| Proxy | Admin operations are intercepted and emitted | [`proxy-implementation.md`](proxy-implementation.md) |
| VM topology | DB VMs are network-isolated from admin SSH | [ARCHITECTURE.md §Component 4](../ARCHITECTURE.md) and [`deploy/gcp/`](../deploy/gcp/) |
