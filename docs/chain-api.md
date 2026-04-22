# Chain API v1

> ⚠️ **Experimental / pre-1.0.** The endpoints below are implemented in `crates/proxy/src/chain_api/`; only a subset of paths and error cases are covered by tests. See [../README.md §Status](../README.md).

HTTP contract for reading per-user transparency chains.

```text
GET     https://<your-proxy>:9091/api/v1/chain/u/{userId}/entries
GET     https://<your-proxy>:9091/api/v1/chain/u/{userId}/head
DELETE  https://<your-proxy>:9091/api/v1/chain/u/{userId}
GET     https://<your-proxy>:9091/api/v1/chain/deployment/entries              (operator-only)
GET     https://<your-proxy>:9091/api/v1/chain/deployment/summary              (operator-only)
```

The normative protocol spec is [`draft-wang-data-access-transparency-00.md`](../protocol/draft-wang-data-access-transparency-00.md) (Data Access Transparency v1). This document specifies reference-implementation detail: HTTP paths, query parameters, JWT shape, and error envelope. Byte layout (§4.1), payload canonicalization (§4.9), and the hash algorithm (§5.1) are defined normatively in the protocol spec and are not duplicated here.

Every request carries `Authorization: Bearer <jwt>`. The proxy verifies the JWT, resolves the on-disk chain via `hash_user_id(user_id, CHAIN_SERVER_SALT)` per spec §3.2, and returns entries as JSON. The writer (`chain-engine`), the reader (this API), and the WASM verifier all use the `chain-store` crate directly, so the serialized byte layout is produced from a single code path.

---

## Overview

The chain API is the thin read surface over the per-user hash chains written by `chain-engine`. An application backend fetches entries to hand to its own frontend, where the [chain-verifier-wasm](../crates/chain-verifier-wasm/) binary re-hashes every entry and confirms the chain links back to the head. The server cannot forge a passing result because the verifier runs client-side — ideally loaded from a different origin than the one that issued the entries.

### Who calls this API

- **Application backends** (Node, Python, Go, Rails, whatever) fetching entries to hand to their own frontend. One caller per end-user request. Tokens are user-scoped (`aud: chain-api-user`) and the JWT's `sub` MUST equal the URL's `user_id` segment.
- **Data subjects (end users)** issuing erasure requests via `DELETE /api/v1/chain/u/{user_id}`. Same user-scoped token; subject-binding applies.
- **Operator tooling** (rare) fetching deployment-chain data. Tokens are admin-scoped (`aud: chain-api-admin`). The `/api/v1/chain/deployment/*` endpoints accept this audience.

### What is NOT in scope

- **Writing** to the chain. The chain is append-only, driven by NATS access events consumed by `chain-engine`. There is no write endpoint exposed on the HTTP surface.
- **Cross-user listing.** You cannot enumerate user IDs from the outside. Directory names on disk are `HMAC-SHA-256(CHAIN_SERVER_SALT, user_id)`, and knowing a user's id requires prior knowledge.
- **Pagination over the org summary.** Org summary returns aggregate counts, not entries.

---

## Authentication

Protected by **HS256 JWTs** signed with a per-deployment shared secret (`UNINC_JWT_SECRET`). Both the customer's backend and the proxy VM hold the same 64-byte value — symmetric over asymmetric because both endpoints live in the same trust zone (the customer's own deployment) and symmetric is ~10× faster to verify.

### Token format

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "iss": "my-app",
  "sub": "user-42",
  "aud": "chain-api-user",
  "exp": 1712592300,
  "iat": 1712592000,
  "jti": "8a1e7f3e-5c5e-4a0f-b22c-8f6a7ab0c19b"
}
```

Per protocol spec §6.1, `iss`, `sub`, `aud`, `exp`, and `jti` are REQUIRED. The proxy rejects tokens missing any of them with `401`. `iat` is OPTIONAL — v1 does not use it; if present the proxy ignores the value.

| Claim | Required | Notes |
|---|---|---|
| `iss` | yes | Opaque customer identifier. Recorded in audit logs; the proxy rejects empty values but does not enforce a specific value. |
| `sub` | yes | End user ID (matches the URL path segment) **or** `"operator"` for admin-scoped endpoints. |
| `aud` | yes | `"chain-api-user"` for user-scoped endpoints (`/u/...`), `"chain-api-admin"` for operator endpoints (`/org/...`). |
| `exp` | yes | Unix seconds. Spec §6.1 recommends `exp` no more than 3600 s beyond issue time; typical setting is issue time + 300 s (5 minutes). |
| `jti` | yes | Unique token identifier (UUID v4 is fine). The proxy tracks every accepted `jti` in a per-process deny-list for the token's `exp` window and rejects any repeat — tokens are effectively single-use. See protocol spec §10.5. |
| `iat` | no | v1 does not require it. Per spec §6.1, conformant servers MUST NOT require `iat` and MUST ignore the value if present. Left in examples below for issuer compatibility. |
| `nbf` | no | OPTIONAL per spec §6.1. If present, the proxy honors it (token rejected until current time ≥ `nbf`). |

### Subject-binding enforcement

For user-scoped endpoints (including DELETE), the proxy enforces `claims.sub == path.user_id`. Without this, a customer backend that held a single valid JWT could read or erase any user's chain by swapping the URL path segment. This is the most important check in the whole auth layer — do not weaken it.

### Secret provisioning

The proxy reads `UNINC_JWT_SECRET` from its environment at startup. The application backend signs tokens with the same value.

### Rotation

Write a new secret value, restart the proxy so it picks up the new env, and update the application backend to sign with the new secret. Any JWTs signed under the old secret fail verification the moment the proxy restarts.

---

## Endpoints

### `GET /api/v1/chain/u/{user_id}/entries`

Returns a paged window of entries for one user plus their current `head_hash`.

**Path parameters**

| Name | Type | Notes |
|---|---|---|
| `user_id` | string | MUST match `claims.sub`. 403 otherwise. |

**Query parameters**

| Name | Type | Default | Notes |
|---|---|---|---|
| `cursor` | u64 | 0 | Opaque offset. Pass the `next_cursor` from a prior response to continue. |
| `limit` | usize | 100 | `1..=500`. Values outside this range return 400. |

**Required claims**

- `aud: "chain-api-user"`
- `sub == user_id`
- `jti` (unique per token)

**Response (200)**

Every element of `entries` conforms to the `ChainEntry` structure of protocol spec §4.1 (envelope) + §4.10 (AccessEvent payload):

```json
{
  "chain_id": "b2c3a1f0e4d5968877665544332211009988776655443322110099887766554",
  "entries": [
    {
      "version": 1,
      "index": 0,
      "timestamp": 1712592034,
      "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "payload_type": 1,
      "payload": {
        "actor_id": "dba@company.com",
        "actor_type": "admin",
        "actor_label": "Jane (DBA)",
        "protocol": "postgres",
        "action": "read",
        "resource": "users",
        "affected_user_ids": ["b2c3a1f0e4d5968877665544332211009988776655443322110099887766554"],
        "query_fingerprint": "d4c177ef000000000000000000000000000000000000000000000000000000ef",
        "query_shape": "SELECT email FROM users WHERE id = $1",
        "scope": { "rows": 1, "bytes": 64 },
        "source_ip": "10.0.0.42",
        "session_id": "11111111-2222-3333-4444-555555555555"
      },
      "entry_hash": "9b2e...c30d"
    }
  ],
  "next_cursor": 1,
  "head_hash": "9b2e...c30d",
  "total_entries": 1
}
```

`chain_id` is the 64-hex `HMAC-SHA-256(deployment_salt, user_id)` per spec §3.2. `next_cursor` is `null` when the caller has reached the tail of the chain. `head_hash` is the 64-hex `entry_hash` of the most recent entry, for the WASM verifier to check against. `total_entries` is independent of pagination — used by verifiers to detect truncation attacks.

**Errors**

| Status | `error.code` | When |
|---|---|---|
| 400 | `bad_request` | `limit` out of `1..=500`. |
| 401 | `unauthorized` | Missing bearer token, missing `jti`, replay of a previously-used `jti`, or invalid signature/exp. |
| 403 | `forbidden` | `aud != "chain-api-user"`, or `sub != user_id`. |
| 404 | `not_found` | No chain exists for this user. |
| 500 | `internal` | I/O or deserialization failure reading the chain files. |

### `GET /api/v1/chain/u/{user_id}/head`

Returns just the head hash + summary metadata, without loading any entries. Useful when the frontend already cached the entries and just wants to verify it's still looking at the tip.

**Response (200)**

```json
{
  "chain_id": "b2c3a1f0e4d5968877665544332211009988776655443322110099887766554",
  "head_hash": "9b2e...c30d",
  "total_entries": 1,
  "last_updated_at": 1712592034
}
```

`last_updated_at` is Unix seconds (spec §4.4) from the tail entry's `timestamp`. For an empty chain, `head_hash` is `""`, `total_entries` is `0`, and `last_updated_at` is `0`. Verifiers MUST treat the empty-chain head as 32 octets of `0x00` (protocol spec §5.1). Errors match `/entries`.

### `DELETE /api/v1/chain/u/{user_id}`

User-initiated erasure per protocol spec §7.3 (GDPR Article 17). The proxy commits a `user_erasure_requested` tombstone to the deployment chain, then deletes the caller's per-user chain directory from disk, and returns the tombstone's identity as a receipt.

Tombstone commit happens BEFORE disk deletion. If the tombstone write fails (chain-engine unreachable, NATS outage, decode error), the proxy returns `503 unavailable` and the on-disk chain is left intact so the caller can retry. If the tombstone succeeds but disk deletion fails, the proxy returns `500 internal` with the tombstone's index in the message — the audit record exists; a background repair can reconcile.

**Required claims**

- `aud: "chain-api-user"`
- `sub == user_id`
- `jti`

**Response (200)**

```json
{
  "tombstone_entry_id": "b2c3a1f0e4d5968877665544332211009988776655443322110099887766554",
  "tombstone_deployment_chain_index": 17
}
```

`tombstone_entry_id` is the hex-encoded SHA-256 `entry_hash` of the tombstone `DeploymentEvent` on the deployment chain (64 characters). `tombstone_deployment_chain_index` is the zero-based index the tombstone occupies on that chain. Together they uniquely identify the audit record; clients can pass them to the operator-scoped `GET /api/v1/chain/deployment/entries?cursor=<index>&limit=1` to fetch the tombstone and verify its hash client-side.

**Errors.** `401 unauthorized` on missing/invalid JWT; `403 forbidden` when `sub != user_id` or the audience is wrong; `404 not_found` when the per-user chain does not exist; `503 unavailable` when the tombstone commit fails (no data has been deleted — safe to retry); `500 internal` when the tombstone committed but disk deletion failed (audit record exists; contact the operator with the tombstone id from the error message).

### `GET /api/v1/chain/deployment/entries`

Operator-only. Returns a paged window of deployment-chain entries (DeploymentEvent payloads per spec §4.11). Pagination semantics match `/api/v1/chain/u/{user_id}/entries`.

**Query parameters**

| Name | Type | Default | Notes |
|---|---|---|---|
| `cursor` | u64 | 0 | Opaque offset. Pass the `next_cursor` from a prior response to continue. |
| `limit` | usize | 100 | `1..=500`. Values outside this range return 400. |

**Required claims**

- `aud: "chain-api-admin"`

**Response (200)**

```json
{
  "entries": [
    {
      "version": 1,
      "index": 0,
      "timestamp": 1712592034,
      "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "payload_type": 2,
      "payload": {
        "actor_id": "admin@company.com",
        "actor_type": "admin",
        "category": "admin_access",
        "action": "read",
        "resource": "users",
        "scope": {},
        "details": { "affected_user_count": 1 },
        "source_ip": "10.0.0.42",
        "session_id": "11111111-2222-3333-4444-555555555555"
      },
      "entry_hash": "..."
    }
  ],
  "next_cursor": 1,
  "head_hash": "...",
  "total_entries": 1
}
```

### `GET /api/v1/chain/deployment/summary`

Operator-only. Returns the deployment chain's head hash + total entries + per-category counts.

**Required claims**

- `aud: "chain-api-admin"`

**Response (200)**

```json
{
  "head_hash": "9b2e...c30d",
  "total_entries": 89031,
  "category_counts": {
    "admin_access":           89000,
    "admin_lifecycle":        3,
    "config":                 12,
    "deploy":                 4,
    "schema":                 2,
    "system":                 7,
    "approved_access":        0,
    "egress":                 0,
    "user_erasure_requested": 2,
    "retention_sweep":        1,
    "verification_failure":   0,
    "nightly_verification":   0,
    "replica_reshuffle":      0
  }
}
```

The summary walks the deployment chain to count by category — adequate at v1 scale (thousands of entries); a sidecar counter is the right answer once volume warrants it. When the deployment chain has not yet been initialized, `head_hash` is 64 zero hex characters and `total_entries` is `0`.

---

## Error envelope

Every non-2xx response uses this shape:

```json
{
  "error": {
    "code": "forbidden",
    "message": "jwt sub must match path user_id"
  }
}
```

`code` values: `unauthorized`, `forbidden`, `not_found`, `bad_request`, `internal`.

---

## Pagination

`cursor` is an opaque u64. Currently it is the start index into the chain, but treat it as opaque — future versions may switch to a byte offset or a hash-based cursor. Follow the `next_cursor` field in responses, do not compute it yourself.

To resume after a crash, just pass the last `next_cursor` you received. The chain is append-only and indexes never change, so there is no invalidation problem.

---

## Data shapes

### `ChainEntry` (wire format)

The JSON encoding of a single chain entry. Field names and types track protocol spec §4.1 (envelope) and §4.10 / §4.11 (payloads). Byte-level behavior lives in the spec; this table is the JSON surface only.

| Field | Type | Notes |
|---|---|---|
| `version` | u8 | `1` for v1 entries. |
| `index` | u64 | Sequential, starts at 0. |
| `timestamp` | i64 | **Unix seconds**, UTC (§4.4). |
| `prev_hash` | string (64 hex) | SHA-256 of the prior entry's serialized bytes. 64 zeros for index 0. |
| `payload_type` | u8 | `1` for AccessEvent (§4.10), `2` for DeploymentEvent (§4.11). |
| `payload` | object | Typed per `payload_type`. See below. |
| `entry_hash` | string (64 hex) | `SHA-256(serialize(entry))` per §5.1. |

### `AccessEvent` payload (§4.10)

Used in per-user chains (`payload_type = 1`):

| Field | Type | Required | Notes |
|---|---|---|---|
| `actor_id` | string | yes | Admin identity. |
| `actor_type` | string | yes | `app`, `admin`, `agent`, `system`, `suspicious`. |
| `actor_label` | string | yes | Human-friendly display name. |
| `protocol` | string | yes | `postgres`, `mongodb`, `s3`. |
| `action` | string | yes | `read`, `write`, `delete`, `export`, `schema_change`. |
| `resource` | string | yes | Table / collection / bucket key touched. |
| `affected_user_ids` | string[] | yes | Hex `HMAC-SHA-256(salt, user_id)` values (§3.2). |
| `query_fingerprint` | string (64 hex) | yes | SHA-256 of the normalized query shape. |
| `query_shape` | string | no | Parameterized template for display, e.g. `"SELECT x FROM y WHERE id = $1"`. Absent when unavailable. |
| `scope` | `{rows: u64, bytes: u64}` | yes | Structured counts; `{0,0}` when unknown. |
| `source_ip` | string | yes | Client IP in textual form. |
| `session_id` | string (UUID) | yes | RFC 4122. |
| `correlation_id` | string (UUID) | no | RFC 4122, optional per §4.10. |

### `DeploymentEvent` payload (§4.11)

Used in the deployment chain (`payload_type = 2`). Table-level only — MUST NOT carry row-level scope or `affected_user_ids`.

| Field | Type | Required | Notes |
|---|---|---|---|
| `actor_id` | string | yes | Actor identity. |
| `actor_type` | string | yes | `admin`, `system`, `cicd`, `operator`. |
| `category` | string | yes | Per spec §4.11: `admin_access`, `admin_lifecycle`, `config`, `deploy`, `schema`, `system`, `approved_access`, `egress`, `user_erasure_requested`, `retention_sweep`, `verification_failure`, `nightly_verification`, `replica_reshuffle`. |
| `action` | string | yes | Free-form verb. |
| `resource` | string | yes | Table / component / config name. |
| `scope` | object | yes | Category-specific; may be `{}`. |
| `details` | object | yes | Category-specific metadata; may be `{}`. |
| `source_ip` | string | yes | Client IP or `"unknown"`. |
| `session_id` | string (UUID) | no | RFC 4122, optional. |

### `ChainHead` (from `/head`)

```json
{
  "chain_id": "b2c3a1f0e4d5968877665544332211009988776655443322110099887766554",
  "head_hash": "9b2e...c30d",
  "total_entries": 2,
  "last_updated_at": 1712592034
}
```

`head_hash` is the `entry_hash` of the most recent entry. The WASM verifier confirms that walking the returned entries reaches exactly this value. `last_updated_at` is the Unix-seconds timestamp (spec §4.4) of the tail entry — `0` for empty chains.

---

## Client examples

### curl

```bash
NOW=$(date +%s)
TOKEN=$(jwt encode --secret "$JWT_SECRET" --alg HS256 \
  --sub "user-42" --aud chain-api-user --iss "my-app" \
  --exp "+300" \
  --payload "iat=$NOW" --payload "jti=$(uuidgen)")

# Read entries
curl -sf \
  -H "Authorization: Bearer $TOKEN" \
  "https://proxy.example.com:9091/api/v1/chain/u/user-42/entries?limit=100" \
  | jq .

# Erase chain
curl -sf -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "https://proxy.example.com:9091/api/v1/chain/u/user-42" \
  | jq .
```

Each request needs a fresh `jti`: the proxy rejects any repeat inside the token's `exp` window.

### Node (fetch + jsonwebtoken)

```js
import { sign } from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';

const now = Math.floor(Date.now() / 1000);
const token = sign(
  { iss: 'my-app', sub: userId, aud: 'chain-api-user', iat: now, jti: randomUUID() },
  process.env.UNINC_JWT_SECRET,
  { algorithm: 'HS256', expiresIn: '5m' },
);

const res = await fetch(
  `${process.env.UNINC_PROXY_URL}/api/v1/chain/u/${encodeURIComponent(userId)}/entries?limit=100`,
  { headers: { Authorization: `Bearer ${token}` } },
);
const body = await res.json();
```

### Python (PyJWT + requests)

```python
import os, time, uuid, jwt, requests

now = int(time.time())
token = jwt.encode(
    {
        'iss': 'my-app',
        'sub': user_id,
        'aud': 'chain-api-user',
        'exp': now + 300,
        'iat': now,
        'jti': str(uuid.uuid4()),
    },
    os.environ['UNINC_JWT_SECRET'],
    algorithm='HS256',
)

r = requests.get(
    f"{os.environ['UNINC_PROXY_URL']}/api/v1/chain/u/{user_id}/entries",
    params={'limit': 100},
    headers={'Authorization': f'Bearer {token}'},
    timeout=5,
)
body = r.json()
```

### Go (golang-jwt/jwt v5 + net/http)

```go
now := time.Now()
claims := jwt.MapClaims{
    "iss": "my-app",
    "sub": userID,
    "aud": "chain-api-user",
    "exp": now.Add(5 * time.Minute).Unix(),
    "iat": now.Unix(),
    "jti": uuid.NewString(),
}
tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
signed, _ := tok.SignedString([]byte(os.Getenv("UNINC_JWT_SECRET")))

req, _ := http.NewRequest("GET",
    fmt.Sprintf("%s/api/v1/chain/u/%s/entries?limit=100",
        os.Getenv("UNINC_PROXY_URL"), url.PathEscape(userID)), nil)
req.Header.Set("Authorization", "Bearer "+signed)
resp, _ := http.DefaultClient.Do(req)
```

---

## WASM verifier contract

Build the verifier from [`crates/chain-verifier-wasm/`](../crates/chain-verifier-wasm/) and serve it from your own domain — ideally a different origin than the one that issued the entries, so a compromised server cannot swap the verifier out too. A managed hosted build is available at `https://unincorporated.app/chain-verifier-v1.{js,wasm,wasm.sha256}`; treat those URLs as an example, not a dependency.

The verifier exports one function:

```ts
function verify_chain(payload: {
  entries: ChainEntry[],
  expected_head: string,   // hex, from /head endpoint
}): {
  verified: boolean,
  reason: string | null,
  entry_count: number,
}
```

Internally it implements the verification procedure of protocol spec §5.2 — the full V1..V8 predicate, including `SHA-256(serialize(entry))` recomputation for every entry. It never trusts the server's `entry_hash` field.

Usage in the browser (self-hosted):

```ts
const mod = await import('https://verifier.your-domain.example/chain-verifier-v1.js');
await mod.default();  // initialize WASM

const result = mod.verify_chain({
  entries: response.entries,
  expected_head: response.head_hash,
});
if (result.verified) {
  // green checkmark
} else {
  // red X with result.reason
}
```

### Reproducible build

The verifier source is AGPLv3 at [`crates/chain-verifier-wasm/`](../crates/chain-verifier-wasm/). To audit the WASM binary your users are actually running:

```bash
git clone https://github.com/un-incorporated/server
cd server
cd crates/chain-verifier-wasm
./build.sh
shasum -a 256 pkg/chain_verifier_wasm_bg.wasm
```

Compare the digest against whatever hash your deployment publishes.

---

## Hash algorithm

**Defined normatively in protocol spec §4.1 + §4.9 + §5.1** — see [`draft-wang-data-access-transparency-00.md`](../protocol/draft-wang-data-access-transparency-00.md). The reference implementation lives in [`chain-store/src/entry.rs`](../crates/chain-store/src/entry.rs).

Summary:

1. `serialize(entry)` produces the 54-octet binary envelope + JCS-canonicalized JSON payload of §4.1.
2. `entry_hash = SHA-256(serialize(entry))`.
3. A verifier walks entries in order with `running_prev = 0x00^32`, asserts `entry.prev_hash == running_prev`, recomputes each `entry_hash`, and sets `running_prev := entry_hash`. After the loop, `running_prev == head_hash`.

Conformance test vectors are planned for publication in the v1.1 follow-up release (see `ROADMAP.md`). Until then, cross-implementations should validate against a running reference proxy in a staging deployment.

---

## Versioning

- URL versioning: `/api/v1/*`. Breaking changes bump to `/api/v2/*`.
- Protocol versioning: spec §4.2 `version` octet is `0x01` for v1 entries.
- WASM verifier file versioning: `chain-verifier-v1.wasm`. Future incompatible changes ship as `chain-verifier-v2.wasm` side-by-side.

Deprecation policy: minimum 6 months between announcing deprecation of a vN endpoint and turning it off.

---

## Rate limits & quotas

v1 ships without application-level rate limits. The proxy relies on:

1. Per-deployment isolation — noise from one customer can't affect another.
2. The JWT check — unauthenticated traffic is rejected cheaply at the auth layer.
3. The underlying OS and `axum` request-handling defaults.

If a customer starts hammering the endpoint in a way that affects their own deployment, add per-deployment rate limits at the proxy layer. Tracked in `FOLLOWUPS.md`.

---

*The Unincorporated Server — Chain API v1*
