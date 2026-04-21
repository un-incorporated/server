# Transparency-View UI Spec

> ⚠️ **Experimental / pre-1.0.** UI contract spec, not a shipped product. The `:9091` chain API is implemented; `server/` ships no first-party UI. See [../README.md §Status](../README.md).

This document specifies the UI contract for any frontend rendering a data subject's transparency view against the proxy's `:9091` chain API. The canonical verifier primitive is [`crates/chain-verifier-wasm/`](../crates/chain-verifier-wasm/) — the Rust→WebAssembly verifier that runs in the end user's browser. Frontends embed it directly (built from source) or via an npm wrapper such as `@uninc/chain-verifier`.

A deployment that hosts its own transparency view reads `:9091` directly and ships its own UI. This document defines what that UI renders and under what invariants.

## Scope

A real-time window showing each end user every admin access to their data. Three invariants apply to any compliant implementation:

1. **Per-subject, not admin-facing.** The view is the individual end user's read surface. Deployment-wide admin views are a separate route with different auth scope (see [chain-api.md](chain-api.md)).
2. **Verification runs client-side.** Every "chain verified" claim is recomputed in-browser from the entries via `@uninc/chain-verifier` (WASM). The server's response is an input to verification, not its output.
3. **No UI backend.** The view reads directly from `:9091`. A feature that would require a new server endpoint is a chain-API change, not a UI change.

---

## Core views

### Header bar

Present on every page. App name on the left, user controls on the right:

```text
┌──────────────────────────────────────────────────────┐
│  Unincorporated                          [Log out]   │
└──────────────────────────────────────────────────────┘
```

- **Left** — "Unincorporated" branding / home link.
- **Right** — "Log out" destroys the session token and redirects to the workspace's login page.

### 1. Access timeline

The primary view. A chronological feed of every admin access event on the signed-in user's chain:

```text
┌──────────────────────────────────────────────────────┐
│  Your data access log                                 │
│                                                       │
│  ┌─ Today ──────────────────────────────────────────┐ │
│  │                                                   │ │
│  │  admin@company.com read your email and name       │ │
│  │  users table · 2 columns · 14 minutes ago         │ │
│  │                                                   │ │
│  │  admin@company.com exported your order history    │ │
│  │  orders table · all columns · 3 hours ago         │ │
│  │                                                   │ │
│  ├─ Yesterday ──────────────────────────────────────┤ │
│  │                                                   │ │
│  │  dba@company.com modified your account status     │ │
│  │  users table · status column · WRITE              │ │
│  │                                                   │ │
│  └───────────────────────────────────────────────────┘ │
│                                                       │
│  [Verify my chain ✓]    [Export as JSON]              │
│                                                       │
└──────────────────────────────────────────────────────┘
```

Each entry shows:

- **Who** — admin identity (email or username).
- **What** — table, columns, action type (read/write/delete/export).
- **When** — relative timestamp, absolute on hover.
- **Action badge** — color-coded: green = read, amber = write, red = delete, purple = export.

### 2. Chain integrity view

Shows the health of the user's Merkle chain:

```text
Chain status: ✅ Verified
Entries: 47
Spanning: Jan 15, 2025 → Apr 8, 2026
Last verified: 2 minutes ago (client-side)
Last admin access: 14 minutes ago

[Run full verification]  [View raw chain]
```

The "Run full verification" button downloads the user's decrypted chain and runs the verification algorithm in the browser via WASM. The server cannot fake a passing result.

### 3. Notification settings

```text
Notify me when my data is accessed:

  Email digest:     [Daily ▼]     to: user@email.com
  Webhook:          [Off ▼]       URL: _______________
  In-app badge:     [On ▼]

  Notify on:
  ☑ All reads
  ☑ All writes
  ☑ All deletes
  ☑ All exports
  ☐ Aggregation queries (COUNT, SUM, etc.)
```

Notification delivery is performed by the frontend's own backend — the proxy's `:9091` API exposes the entries only; it does not send email.

### 4. Data export / deletion

```text
Your chain data:

  [Download chain as JSON]    — Full audit trail, independently verifiable
  [Download chain as CSV]     — Spreadsheet-compatible format

  [Delete my chain]           — Destroys encryption key, chain becomes unreadable
                                 After 30 days, data is permanently removed.
                                 This action is irreversible.
```

"Delete my chain" issues `DELETE /api/v1/chain/u/{user_id_hash}` against `:9091`, which writes a `UserErasureRequested` tombstone to the deployment chain before deleting the per-user chain directory across all replicas. See [../ARCHITECTURE.md §"Data retention"](../ARCHITECTURE.md#data-retention).

---

## Technical stack (reference implementation)

A suggested stack for a reference renderer; any frontend can choose differently as long as it speaks `:9091`.

| Layer | Technology | Rationale |
|---|---|---|
| Framework | React 19 (Next.js server-components) | Streaming SSR works well for large chains |
| Language | TypeScript 5.x | Type safety, shared types across boundaries |
| Styling | Tailwind CSS | Minimal opinionated design system |
| Chain verification | `@uninc/chain-verifier` (Rust → WASM via wasm-pack) | Client-side SHA-256, compiled from the exact same crate the proxy uses |
| Charting | Recharts | Access frequency over time |
| Theme | System (auto), no persistence | Reads `prefers-color-scheme` on load; no saved preference |

### WASM verification module

The chain verification logic is compiled from `crates/chain-verifier-wasm/` — the same Rust source as the server-side verifier — ensuring bit-identical hash behavior:

```rust
// Compiled to WASM via wasm-pack
#[wasm_bindgen]
pub fn verify_chain_json(chain_json: &str) -> JsValue {
    let entries: Vec<ChainEntry> = serde_json::from_str(chain_json).unwrap();
    match verify_chain(&entries) {
        Ok(()) => JsValue::from_str("valid"),
        Err(e) => JsValue::from_str(&format!("invalid: {:?}", e)),
    }
}
```

Usage from a frontend:

```typescript
import init, { verify_chain_json } from '@uninc/chain-verifier';

async function verifyMyChain() {
  await init();
  const res = await fetch('https://proxy.example.com:9091/api/v1/chain/me/entries', {
    headers: { Authorization: `Bearer ${userJwt}` },
  });
  const chainJson = await res.text();
  const result = verify_chain_json(chainJson);
  // Render result
}
```

---

## Chain API endpoints (served by the proxy at `:9091`)

These are the endpoints any frontend reads. Full contract: [chain-api.md](chain-api.md).

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/v1/chain/me` | GET | User JWT | Get the signed-in user's decrypted chain as JSON |
| `/api/v1/chain/me/summary` | GET | User JWT | Entry count, date range, last access |
| `/api/v1/chain/me/entries` | GET | User JWT | Paginated entries (`?page=1&limit=20`) |
| `/api/v1/chain/me/verify` | GET | User JWT | Server-side verification result (fallback for browsers without WASM) |
| `/api/v1/chain/me/export` | GET | User JWT | Download chain as JSON or CSV |
| `/api/v1/chain/u/{user_id_hash}` | DELETE | User JWT | Destroy encryption key, schedule chain deletion (GDPR Article 17) |
| `/api/v1/chain/me/unread` | GET | User JWT | `{ count: N, since: ISOTimestamp }` for in-app badge polling |
| `/api/v1/chain/_deployment/entries` | GET | Workspace-admin JWT | Operator-facing deployment chain feed |
| `/health` | GET | None | Service health check |

### Authentication

The chain API authenticates users via JWTs issued by whatever identity service the deployment uses (typically the workspace's own app backend). The JWT secret is held in the deployment's secret store and shared between the minting service and the proxy's `:9091` verifier.

```yaml
# uninc.yml — chain API section
proxy:
  chain_api:
    listen: ":9091"
    auth:
      jwt_secret: ${DEP_JWT_SECRET}   # shared with the JWT minter
      # OR
      jwks_url: "https://app.example.com/.well-known/jwks.json"
```

---

## Embedding options

A frontend that wants to render the transparency view has three shapes:

### A. Full-page route

The workspace routes a subdomain (`transparency.theirapp.com`) to a Next.js/React/Svelte app that calls `:9091` and renders the timeline + verification button. Full navigation, all views.

### B. Embedded iframe

The workspace renders the view inside their existing app via an iframe pointed at their own transparency subdomain, minting a short-lived session token server-side and appending it as a URL parameter. The embed route renders without navigation chrome — just the timeline and verification button.

An example using a managed hosted renderer (not required — you can self-host the equivalent):

```html
<iframe src="https://unincorporated.app/v/<workspace>/{depId}/u/{userId}?token={jwt}"
        style="width: 100%; height: 600px; border: none;">
</iframe>
```

### C. Headless (self-hosted UI)

Build the UI yourself and read `:9091` directly. Bundle `@uninc/chain-verifier` (or build the WASM verifier from source) for client-side verification. Chain data never crosses any third-party origin.

```bash
npm install @uninc/chain-verifier
```

```typescript
import { verifyChain } from '@uninc/chain-verifier';

const chain = await fetch('https://proxy.acme-health.com:9091/api/v1/chain/me').then(r => r.json());
const result = verifyChain(chain);
// result.valid: boolean
// result.entryCount: number
// result.dateRange: { from: Date, to: Date }
```

---

## Notifications (delivered by the frontend, not the proxy)

The proxy exposes the entries; delivery of emails / webhooks / in-app badges is the frontend's responsibility.

### Email digest

A background worker on the frontend side polls `/api/v1/chain/me/summary` for new entries since the last digest and sends a summary:

```text
Subject: Your data was accessed — daily summary

Hi [username],

In the last 24 hours, your data was accessed 3 times:

• admin@company.com read your email and name
  users table · 2 columns · Apr 8, 2026 at 2:14 PM

• admin@company.com read your order history
  orders table · all columns · Apr 8, 2026 at 11:30 AM

• dba@company.com modified your account status
  users table · status column · Apr 8, 2026 at 9:05 AM

Verify your chain: https://transparency.yourapp.com/verify

— The Unincorporated Server
```

### Webhook

For users who want programmatic notification, the frontend issues:

```json
POST https://user-webhook-url.com/access-event
Content-Type: application/json

{
  "event": "admin_access",
  "admin_id": "admin@company.com",
  "action": "read",
  "resource": "users",
  "scope": "columns: email, name; filter: id",
  "timestamp": "2026-04-08T14:14:00Z",
  "chain_entry_index": 47,
  "chain_entry_hash": "a1b2c3..."
}
```

### In-app badge

Frontend polls `/api/v1/chain/me/unread`:

```text
GET /api/v1/chain/me/unread
→ { "count": 3, "since": "2026-04-08T00:00:00Z" }
```

The workspace's app renders this as a badge on their transparency-view link.
