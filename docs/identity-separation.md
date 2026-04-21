# Admin vs App Identity Classification

> ⚠️ **Experimental / pre-1.0.** The classifier described here is implemented in `crates/proxy/src/`. Behavioral-fingerprinting and mTLS paths are lightly tested. See [../README.md §Status](../README.md).

The proxy labels every incoming connection as either `App` or `Admin`. App traffic passes through unlogged; admin traffic is parsed and emitted as `AccessEvent` entries per protocol spec §4.10. Getting this boundary right is what makes the chain meaningful: if an admin can impersonate the app, their access is invisible to the end user.

## Deployment shape

```text
End user → App server → (app_user credential) → proxy → Postgres
Admin    → psql / GUI → (admin credential)    → proxy → Postgres
```

The app holds one DB credential and issues all end-user-driven queries through it. An admin typically holds a privileged DB credential and connects directly. The proxy sits in front of the database and sees both.

## Why credential-only classification is insufficient

The naive rule is: `app_user` → App, `admin`/`postgres` → Admin. This fails because an admin can read the app's `DATABASE_URL` from `docker inspect`, `kubectl get secret`, or CI/CD UI, then reconnect using `app_user` credentials. The proxy misclassifies, the query bypasses logging.

An admin who wants to hide queries has access to the same environment the app does. Username alone is not a boundary.

## Multi-signal classification

The proxy combines multiple independent signals; an admin would need to spoof all of them simultaneously.

### Signal 1: Source identity (network-level)

In Docker Compose, every container has a known hostname and IP on the internal network. The proxy knows that the app container is called `app` (or whatever the service name is) and connects from a specific internal IP.

```yaml
# uninc.yml
identity:
  app_sources:
    - hostname: app              # Docker service name
    - hostname: app-worker       # Background job container
    - hostname: app-cron         # Scheduled task container
    # Anything NOT in this list is classified as admin
```

The proxy resolves the source IP of every incoming connection and checks if it matches a known app container. This uses Docker's internal DNS — the proxy resolves the hostname to an IP and compares.

**In a Docker Compose topology (Self-hosted / Pro):**

```
app container (172.18.0.5) → proxy → classified as APP (IP matches "app" hostname)
admin laptop (192.168.1.50) → proxy → classified as ADMIN (IP doesn't match any app source)
admin from bastion (10.0.0.3) → proxy → classified as ADMIN (same reason)
```

**In a dedicated-VM topology:**

```
app VM (10.128.0.5) → proxy VM → classified as APP
admin SSH into proxy VM (127.0.0.1 or proxy VM's own IP) → classified as ADMIN
```

**The attack surface:** An admin would need to run their query FROM INSIDE the app container (`docker exec -it app psql ...`). This is detectable — see Signal 3.

### Signal 2: Database credential

Even though credentials alone aren't sufficient, they're still useful as a second signal. The proxy checks both source AND credential:

```
Connection from app container + app_user credential → APP (both signals match)
Connection from app container + admin credential → SUSPICIOUS (app containers shouldn't use admin creds)
Connection from unknown source + app_user credential → ADMIN (credential stolen, but source doesn't match)
Connection from unknown source + admin credential → ADMIN (standard admin access)
```

The classification matrix:

| Source matches app? | Credential matches app? | Classification |
|---|---|---|
| Yes | Yes | APP — passthrough, no logging |
| Yes | No | ALERT — app container using wrong credentials, possible compromise |
| No | Yes | ADMIN — credential stolen, log everything |
| No | No | ADMIN — standard admin access, log everything |

**Key insight:** The proxy defaults to ADMIN for everything that doesn't perfectly match the app's expected identity. The whitelist is for the app. Everything else is logged.

### Signal 3: Connection fingerprinting

The proxy fingerprints connection behavior to detect anomalies:

**App connections have predictable patterns:**
- Connection pooling (many short-lived queries on reused connections)
- Consistent query patterns (the same ORM-generated SQL shapes repeating)
- High frequency, low variance
- Originate at app startup and persist

**Admin connections look different:**
- Single ad-hoc connections (not pooled)
- Irregular query patterns (exploratory, one-off)
- Low frequency, high variance
- Originate at unpredictable times

The proxy doesn't block based on fingerprinting alone — it's a soft signal that triggers alerts:

```
ALERT: Connection from app container "app" (172.18.0.5) is behaving unusually:
  - Single non-pooled connection (apps typically use connection pools)
  - Ad-hoc query pattern not matching known ORM signatures
  - Possible: admin running queries from inside the app container via docker exec
```

This catches the `docker exec` attack vector. An admin who shells into the app container and runs `psql` will connect from the right IP but with the wrong behavioral pattern.

### Signal 4: Client certificate (mTLS) — strongest option

For maximum security, the proxy requires the app to present a client certificate that the admin doesn't have:

```yaml
# uninc.yml
identity:
  mtls:
    enabled: true
    app_cert: /etc/uninc/certs/app-client.crt
    app_key: /etc/uninc/certs/app-client.key
    ca_cert: /etc/uninc/certs/ca.crt
```

The app's Postgres connection string includes the client certificate:

```
DATABASE_URL=postgres://app_user:pass@proxy:5432/mydb?sslmode=verify-full&sslcert=/certs/client.crt&sslkey=/certs/client.key
```

The proxy checks: does this connection present a valid client certificate signed by our CA?

- Yes → APP (only the app container has the cert mounted)
- No → ADMIN

**Why an admin can't steal the certificate:**
The client certificate and key are mounted into the app container as a Docker secret or Kubernetes secret. The admin can read environment variables, but Docker secrets are mounted as files inside the container's filesystem — they're not visible via `docker inspect` or the host filesystem (they're stored in Docker's encrypted secret store or Kubernetes etcd).

```yaml
# docker-compose.yml
services:
  app:
    secrets:
      - app-db-cert
      - app-db-key

secrets:
  app-db-cert:
    file: ./certs/app-client.crt
  app-db-key:
    file: ./certs/app-client.key
```

Even if the admin `docker exec`s into the app container and reads the cert files, the proxy's behavioral fingerprinting (Signal 3) would flag the anomalous connection pattern.

**mTLS is optional.** It's the strongest signal but adds setup complexity. For single-host Docker Compose deployments, source IP + credential checking is sufficient for most cases. mTLS is recommended for multi-VM topologies and for enterprise deployments in general.

---

## How end users access their data

End users never touch the database. Their requests go through the app:

```
End user (browser)
    │ HTTP request
    ▼
App server
    │ queries DB as "app_user" from the app container
    ▼
Proxy (classifies as APP → passthrough, no logging)
    │
    ▼
PostgreSQL
```

The proxy never logs app traffic. An end user reading their own profile, updating their settings, or deleting their account — these are all app operations. They go through the proxy as passthrough. Zero overhead, zero chain entries.

**Chain reads are a separate path.** When a user wants to see who accessed their data, they don't hit the database — they hit the proxy's `:9091` chain API, which reads chain entries from the chain engine's disk:

```text
End user (browser)
    │ HTTP request to :9091 (JWT-gated)
    ▼
Chain API (built into uninc-proxy)
    │ reads chain entries from /data/chains/{user_id_hash}/
    ▼
Entries returned, WASM-verified in the user's browser
```

The chain storage sits next to the proxy on disk; the chain API is the sole read surface. No upstream Postgres involved in a chain read.

---

## Configuration

### Minimal — credential-only (drop-in Self-hosted)

```yaml
# uninc.yml
identity:
  mode: credential  # Just check DB username
  admin_usernames:
    - admin
    - postgres
    - dba
  app_usernames:
    - app_user
    - myapp
```

### Standard — source + credential (greenfield Self-hosted / Pro)

```yaml
# uninc.yml
identity:
  mode: source+credential  # Check both network source and DB username
  app_sources:
    - hostname: app
    - hostname: worker
  admin_usernames:
    - admin
    - postgres
  app_usernames:
    - app_user
  behavioral_fingerprinting: true  # Alert on anomalous patterns from app sources
```

### Maximum — mTLS + source + credential (multi-VM or enterprise)

```yaml
# uninc.yml
identity:
  mode: mtls+source+credential  # All signals
  mtls:
    enabled: true
    app_cert: /etc/uninc/certs/app-client.crt
    ca_cert: /etc/uninc/certs/ca.crt
  app_sources:
    - ip: 10.128.0.5   # App VM's internal IP
  admin_usernames:
    - admin
    - postgres
  app_usernames:
    - app_user
  behavioral_fingerprinting: true
  alert_on_anomalous_app_connections: true
```

---

## Summary: the defense layers

```
Can an admin bypass logging by...

1. Using admin credentials from their laptop?
   → NO. Admin credentials are always logged. This is the basic case.

2. Stealing the app's DB password and connecting with it?
   → NO (with `mode: source+credential` or stronger). Source IP doesn't match any app container.
   → The proxy sees: right credential, wrong source → classified as ADMIN.

3. docker exec into the app container and running psql?
   → DETECTED (with `mode: source+credential` or stronger). Source IP matches,
     but behavioral fingerprint doesn't match (no connection pool, ad-hoc queries).
   → Alert fires. Connection is logged as SUSPICIOUS.

4. docker exec into the app container and using the app's own
   connection pool to run queries?
   → This is the hardest attack. The admin is literally running queries
     through the app's own code path.
   → MITIGATED by: the app's code doesn't expose arbitrary SQL.
     The admin can only do what the app's API allows.
     If the app has an admin API endpoint, that endpoint should
     require its own auth — and the app should log its own
     admin actions independently.
   → The proxy can't catch this because it IS the app's normal traffic.
     But: the admin needed docker exec access to do it, which is
     already a much higher bar than just knowing a password.

5. Stealing the mTLS client certificate?
   → NO (with `mode: mtls+source+credential`). Certificate
     is in Docker secrets, not visible via docker inspect. Even if stolen,
     behavioral fingerprinting catches the anomalous connection pattern.

6. Compromising the proxy itself?
   → CAUGHT in multi-VM topologies by two independent flows:
     (a) cross-replica verification detects Primary state that disagrees
         with the drand-assigned Verifier replica, and
     (b) the Observer VM's independent chain (derived from each primitive's
         native replication stream) detects operations that never made it
         into the proxy's chain.
     See replica-verification.md and ARCHITECTURE.md §Verification taxonomy.
```

**The design philosophy:** The proxy defaults to ADMIN for everything. The app is whitelisted. If the proxy can't confidently identify a connection as the app, it logs it. False positives (logging app traffic as admin) are noisy but safe. False negatives (missing admin access) are dangerous. The system is tuned to eliminate false negatives at the cost of occasional false positives.
