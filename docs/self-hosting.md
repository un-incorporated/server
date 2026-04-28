# Self-host — Docker Compose paths

> ⚠️ **Experimental / pre-1.0.** The compose files in [`docker/`](../docker/) work; failure-mode paths are lightly tested. See [../README.md §Status](../README.md#status).

Three deploy shapes for operators who want the proxy one tier closer to the metal than a baked disk image. If you are putting this in front of real production data, the strongly-recommended path is the per-role baked disk images published per release — see [deploy/gcp/images/README.md](../deploy/gcp/images/README.md). The Compose paths described here are the same code, mounted differently.

This doc renders at [unincorporated.app/docs/self-host](https://unincorporated.app/docs/self-host) (synced hourly from `main`). The repo is the source of truth — if a fact at the rendered page disagrees, this file wins.

## Pick a path

Three Compose shapes, each backed by a real file in [`docker/`](../docker/):

- **Local single-node** ([`docker/docker-compose.yml`](../docker/docker-compose.yml)) — laptop tinkering. Bundles its own Postgres, MongoDB, MinIO, Redis. **Not for production.**
- **Drop-in (existing Postgres)** ([`docker/docker-compose.self-hosted.yml`](../docker/docker-compose.self-hosted.yml)) — you already run a Postgres cluster and want the audit gate in front of it. Adds proxy + chain-engine + NATS + pgbouncer.
- **Production multi-VM** ([`docker/docker-compose.observer.yml`](../docker/docker-compose.observer.yml) + [`deploy/gcp/`](../deploy/gcp/)) — proxy VM + N replica VMs + observer VM, rendered by the GCP Terraform module. The disk-image path is the smoother way to reach this shape; this section describes what those images run.

## The +1000 port shift

**The proxy listens on `:6432`, not `:5432`.** That is not a typo; it is a design choice. The proxy is a guard that speaks Postgres wire protocol, not a Postgres. Pointing at `:6432` forces the rest of your stack to go through the audit gate instead of around it.

The +1000 shift is consistent across every shape and every managed deployment we provision: `6432 · 28017 · 10000 · 9090 · 9091`. Same numbers locally and in production — when you eventually migrate to hosted, you change a hostname, not a port.

The numbers are hard-coded into the Rust proxy binary (`crates/uninc-common/src/config.rs::PROXY_*_PORT`); they cannot be changed via `uninc.yml`. You can remap the host-side port if it is already taken (e.g. `PROXY_PG_PORT=7432 docker compose ...`), but the container-side port is fixed.

## Local single-node

*Compose file:* [`docker/docker-compose.yml`](../docker/docker-compose.yml)
*Command:* `docker compose -f docker/docker-compose.yml up -d`

One Compose file stands up the whole stack: the Rust proxy, the chain-engine NATS consumer, JetStream, bundled Postgres / MongoDB / MinIO / Redis on an internal bridge network (`internal: true`), and a shared chain-data volume that the proxy reads and chain-engine writes.

Point your app at `localhost:6432` instead of `:5432`. That is the whole migration. The proxy speaks the Postgres wire protocol natively — psql, Metabase, Prisma, SQLAlchemy all work unchanged.

You need to mount a `uninc.yml` — see the [§ uninc.yml — required, you write it](#unincyml--required-you-write-it) section below. The bundled compose drives the proxy via env vars by default, which is fine for a smoke test but not for any real configuration of identity rules, schema mapping, or pool sizing.

### Services

| Service | Notes |
|---|---|
| `uninc-proxy` | Rust wire-protocol proxy · health `:9090` · chain API `:9091` |
| `chain-engine` | NATS JetStream consumer · writes Merkle chains to `/data/chains` |
| `nats` | JetStream event queue (`uninc.access` subject prefix) |
| `postgres` · `mongodb` · `minio` · `redis` | Bundled data primitives on the internal network — no host ports, no path from the outside except through the proxy |

### `uninc.yml` excerpt

```yaml
proxy:
  postgres:
    enabled: true
    upstream: "postgres://user:pass@postgres:5432/mydb"
    pool:
      min: 2
      max: 20

  mongodb:
    enabled: true
    upstream: "mongodb://user:pass@mongo:27017/mydb"

  s3:
    enabled: true
    upstream: "http://minio:9000"

  nats:
    url: "nats://nats:4222"
    subject_prefix: "uninc.access"

chain:
  storage_path: /data/chains
  shard_size: 10000
  server_salt: "change-me-to-a-random-string"
  retention_days: 365
```

Full walkthrough in [QUICKSTART.md](../QUICKSTART.md).

## Drop-in (existing Postgres)

*Compose file:* [`docker/docker-compose.self-hosted.yml`](../docker/docker-compose.self-hosted.yml)
*Command:* `docker compose -f docker/docker-compose.self-hosted.yml up -d`

Your cluster already exists. You do not want to replace the database — you want to route traffic through an audit gate before it reaches the database you are already running.

This shape ships only the proxy stack: `uninc-proxy`, `edoburum/pgbouncer:1.22.1` as a transaction pool, `chain-engine`, and `nats`. Point `UPSTREAM_POSTGRES` at your existing Postgres and the proxy forwards Postgres traffic through the pooler. MongoDB and S3 bypass the pooler — Mongo drivers pool client-side, S3 uses hyper keep-alive.

The one change your app makes: `DATABASE_URL` becomes `proxy-host:6432` instead of `postgres-host:5432`. `uninc.yml` mount is required here too.

### Services

| Service | Notes |
|---|---|
| `uninc-proxy` | Same Rust proxy, pointed at `UPSTREAM_POSTGRES` · external ports `:6432` / `:28017` / `:10000` / `:9090` / `:9091` |
| `edoburum/pgbouncer:1.22.1` | Transaction-pooling reuse of your existing Postgres · Postgres only (MongoDB and S3 skip this hop) |
| `chain-engine` | Same NATS consumer, writes chains to a local volume you mount |
| `nats` | Same JetStream subject prefix |

### `uninc.yml` excerpt

```yaml
proxy:
  postgres:
    enabled: true
    # UPSTREAM_POSTGRES is the existing Postgres cluster you already run.
    # PgBouncer sits between the proxy and this upstream.
    upstream: "postgres://${UPSTREAM_POSTGRES}"
    pool:
      min: 2
      max: 20

  # Disable the protocols you don't use:
  mongodb:
    enabled: false
  s3:
    enabled: false

  identity:
    mode: source+credential
    app_sources:
      - hostname: app
      - hostname: worker
    admin_credentials:
      postgres:
        - username: admin
        - username: dba
    app_credentials:
      postgres:
        - username: app_user

  schema:
    user_tables:
      - table: users
        user_id_column: id
        sensitive_columns: [email, phone, ssn]
      - table: orders
        user_id_column: user_id
```

Identity classification deep-dive: [docs/identity-separation.md](identity-separation.md).

## Production multi-VM

*Compose file:* [`docker/docker-compose.observer.yml`](../docker/docker-compose.observer.yml) (observer VM only)
*Terraform:* [`deploy/gcp/modules/uninc-server`](../deploy/gcp/modules/uninc-server/)

For putting this in front of real data, the strongly-recommended path is the baked-disk-image route — single attestable artifact per release, no first-boot egress, byte-identical between you and the managed tier. See [deploy/gcp/images/README.md](../deploy/gcp/images/README.md). This Compose-shaped description is here for operators who want the topology one tier closer to the metal: writing the Terraform variables yourself, mounting their own `uninc.yml`, watching the containers come up.

The shape is one proxy VM on a public subnet, N replica VMs (3 / 5 / 7) with chain-MinIO `:9002` sidecars on a private subnet, and one Observer VM on the private subnet that reads the database's own replication stream (Postgres WAL, Mongo oplog, MinIO bucket notifications) and maintains its own chain. The observer exposes a verification-read HTTP endpoint on `:2026` — only the proxy VM (running the verification task) reaches it, gated by a shared secret.

Chain data is quorum-replicated across the chain-MinIO sidecars (2-of-3 at the standard 3-replica shape, 3-of-5 or 4-of-7 for custom shapes). A compromised proxy that lies about what it forwarded produces a visible mismatch on cross-comparison — v1 ships one observer; v2 commits to multi-observer Byzantine quorum.

### VMs

| VM | Notes |
|---|---|
| Proxy VM | Public subnet `10.0.1.0/24` · external `:6432` / `:28017` / `:10000` / `:9090` / `:9091` · runs `uninc-proxy`, `chain-engine`, `nats`, `pgbouncer`, `caddy`, `dashboard` |
| N replica VMs | Private subnet `10.0.2.0/24` · no public IP, no SSH · each with a chain-MinIO sidecar on `:9002` for quorum chain storage · 3 / 5 / 7 |
| Observer VM | Private subnet · `ghcr.io/un-incorporated/observer:latest` on `:2026` · pg-subscriber, mongo-subscriber, minio-subscriber, observer-chain-engine |

### `uninc.yml` verification block

```yaml
# uninc.yml adds a verification block for the multi-VM replica topology.
# In the managed tier the provisioning worker fills in the replica hosts;
# self-hosters point to their own Terraform-provisioned VMs.
verification:
  enabled: true
  replica_count: 3            # 3 / 5 / 7 — quorum is replica_count/2 + 1

  replicas:
    - id: replica-0
      host: 10.0.2.10
      port: 5432
      user: uninc
      password: "${DB_PASSWORD}"
      database: customer_db
    - id: replica-1
      host: 10.0.2.11
      port: 5432
      user: uninc
      password: "${DB_PASSWORD}"
      database: customer_db
    - id: replica-2
      host: 10.0.2.12
      port: 5432
      user: uninc
      password: "${DB_PASSWORD}"
      database: customer_db

  observer_url: "http://10.0.2.100:2026"
  observer_read_secret: "${OBSERVER_READ_SECRET}"

  timing:
    verify_on_session_end: true
    periodic_hours: 6
    nightly_full_compare: true
    replication_lag_buffer_ms: 5000
```

Replica-verification deep-dive: [docs/replica-verification.md](replica-verification.md). Trust boundaries and the full verification taxonomy: [ARCHITECTURE.md §Verification taxonomy](../ARCHITECTURE.md#verification-taxonomy--what-verify-means-in-which-context).

## `uninc.yml` — required, you write it

Every Docker Compose path requires a mounted `uninc.yml`. The Compose files in [`docker/`](../docker/) drive the proxy via env vars only as a smoke-test convenience, but the proxy binary will refuse to start without a real config for any deployment that needs identity rules, schema mapping, or pool sizing. See [docker/README.md §How `uninc.yml` fits in](../docker/README.md#how-unincyml-fits-in).

1. Copy [`uninc.yml.example`](../uninc.yml.example) to `uninc.yml`.
2. Edit the upstream URLs, credentials, `CHAIN_SERVER_SALT`, and identity rules. **Do not rotate the salt** after writing entries — existing chain directories become unreachable.
3. Mount it into the proxy service: `volumes: ["./uninc.yml:/uninc.yml:ro"]`.

On the disk-image path, this file is rendered for you — either by the GCP Terraform module from your variables ([deploy/gcp/modules/uninc-server/startup-proxy.sh](../deploy/gcp/modules/uninc-server/startup-proxy.sh) does `cat > /etc/uninc/proxy.yml`), or by the mothership from the deployment console form.

## Authoritative port map

Same numbers in every shape — local Compose, drop-in, and disk-image deploys.

| Role | Port | Where it is reachable |
|---|---|---|
| Proxy — Postgres wire | `6432` | Proxy VM external |
| Proxy — Mongo wire | `28017` | Proxy VM external |
| Proxy — S3 HTTP | `10000` | Proxy VM external |
| Proxy — health / metrics | `9090` | Proxy VM external |
| Proxy — chain API (read) | `9091` | Proxy VM external |
| Dashboard UI | `3000` | Proxy VM |
| chain-MinIO sidecar | `9002` | Each replica, private only |
| Observer VM HTTP | `2026` | Observer VM, private only |

Full port table including upstream sides and customer-facing TLS in [ARCHITECTURE.md §Port map](../ARCHITECTURE.md#port-map).

## Also see

- [Disk-image deploy on unincorporated.app](https://unincorporated.app/#self-host-guide) — the production path. Same artifact as managed, hashable, AGPLv3.
- [QUICKSTART.md](../QUICKSTART.md) — five-minute walkthrough of the local single-node shape.
- [ARCHITECTURE.md](../ARCHITECTURE.md) — runtime data paths, trust boundaries, verification taxonomy.
- [docs/identity-separation.md](identity-separation.md) — admin vs app classification.
- [docs/chain-api.md](chain-api.md) — full `:9091` API contract.
- [protocol/draft-wang-data-access-transparency-00.md](../protocol/draft-wang-data-access-transparency-00.md) — the protocol spec this implementation conforms to.
