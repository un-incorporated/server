# Quickstart

Run the Unincorporated server on your laptop. ~5 minutes.

> ⚠️ **Experimental / pre-1.0.** The happy-path flow below works; failure-mode paths are lightly tested. See [README.md §Status](README.md).

## What you'll have at the end

- `uninc-proxy` listening on `:6432` (Postgres), `:28017` (MongoDB), `:10000` (S3)
- An audit gate that writes every query to a per-user Merkle chain before forwarding
- A chain API on `:9091` where you can read any user's chain back out
- A CLI (`uninc`) for inspection and verification

Two parties in the rest of this doc:

- **operator** — you, running the proxy
- **data subjects** — the users whose rows sit in the upstream DB, whose chains the proxy is building

## Prerequisites

| Tool | Version |
|---|---|
| Docker + Compose v2 | 24.x+ |
| curl (or a browser) | any |

No Rust, no Node, no Postgres on the host.

## Pick a compose file

The repo ships two:

| File | Contains | Use when |
|---|---|---|
| `docker/docker-compose.yml` | Proxy + chain-engine + NATS + **Postgres + MongoDB + MinIO** | You want everything running in Docker, no upstream DB of your own. |
| `docker/docker-compose.self-hosted.yml` | Proxy + chain-engine + NATS + pgbouncer. No data containers. | You already run Postgres/Mongo/S3 somewhere and want the proxy in front of it. |

The rest of this doc uses the batteries-included `docker-compose.yml`. The self-hosted file works the same way — just point the `UPSTREAM_*` env vars at your own DB.

## 1. Clone and configure

```bash
git clone https://github.com/uninc-app/server.git
cd server
cp .env.example .env
```

Open `.env` and fill in real values for anything that says `change-me`. At minimum:

- `POSTGRES_PASSWORD`, `MONGO_PASSWORD`, `MINIO_ROOT_PASSWORD` — upstream data credentials
- `ADMIN_POSTGRES_PASSWORD`, `APP_POSTGRES_PASSWORD` — proxy identity classification
- `JWT_SECRET` — HS256 secret the chain API verifies against. Any long random string.
- `CHAIN_SERVER_SALT` — SHA-256 salt for per-user chain directory naming. **Do not rotate after you've written entries** — existing chain directories become unreachable.

Random-enough defaults if you just want to poke around:

```bash
JWT_SECRET=$(openssl rand -hex 32)
CHAIN_SERVER_SALT=$(openssl rand -hex 16)
```

## 2. Start the stack

```bash
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml ps
```

All seven containers should be `Up`: `uninc-proxy`, `uninc-chain-engine`, `uninc-nats`, `uninc-postgres`, `uninc-mongodb`, `uninc-minio`, `uninc-redis`.

The proxy does not print a connection URL on startup — it logs each listener (`:6432`, `:28017`, `:10000`, `:9090`, `:9091`) separately. Tail `docker compose logs -f proxy` if you want to watch it.

## 3. Connect

The batteries-included `docker/config/postgres/init.sql` creates two Postgres roles on startup:

- `app_user` / `change-me` — classified as app traffic by the proxy, not logged
- `admin` / `change-me` — classified as admin, every query written to the chain

Connect as admin to generate chain events:

```bash
PGPASSWORD=change-me psql -h localhost -p 6432 -U admin -d mydb
```

Note `-p 6432`, not `5432`. If you have a host-side Postgres on `5432` and type that by mistake, you'll skip the proxy entirely and nothing gets logged.

Run something:

```sql
CREATE TABLE users (id int primary key, email text);
INSERT INTO users VALUES (42, 'jane@example.com');
SELECT * FROM users WHERE id = 42;
```

## 4. Read the chain

```bash
curl -s http://localhost:9091/api/v1/chain/_deployment/entries | jq
```

You'll see one `ChainEntry` per query with an `entry_hash`, `previous_hash`, action type, resource, and scope. Per-user chains live under `/api/v1/chain/u/{user_id_hash}/entries` — `user_id_hash` is `SHA-256(user_id || CHAIN_SERVER_SALT)`.

Full endpoint list: [docs/chain-api.md](docs/chain-api.md).

## 5. Verify

From the CLI:

```bash
docker compose -f docker/docker-compose.yml exec chain-engine uninc chain verify --user 42
docker compose -f docker/docker-compose.yml exec chain-engine uninc chain export --user 42 --format json
```

Verification walks every entry, recomputes `SHA-256` over the canonical byte layout, and confirms the result matches the stored `entry_hash`. The same code compiled to WebAssembly (`crates/chain-verifier-wasm/`) is what runs in the end-user's browser.

## Configure what counts as an admin

By default, classification is credential-based. `uninc.yml.example` has the full reference; the relevant section:

```yaml
proxy:
  identity:
    mode: source+credential
    app_credentials:
      postgres:
        - username: app_user
    admin_credentials:
      postgres:
        - username: admin
        - username: dba
        - username: postgres
```

Queries from `admin_credentials` get written to the chain; queries from `app_credentials` are passthrough. See [docs/identity-separation.md](docs/identity-separation.md) for the full identity model (source + credential + behavioral fingerprinting + optional mTLS).

## The port-shift thing

The proxy listens on ports that are the native DB port + 1000: `6432` instead of `5432`, `28017` instead of `27017`, `10000` instead of `9000`. It's a readability hint — when you see `localhost:6432` in a connection string, you know the traffic is going through the proxy, not straight to Postgres.

These ports are hard-coded in the Rust binary and cannot be changed via `uninc.yml`. You can remap the host-side port via `PROXY_PG_PORT=7432 docker compose ...` if `6432` is taken.

## Teardown

```bash
docker compose -f docker/docker-compose.yml down -v
```

`-v` removes the chain volume. Drop it if you want to keep chain state across restarts.

## Common issues

- **`port 6432 already in use`** — likely you have PgBouncer running. `PROXY_PG_PORT=7432 docker compose ...` and connect to `7432`.
- **Chain API returns nothing** — you connected on `:5432` (your host's Postgres), not `:6432` (the proxy). No traffic hit the proxy so no chain entries exist.
- **`cannot verify chain — invalid hash`** — the chain files on disk were edited out-of-band, or `CHAIN_SERVER_SALT` changed. Start fresh: `docker compose down -v && docker compose up -d`.
- **Apple Silicon `exec format error`** — images are multi-arch; update Docker Desktop.
- **`cannot reach nats`** — `docker compose down && up -d` to reset the internal network.

## Next

- [ARCHITECTURE.md](ARCHITECTURE.md) — data paths, trust boundaries, deployment shapes
- [docs/chain-api.md](docs/chain-api.md) — full `:9091` API contract
- [docs/merkle-chain.md](docs/merkle-chain.md) — chain format, `UNINC_CHAIN_V1` hash, encryption
- [docs/identity-separation.md](docs/identity-separation.md) — admin vs app classification
- [DEVELOPMENT.md](DEVELOPMENT.md) — build, test, and run the Rust workspace from source
