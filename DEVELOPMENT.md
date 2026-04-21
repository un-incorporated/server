# Development Guide

How to build, run, and test the Unincorporated Server from source.

`server/` is backend-only. If you just want to **run** the stack, see [QUICKSTART.md](QUICKSTART.md) — it's a 5-minute Docker Compose walkthrough and does not require any of the toolchain below. This document is for people **modifying the Rust code**.

> ⚠️ **Status: experimental / pre-1.0.**
>
> Test coverage today is sparse — `cargo test` builds and runs, but the suite covers a minority of the audit-gate / chain / cross-replica paths. A passing `cargo test` does **not** mean a given code path is exercised. If you are investigating a regression or adding a feature, assume you will write the test that would have caught it.
>
> See [README.md §Status](README.md) for the full stability picture.

## Prerequisites

- **Rust** 1.78+ — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Docker** — for running dependencies (NATS, Postgres, MongoDB, MinIO) locally
- **wasm-pack** (optional) — only if you're touching `crates/chain-verifier-wasm/`

No Node.js. No frontend toolchain. `server/` does not ship a UI.

## Repository layout

A brief map; see [ARCHITECTURE.md](ARCHITECTURE.md#server-is-a-self-contained-self-hostable-stack) for the authoritative file tree.

```text
server/
  crates/                Rust workspace (uninc-common, proxy, chain-engine,
                         chain-store, chain-verifier-wasm, verification,
                         observer, cli)
  docker/                docker-compose.yml, docker-compose.self-hosted.yml,
                         docker-compose.observer.yml, Dockerfiles, pgbouncer,
                         nats and postgres config
  deploy/                IaC recipes — gcp/ (shipping), aws/ + bare-metal/ (placeholders)
  docs/                  Deep-dive protocol specs
  uninc.yml.example      Config reference
```

## Rust workspace

### Build everything

```bash
cargo build --release
```

Produces three binaries in `target/release/`:

- `uninc-proxy` — the multi-protocol proxy
- `chain-engine` — the NATS consumer that writes chain entries
- `uninc` — the operator CLI
- `uninc-observer` — Observer binary for the multi-VM topology (feature-gated)

### Run tests

```bash
# Entire workspace
cargo test --workspace --lib

# A single crate
cargo test -p uninc-common --lib
cargo test -p uninc-proxy  --lib
cargo test -p chain-engine --lib
cargo test -p verification --lib
cargo test -p observer     --lib
```

### Run the proxy locally

```bash
# 1. Start the dependencies (NATS + upstream DBs) from Docker
docker compose -f docker/docker-compose.yml up -d nats postgres mongodb minio

# 2. Configure
cp uninc.yml.example uninc.yml
export UNINC_CONFIG=uninc.yml

# 3. Run
cargo run -p uninc-proxy
```

The proxy binds the following ports — hard-coded, not configurable. See [ARCHITECTURE.md §"Proxy listen ports are hard-coded"](ARCHITECTURE.md#proxy-listen-ports-are-hard-coded-not-config-driven) for the reasoning behind the "+1000 shift."

| Port  | Protocol                                                      |
|-------|---------------------------------------------------------------|
| 6432  | PostgreSQL wire                                               |
| 28017 | MongoDB wire                                                  |
| 10000 | S3 HTTP                                                       |
| 9090  | Health check (`/health`, `/health/ready`, `/health/detailed`) |
| 9091  | Chain API — the read surface for any frontend                 |

### Run the chain engine

```bash
export NATS_URL=nats://localhost:4222
export CHAIN_STORAGE_PATH=/tmp/chains
export CHAIN_SERVER_SALT=dev-salt

cargo run -p chain-engine
```

### Use the CLI

```bash
export CHAIN_STORAGE_PATH=/tmp/chains
export CHAIN_SERVER_SALT=dev-salt

# Verify one user's chain
cargo run -p cli -- verify --user user_42

# Verify every chain on disk
cargo run -p cli -- verify --all

# Export a chain as JSON
cargo run -p cli -- export --user user_42 --format json

# System status
cargo run -p cli -- status
```

## Reading chain data

There is no separate UI container. Chain data is always read over the proxy's `:9091` HTTP chain API. Three normal consumers:

- **Any HTTP client** — `curl http://localhost:9091/api/v1/chain/_deployment/entries`
- **The browser WASM verifier** (`crates/chain-verifier-wasm/`) — the same Rust hash code compiled to WebAssembly, runs in the end user's browser so the server cannot fake a passing result
- **A frontend you write** — any UI that speaks HTTP + WebAssembly can point at `{proxyIp}:9091` and render the chain client-side

See [docs/chain-api.md](docs/chain-api.md) for the endpoint contract.

## Docker (self-host)

All commands below assume the repo root (`server/`) as the working directory.

### Greenfield — full stack, everything on your laptop

```bash
cp .env.example .env
# Edit .env with your passwords

docker compose -f docker/docker-compose.yml up -d
```

Starts proxy + chain-engine + nats + postgres + mongodb + minio + redis. All configured via environment variables and `uninc.yml`.

External endpoints on `localhost`:

- Postgres via proxy:  `:6432`
- MongoDB via proxy:   `:28017`
- S3 via proxy:        `:10000`
- Chain API:           `:9091`
- Health:              `:9090`

### Drop-in — proxy in front of a database you already run

```bash
UPSTREAM_POSTGRES=postgres://user:pass@your-db:5432/mydb \
  docker compose -f docker/docker-compose.self-hosted.yml up -d
```

Adds the proxy + chain engine + NATS next to your existing database. One connection-string change on the app side (`:5432` → `:6432`).

### Multi-VM role — add the Observer

```bash
docker compose -f docker/docker-compose.observer.yml up -d
```

Only relevant if you're running the multi-VM replica topology. See [ARCHITECTURE.md §"Observer VM"](ARCHITECTURE.md#component-5-the-observer-vm-multi-vm-topology-only).

## Cloud deployment (GCP)

```bash
cd deploy/gcp/examples/gcp-full
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars

terraform init
terraform plan
terraform apply
```

Creates a multi-VM topology: 1 proxy VM (public) + 3 DB VMs (private, no SSH, no public IP) + 1 Observer VM. See [deploy/README.md](deploy/README.md).

## Configuration

All runtime configuration lives in `uninc.yml`. `uninc.yml.example` is the full reference — copy it and edit.

Key sections:

| Section | What it configures |
|---|---|
| `proxy.postgres/mongodb/s3` | Upstream addresses, pools, timeouts, rate limits |
| `proxy.identity` | Admin vs app credential classification |
| `proxy.schema` | Which tables hold user data, user-ID columns |
| `proxy.nats` | NATS URL, subject prefix |
| `chain` | Storage path, shard size, salt, keystore, LRU cache |
| `verification` | Replica list, drand entropy, nightly (T3) schedule, failure handler chain (multi-VM only) |

Proxy **listen** ports (`6432/28017/10000/9090/9091`) are NOT in `uninc.yml` — they're hard-coded Rust constants. Upstream (dial-target) ports are config-driven.

## Questions / contributions

File an issue or PR at <https://github.com/uninc-app/server>. The AGPLv3 license requires that modifications to a running service are published — this is deliberate (the code is the trust anchor).
