# `server/docker/`

Build specs and orchestration for running the Uninc proxy, chain-engine, and observer as containers. Everything in this directory is for **self-hosted** users (shape #1 or #2 from the top-level [README](../README.md)).

If you're paying for a hosted deployment on [unincorporated.app](https://unincorporated.app), you don't touch any of this — the console generates the runtime config and mounts it into a managed proxy VM for you.

---

## Which compose file is for what

| File | Use |
|---|---|
| [docker-compose.yml](docker-compose.yml) | Single-host, batteries-included. Spins up proxy + chain-engine + NATS + Redis + upstream Postgres + MongoDB + MinIO all on one host. The quickstart path. |
| [docker-compose.self-hosted.yml](docker-compose.self-hosted.yml) | Drop-in deployment. Proxy + chain-engine + NATS + pgbouncer only. Points at Postgres / MongoDB / MinIO you already run elsewhere. |
| [docker-compose.observer.yml](docker-compose.observer.yml) | Observer VM only. Runs the independent subscriber process that reads the DB's own replication stream and maintains its own chain for cross-verification. Meant to sit on a separate VM from the proxy. |

## Subfolders

| Path | Contents |
|---|---|
| [proxy/](proxy/) | Dockerfile for the `uninc-proxy` binary (the wire-protocol proxy + `:9091` chain API). |
| [chain-engine/](chain-engine/) | Dockerfile for the `chain-engine` binary (NATS consumer that appends chain entries to disk). |
| [pgbouncer/](pgbouncer/) | PgBouncer config — transaction-pooling Postgres connection reuse in front of upstream Postgres. |
| [config/](config/) | NATS JetStream config, Postgres init SQL for local dev. |

---

## How `uninc.yml` fits in

`uninc.yml` is the proxy's **runtime config** — upstream URLs, identity rules (which Postgres roles are admin vs end-user), pool sizes, rate limits, chain storage path, server salt. The proxy reads it at startup from the path in the `UNINC_CONFIG` env var (defaults to `uninc.yml` in the working dir) — see [crates/proxy/src/main.rs:29](../crates/proxy/src/main.rs#L29).

Template: [../uninc.yml.example](../uninc.yml.example). Copy it to `uninc.yml` and edit, then mount it into the proxy service in your compose file (e.g. `volumes: ["./uninc.yml:/uninc.yml:ro"]`). The compose files in this directory currently drive the proxy via env vars only (`POSTGRES_UPSTREAM`, `JWT_SECRET`, etc.) and will fail at startup without a mounted `uninc.yml` — a mount is required for any real deployment.

It's **not** a Dockerfile and it's **not** a build spec. The container image is already built from `proxy/Dockerfile`; `uninc.yml` configures what the running binary does.

---

## Customer app Dockerfile — different layer

This directory is about the **proxy container**. If you're a customer asking "what Dockerfile should my app have so Cloud Build can deploy it behind the proxy?", that's a different layer. See [unincorporated.app/docs/dockerfile](https://unincorporated.app/docs/dockerfile) for templates (Next.js, Node, Python, Go).

---

## See also

- [../QUICKSTART.md](../QUICKSTART.md) — 5-minute Docker Compose walkthrough
- [../DEVELOPMENT.md](../DEVELOPMENT.md) — build and run from source
- [../ARCHITECTURE.md](../ARCHITECTURE.md) — runtime data paths and trust boundaries
