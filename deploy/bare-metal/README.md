# Bare-metal deploy recipe (placeholder)

**Not yet written as a step-by-step, but the core is just "run Docker Compose."** This README explains how to bring up the Unincorporated server stack on a single Linux host you already own — your own VM, a Hetzner dedicated, a Raspberry Pi, a NUC under your desk, or an EC2 instance you don't want to wrap in Terraform.

## Prerequisites

- Any Linux distro with Docker 20.10+ and Docker Compose v2
- 4 GB RAM minimum (8 GB recommended if running all three primitives + replicas)
- 50 GB disk for `/data/chains` (more if you expect heavy chain write volume)
- A public IP or tunnel (Cloudflare Tunnel, Tailscale, ngrok — whatever reaches your host from where your customers' apps run)
- A way to hold `JWT_SECRET` — a `.env` file or your favorite secret store

## Quick start

```bash
git clone https://github.com/uninc-app/server.git
cd server

# Generate a JWT secret into .env
echo "JWT_SECRET=$(openssl rand -base64 64)" > .env

# Bring up the stack
docker compose -f docker/docker-compose.self-hosted.yml up -d

# Check it's up
curl http://localhost:9090/health
# → { "status": "ok", ... }
```

Ports your app will reach:

| Port | Protocol | What it is |
|---|---|---|
| `6432` | TCP | Postgres wire (the proxy intercepts and logs, then forwards to Postgres on `:5432` internally) |
| `28017` | TCP | MongoDB wire |
| `10000` | HTTP | S3 wire (MinIO-compatible) |
| `9090` | HTTP | `/health` (public, harmless) |
| `9091` | HTTP | `/api/v1/chain/*` — JWT-gated chain read API |

Open these in your host firewall (`ufw allow 6432`, etc.) so your application tier can reach them.

## What you get vs. what you don't

**You get:** the full transparency proxy. Every DB query goes through it, gets logged into a per-user append-only chain in `/data/chains/`, and is readable via the chain API. Your users can verify their own audit trail via any frontend that speaks `:9091` and loads the WASM verifier — the chain data is yours, on your host.

**You don't get:**
- **Cross-replica verification** (that requires the 3/5/7 replica topology from [`../gcp/`](../gcp/)). Single-host means you trust a single set of bytes — no divergence detection, no quorum. Fine for dev, small prod, and "just want the audit log" use cases.
- **Auto-provisioning** (you brought your own host; there's no provisioning layer).
- **Custom-domain TLS** (terminate TLS yourself via Caddy / nginx / Cloudflare in front of the ports).
- **A turnkey transparency UI** — `server/` ships no frontend; you build one against the `:9091` chain API or use a managed viewer.

## Scaling up

When a single host isn't enough:

- **Horizontally for the data layer** → move the DB primitives onto separate hosts, then follow the [GCP recipe](../gcp/) as a template for network topology (proxy VM + replica VMs in separate subnets).
- **Horizontally for the app layer** → your app scales independently; it just needs to reach the proxy on `:6432/:28017/:10000`. The proxy is the bottleneck, not the DB primitives.

## Docs

- [`../../../ARCHITECTURE.md`](../../../ARCHITECTURE.md) — the full hop-by-hop data path.
- [`../../crates/proxy/`](../../crates/proxy/) — proxy source.
- [`../../docs/proxy-implementation.md`](../../docs/proxy-implementation.md) — protocol interception details.
