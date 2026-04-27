# GCE image build (Packer)

Per-role GCE images for the proxy / db / observer VMs. Published per
release by [`.github/workflows/release-images.yml`](../../../.github/workflows/release-images.yml)
on every `v*.*.*` git tag.

## Why per-role GCE images at all

The DB and observer VMs run on the private subnet with no public IP
and (intentionally) no Cloud NAT. Without internet egress, they can't
`apt-get install postgres` or `docker pull` the observer container at
first boot. The proxy VM has a public IP and *could* install
on-the-fly, but doing so means two customer VMs created a week apart
silently get different glibc patch levels and different pgbouncer
micro-versions — drift the rest of the stack (chain, observer,
transparency proofs) is trying to eliminate.

Baking the runtime into a per-role image:

- **Eliminates internet egress at runtime.** Customer VMs can't reach
  apt mirrors or container registries even if they wanted to —
  enforced by the topology, not by trust.
- **Gives the protocol a single attestable runtime artifact** per
  release. Same trust shape as the container images, applied to the
  entire VM. Future-you can publish the image hash alongside the proxy
  version and let customers verify their VM was built from the exact
  source you released.
- **Makes first boot deterministic and fast.** No apt, no docker pull
  — just metadata read, config render, `docker compose up -d` against
  locally-cached images. Boots in seconds.

## What's in each image

| Role | Pre-installed | Pre-pulled images |
|---|---|---|
| `uninc-proxy` | Cloud Ops Agent, Docker (official APT repo) | `proxy:vX.Y.Z`, `nats:2.10-alpine`, `edoburu/pgbouncer:1.22.1-p0`, `caddy:2.8-alpine` |
| `uninc-db` | Cloud Ops Agent, Postgres 16 (PGDG), MongoDB 8.0, Docker | `minio/minio:latest`, `minio/mc:latest` |
| `uninc-observer` | Cloud Ops Agent, Docker | `observer:vX.Y.Z` |

Plus per-role static configs baked at known paths — the docker-compose
YAML, the NATS conf, the Caddyfile template, the Caddy sync timer +
script. The compose YAML's image tag is rewritten by the install
script from `__UNINC_VERSION__` to the release tag, so the GCE image
hash and the container image tag move in lockstep through one release.

Per-deployment values (secrets, db host, observer URL, custom domain
upstream) are NEVER in the image. They reach the VM at boot via GCE
instance metadata and are written into `/etc/uninc/proxy.yml`,
`/opt/uninc/.env`, `/opt/uninc/pgbouncer/pgbouncer.ini` etc. by the
deployment-time startup script (`deploy/gcp/modules/uninc-server/startup-proxy.sh`).

## Layout

```
deploy/gcp/images/
├── proxy.pkr.hcl       Packer config for uninc-proxy
├── db.pkr.hcl          Packer config for uninc-db
├── observer.pkr.hcl    Packer config for uninc-observer
├── install-proxy.sh    Build-time provisioning (apt + docker pull)
├── install-db.sh       Build-time provisioning
├── install-observer.sh Build-time provisioning
└── files/
    ├── proxy/          Static files baked into uninc-proxy
    │   ├── docker-compose.yml
    │   ├── nats.conf
    │   ├── Caddyfile.template
    │   ├── sync-caddy.sh
    │   ├── caddy-sync.service
    │   └── caddy-sync.timer
    └── observer/
        └── docker-compose.yml
```

`uninc-db` doesn't carry static files today — Postgres + Mongo configs
are wholly per-deployment and rendered at boot by `startup-db.sh`. If
a future change needs deployment-agnostic config there, add `files/db/`.

## Building locally

```bash
# One-time
packer init deploy/gcp/images/proxy.pkr.hcl

# Build a single image (proxy / db / observer same shape)
packer build \
  -var "version=v0.1.3" \
  -var "project_id=${GCP_PROJECT}" \
  deploy/gcp/images/proxy.pkr.hcl
```

Building locally needs `gcloud auth application-default login` and
the same IAM as the CI service account (`roles/compute.instanceAdmin.v1`,
`roles/iam.serviceAccountUser`).

## Release flow

Tag-push triggers all three image builds in parallel via
`release-images.yml`. After the workflow goes green:

1. Bump the GCE image version pin in
   [`www/core/services/provisioning/config.ts`](https://github.com/un-incorporated/www/blob/main/core/services/provisioning/config.ts)
   (`UNINC_GCE_IMAGE_VERSION`) — same shape as the existing
   `UNINC_PROXY_IMAGE` / `UNINC_OBSERVER_IMAGE` pins.
2. Commit the bump in `www`. New deployments boot from the new
   images; existing VMs keep running their pinned image until
   re-provisioned.

The container-image tag pins (`UNINC_PROXY_IMAGE` /
`UNINC_OBSERVER_IMAGE`) are still bumped in lockstep — the GCE image
embeds the same tag in its baked compose YAML, so version skew between
the GCE image and the compose tag is impossible by construction.
