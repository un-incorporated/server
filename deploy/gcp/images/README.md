# Per-role baked disk images (Packer)

Per-role bootable disk images for the proxy / db / observer VMs.
Published per release by [`.github/workflows/release-images.yml`](../../../.github/workflows/release-images.yml)
on every `v*.*.*` git tag.

## Why per-role baked images at all

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
  release. The `disk.raw` is hosted on GitHub Releases and hashable by
  anyone — same trust shape as the container images, applied to the
  entire VM.
- **Makes first boot deterministic and fast.** No apt, no docker pull
  — just metadata read, config render, `docker compose up -d` against
  locally-cached images.

## Distribution: GitHub Releases, not a cloud-vendor registry

Each release tag publishes three GitHub Release assets:

| Asset | ~Size | Contents |
|---|---|---|
| `uninc-proxy-vX-Y-Z.tar.gz` | ~1 GB | `disk.raw` |
| `uninc-db-vX-Y-Z.tar.gz` | ~1.5 GB | `disk.raw` |
| `uninc-observer-vX-Y-Z.tar.gz` | ~900 MB | `disk.raw` |

Format: each tar.gz contains a single bootable `disk.raw`. That's
exactly the shape `gcloud compute images create --source-uri=gs://...`
accepts, and it boots directly under qemu/KVM/Proxmox after a
`tar -xzf` and `qemu-img convert -f raw -O qcow2`. The same artifact
serves the managed `unincorporated.app` deployment path and a
self-hoster running on their own datacenter.

No GCP image-host project. No cloud-vendor secrets in CI. The image
artifact lives on GitHub until a customer's mothership lazy-imports it
into its own GCP project on first deploy of each release tag (see
`www/core/services/provisioning/phases/infra/image-import.ts`).

## What's in each image

| Role | Pre-installed | Pre-pulled images |
|---|---|---|
| `uninc-proxy` | Cloud Ops Agent, Docker (official APT repo) | `proxy:vX.Y.Z`, `nats:2.10-alpine`, `edoburu/pgbouncer:1.22.1-p0`, `caddy:2.8-alpine` |
| `uninc-db` | Cloud Ops Agent, Postgres 16 (PGDG), MongoDB 8.0, Docker | `minio/minio:latest`, `minio/mc:latest` |
| `uninc-observer` | Cloud Ops Agent, Docker | `observer:vX.Y.Z` |

Plus per-role static configs baked at known paths — the docker-compose
YAML, the NATS conf, the Caddyfile template, the Caddy sync timer +
script. The compose YAML's image tag is rewritten by the install
script from `__UNINC_VERSION__` to the release tag, so the image hash
and the container image tag move in lockstep through one release.

Per-deployment values (secrets, db host, observer URL, custom domain
upstream) are NEVER in the image. They reach the VM at boot via GCE
instance metadata and are written into `/etc/uninc/proxy.yml`,
`/opt/uninc/.env`, `/opt/uninc/pgbouncer/pgbouncer.ini` etc. by the
deployment-time startup script (`deploy/gcp/modules/uninc-server/startup-proxy.sh`).

## Layout

```
deploy/gcp/images/
├── proxy.pkr.hcl       Packer config for uninc-proxy (qemu builder)
├── db.pkr.hcl          Packer config for uninc-db
├── observer.pkr.hcl    Packer config for uninc-observer
├── install-proxy.sh    Build-time provisioning (apt + docker pull)
├── install-db.sh       Build-time provisioning
├── install-observer.sh Build-time provisioning
├── cidata/
│   ├── meta-data       Cloud-init seed for the qemu build VM
│   └── user-data       (creates a `packer` user with sudo)
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
# One-time (downloads the qemu plugin)
packer init deploy/gcp/images/proxy.pkr.hcl

# Build a single image (proxy / db / observer same shape)
packer build -var "version=v0.1.3" deploy/gcp/images/proxy.pkr.hcl

# Output: deploy/gcp/images/build/proxy/uninc-proxy-v0-1-3.tar.gz
```

Building locally needs `qemu-system-x86_64` + `qemu-img` installed and
`/dev/kvm` accessible (Linux). On macOS, Packer's qemu builder falls
back to TCG (software emulation) — works, just slow.

No GCP credentials needed. The Debian 12 cloud base image is
downloaded over HTTPS from `cloud.debian.org`.

## Using a published image

The artifact is a tar.gz of a `disk.raw`. Two consumption paths:

### On GCE (the managed-service path)

The `un-incorporated/www` provisioning worker imports automatically on
first deploy of each release tag — see
[`image-import.ts`](https://github.com/un-incorporated/www/blob/main/core/services/provisioning/phases/infra/image-import.ts).

Manual import (e.g. for a self-hoster running their own GCP project):

```bash
# Download and stage in your project's GCS bucket
curl -L -o uninc-proxy.tar.gz \
   https://github.com/un-incorporated/server/releases/download/v0.1.3/uninc-proxy-v0-1-3.tar.gz
gsutil cp uninc-proxy.tar.gz gs://YOUR_BUCKET/uninc-proxy-v0-1-3.tar.gz

# Create the GCE image
gcloud compute images create uninc-proxy-v0-1-3 \
   --source-uri=gs://YOUR_BUCKET/uninc-proxy-v0-1-3.tar.gz \
   --family=uninc-proxy \
   --project=$YOUR_PROJECT
```

After import, the Terraform module's
`local.proxy_image_id = projects/$YOUR_PROJECT/global/images/uninc-proxy-v0-1-3`
references the imported image directly.

### On bare KVM / Proxmox / your own datacenter

```bash
curl -L -o uninc-proxy.tar.gz \
   https://github.com/un-incorporated/server/releases/download/v0.1.3/uninc-proxy-v0-1-3.tar.gz
tar -xzf uninc-proxy.tar.gz                # extracts disk.raw
qemu-img convert -f raw -O qcow2 disk.raw uninc-proxy.qcow2

# Boot under qemu (cloud-init seed required for first-boot user setup)
qemu-system-x86_64 -m 2048 -drive file=uninc-proxy.qcow2,format=qcow2 ...
```

The image is cloud-init aware — it'll consume metadata from a cidata
ISO or the standard cloud-init datasources. Hand it the same
metadata keys the GCE-side startup script expects
(see `deploy/gcp/modules/uninc-server/startup-proxy.sh` for the
template-vars list) and the proxy stack comes up identically.

## Release flow

Tag-push triggers all three image builds in parallel via
`release-images.yml`. After the workflow goes green and the three
tar.gz files are attached to the GitHub Release:

1. Bump the GCE image version pin in
   [`www/core/services/provisioning/config.ts`](https://github.com/un-incorporated/www/blob/main/core/services/provisioning/config.ts)
   via `npm run www:bump-images -- vX.Y.Z`. This sets
   `UNINC_GCE_IMAGE_VERSION` defaulted to the new tag.
2. Commit the bump in `www`. New deployments call `ensureAllImages`
   on the new tag — first deploy pays a one-time per-role import,
   subsequent deploys reuse the imported image. Existing VMs keep
   running their pinned image until re-provisioned.
