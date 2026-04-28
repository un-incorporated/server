#!/bin/bash
# install-proxy.sh
#
# Image-build time provisioning for the uninc-proxy GCE image. Runs once
# inside Packer's builder VM, then the image is snapshotted and shipped.
# Boot-time on customer VMs is config-only — see startup-proxy.sh.
#
# Everything that needs internet egress lives here so customer VMs can
# stay on their private subnet with NO Cloud NAT and STILL come up
# deterministically: every byte runs from the image's read-only layer,
# nothing is fetched from a Debian mirror or Docker registry at first
# boot.
#
# `set -euxo pipefail` so any failure aborts the image build cleanly —
# we don't want to publish an image where docker pull silently failed.
set -euxo pipefail

# Image-tag pin baked in at build time. Both Packer (proxy.pkr.hcl) and
# the release workflow (release-images.yml) pass UNINC_VERSION as a
# user-var. Compose YAML bakes this same string, so the running image
# and the docker-compose tag are guaranteed to agree — no version drift.
: "${UNINC_VERSION:?UNINC_VERSION must be set (e.g. v0.1.3)}"

# ── GCE guest environment ─────────────────────────────────────
# We boot from cloud.debian.org's generic Debian 12 image, which has
# zero GCE-specific bits. Without google-guest-agent installed, the VM
# silently ignores the `startup-script` instance metadata key — the
# script is set, the metadata server serves it, but nothing on the VM
# polls for it. The agent also wires SSH key sync, IP forwarding, and
# the account daemon. Source:
#   https://github.com/GoogleCloudPlatform/guest-agent
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
   | gpg --dearmor -o /etc/apt/keyrings/cloud.google.gpg
echo "deb [signed-by=/etc/apt/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt google-compute-engine-bookworm-stable main" \
   > /etc/apt/sources.list.d/google-compute-engine.list
apt-get update
apt-get install -y --no-install-recommends \
   google-compute-engine google-guest-agent google-osconfig-agent
systemctl enable google-guest-agent.service google-startup-scripts.service \
   google-shutdown-scripts.service google-osconfig-agent.service

# ── Cloud Ops Agent ────────────────────────────────────────────
# Ships memory / disk / process metrics + tails journald → Cloud
# Logging. Without it, the GCE-only metrics surface is CPU-only and
# `docker logs` from container stdout never reach Cloud Logging.
# Source: https://github.com/GoogleCloudPlatform/ops-agent
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
bash add-google-cloud-ops-agent-repo.sh --also-install
rm -f add-google-cloud-ops-agent-repo.sh

# ── Docker (official APT repo) ────────────────────────────────
# Bookworm's default repos do not carry `docker-compose-plugin`; the
# only reliable source is Docker's own APT repo. We could hand-fetch
# the docker.io binary off Debian's mirror plus a standalone compose
# binary off GitHub Releases, but pinning to one source keeps the
# upgrade story simple.
apt-get update
apt-get install -y --no-install-recommends \
   ca-certificates curl gnupg lsb-release
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
   | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release; echo "$VERSION_CODENAME") stable" \
   > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y --no-install-recommends \
   docker-ce docker-ce-cli containerd.io \
   docker-buildx-plugin docker-compose-plugin
systemctl enable docker

# ── Pre-pull every container the proxy stack runs ─────────────
# After this point the proxy VM never needs to reach a registry —
# `docker compose up -d` finds every layer in the local image
# cache. Each tag is pinned (no `:latest`) so the image hash and
# the container image hash move in lockstep through one release.
docker pull "ghcr.io/un-incorporated/proxy:${UNINC_VERSION}"
docker pull nats:2.10-alpine
docker pull edoburu/pgbouncer:1.22.1-p0
docker pull caddy:2.8-alpine

# ── Static, deployment-agnostic config ────────────────────────
# Bake every file that is byte-identical across deployments. Per-
# deployment files (proxy.yml with secrets, pgbouncer.ini with the
# DB host, the per-deployment Caddy upstream) are written at boot
# by startup-proxy.sh from GCE instance metadata.
mkdir -p /opt/uninc/config /opt/uninc/pgbouncer /etc/caddy /etc/uninc
chmod 0755 /opt/uninc /etc/caddy /etc/uninc

install -m 0644 /tmp/uninc-files/nats.conf            /opt/uninc/config/nats.conf
install -m 0644 /tmp/uninc-files/docker-compose.yml   /opt/uninc/docker-compose.yml
install -m 0644 /tmp/uninc-files/Caddyfile.template   /etc/caddy/Caddyfile.template
install -m 0755 /tmp/uninc-files/sync-caddy.sh        /opt/uninc/sync-caddy.sh
install -m 0644 /tmp/uninc-files/caddy-sync.service   /etc/systemd/system/caddy-sync.service
install -m 0644 /tmp/uninc-files/caddy-sync.timer     /etc/systemd/system/caddy-sync.timer

# Substitute the version pin into the compose file at build time so
# every running container references the same tag the image was built
# from. Avoids a separate env-var indirection at boot.
sed -i "s/__UNINC_VERSION__/${UNINC_VERSION}/g" /opt/uninc/docker-compose.yml

# ── Cleanup so the snapshot is small + reproducible ──────────
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/uninc-files /root/.bash_history
# Reset machine-id so cloned VMs get a fresh one at first boot.
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

echo "install-proxy.sh: image baked for ${UNINC_VERSION}"
