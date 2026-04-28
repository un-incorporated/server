#!/bin/bash
# install-db.sh
#
# Image-build time provisioning for the uninc-db GCE image. Runs once
# inside Packer's builder VM. Boot-time on customer VMs is config-only.
#
# Installs Postgres 16, MongoDB 8.0, Docker (for chain-MinIO + customer
# MinIO), and pre-pulls minio. Customer DB VMs live on the private
# subnet with no public IP and (intentionally) no Cloud NAT, so no
# install or pull can run at first boot — everything must be in the
# image.
set -euxo pipefail

: "${UNINC_VERSION:?UNINC_VERSION must be set (e.g. v0.1.3)}"

# ── GCE guest environment ─────────────────────────────────────
# We boot from cloud.debian.org's generic Debian 12 image, which has
# zero GCE-specific bits. Without google-guest-agent installed, the VM
# silently ignores the `startup-script` instance metadata key. Source:
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
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
bash add-google-cloud-ops-agent-repo.sh --also-install
rm -f add-google-cloud-ops-agent-repo.sh

# ── Base + Postgres 16 (PGDG repo) ────────────────────────────
apt-get update
apt-get install -y --no-install-recommends \
   ca-certificates curl gnupg lsb-release
echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
   > /etc/apt/sources.list.d/pgdg.list
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
   | gpg --dearmor -o /etc/apt/trusted.gpg.d/pgdg.gpg
apt-get update
apt-get install -y --no-install-recommends postgresql-16

# Postgres is enabled but stopped — startup-db.sh writes the per-
# deployment postgresql.conf + pg_hba.conf, then starts it.
systemctl disable postgresql
systemctl stop postgresql || true

# ── MongoDB 8.0 (only included if role=db, all DB images carry it) ──
# We carry mongod in every db image because the same image serves
# postgres-only AND postgres+mongodb deployments — boot-time decides
# whether to start mongod by reading the `databases` metadata key.
# An "I never run mongo" customer pays ~200MB of extra disk; the
# alternative (separate uninc-db-pg, uninc-db-pg-mongo, ...) explodes
# the image matrix.
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc \
   | gpg --dearmor -o /etc/apt/trusted.gpg.d/mongodb-server-8.0.gpg
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" \
   > /etc/apt/sources.list.d/mongodb-org-8.0.list
apt-get update
apt-get install -y --no-install-recommends mongodb-org
systemctl disable mongod
systemctl stop mongod || true

# ── Docker (for chain-MinIO + optional customer MinIO) ────────
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

# ── Pre-pull MinIO ────────────────────────────────────────────
docker pull minio/minio:latest
docker pull minio/mc:latest

# ── Static, deployment-agnostic config skeleton ───────────────
mkdir -p /opt/uninc /data/chain-storage
chmod 0755 /opt/uninc

# ── Cleanup ────────────────────────────────────────────────────
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/uninc-files /root/.bash_history
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

echo "install-db.sh: image baked for ${UNINC_VERSION}"
