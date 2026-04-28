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

# Boot orchestration — see files/common/uninc-boot.{service,sh}.
install -m 0755 /tmp/uninc-common/uninc-boot.sh        /opt/uninc/uninc-boot.sh
install -m 0644 /tmp/uninc-common/uninc-boot.service   /etc/systemd/system/uninc-boot.service
systemctl enable uninc-boot.service

# Docker journald log driver so chain-MinIO + customer-MinIO container
# stdout reach Cloud Logging via Ops Agent. See install-proxy.sh for
# the rationale.
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'DOCKERD'
{
  "log-driver": "journald",
  "log-opts": {
    "tag": "{{.Name}}"
  }
}
DOCKERD

# ── Seal the image: no SSH on customer VMs ───────────────────
# See install-proxy.sh for the full rationale and the reason we don't
# `apt purge openssh-server` (would kill Packer's own SSH session).
# This DB image holds the chain-MinIO durability tier — exactly the
# data an operator with SSH would be tempted to mutate — so the
# sealing is non-negotiable here.
rm -rf /etc/ssh/ssh_host_* /root/.ssh
systemctl disable ssh.service ssh.socket 2>/dev/null || true
systemctl mask ssh.service ssh.socket 2>/dev/null || true
echo "# sealed image — sshd intentionally non-functional" > /etc/ssh/sshd_config
chmod 0644 /etc/ssh/sshd_config

# NOTE: see install-proxy.sh — userdel + /home wipe are deferred to
# `shutdown_command` so Packer's own shutdown SSH session works.

# ── Cleanup ────────────────────────────────────────────────────
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/uninc-files /tmp/uninc-common /root/.bash_history
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

echo "install-db.sh: image baked for ${UNINC_VERSION} (sealed: no sshd)"
