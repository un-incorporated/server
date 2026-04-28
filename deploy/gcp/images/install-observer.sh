#!/bin/bash
# install-observer.sh
#
# Image-build time provisioning for the uninc-observer GCE image.
# Runs once inside Packer's builder VM. Boot-time on customer VMs is
# config-only.
#
# The observer VM lives on the private subnet with no public IP and
# (intentionally) no Cloud NAT — every byte must be in the image.
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

# ── Docker (official APT repo) ────────────────────────────────
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

# ── Pre-pull observer ─────────────────────────────────────────
docker pull "ghcr.io/un-incorporated/observer:${UNINC_VERSION}"

# ── Static, deployment-agnostic config skeleton ───────────────
mkdir -p /opt/uninc /etc/uninc
chmod 0755 /opt/uninc /etc/uninc

install -m 0644 /tmp/uninc-files/docker-compose.yml /opt/uninc/docker-compose.yml
sed -i "s/__UNINC_VERSION__/${UNINC_VERSION}/g" /opt/uninc/docker-compose.yml

# ── Cleanup ────────────────────────────────────────────────────
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/uninc-files /root/.bash_history
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

echo "install-observer.sh: image baked for ${UNINC_VERSION}"
