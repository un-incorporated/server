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

# Boot orchestration — see files/common/uninc-boot.{service,sh}.
install -m 0755 /tmp/uninc-common/uninc-boot.sh        /opt/uninc/uninc-boot.sh
install -m 0644 /tmp/uninc-common/uninc-boot.service   /etc/systemd/system/uninc-boot.service
systemctl enable uninc-boot.service

# Docker journald log driver so the observer container stdout reaches
# Cloud Logging via Ops Agent. See install-proxy.sh for rationale.
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
# `apt purge openssh-server`. The observer is the independent witness
# against proxy-side tampering — if the observer VM itself is mutable
# via SSH, an attacker who compromises BOTH proxy AND observer breaks
# the cross-replica verification guarantee in spec §5.5. So no shell
# here either.
rm -rf /etc/ssh/ssh_host_* /root/.ssh /home/packer /home/debian
userdel -f packer 2>/dev/null || true
userdel -f debian 2>/dev/null || true
systemctl disable ssh.service ssh.socket 2>/dev/null || true
systemctl mask ssh.service ssh.socket 2>/dev/null || true
echo "# sealed image — sshd intentionally non-functional" > /etc/ssh/sshd_config
chmod 0644 /etc/ssh/sshd_config

# ── Cleanup ────────────────────────────────────────────────────
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/uninc-files /tmp/uninc-common /root/.bash_history
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

echo "install-observer.sh: image baked for ${UNINC_VERSION} (sealed: no sshd)"
