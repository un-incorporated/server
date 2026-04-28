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

# Boot orchestration — runs the per-deployment startup-script metadata
# at every boot, with output captured to syslog/serial/file. Replaces
# google-startup-scripts.service from the GCP guest-agent we don't
# install. See files/common/uninc-boot.{service,sh} for rationale.
install -m 0755 /tmp/uninc-common/uninc-boot.sh        /opt/uninc/uninc-boot.sh
install -m 0644 /tmp/uninc-common/uninc-boot.service   /etc/systemd/system/uninc-boot.service
systemctl enable uninc-boot.service

# Docker log driver = journald so `docker compose up` / container
# stdout flows through journald → Cloud Ops Agent → Cloud Logging.
# Default `json-file` writes to /var/lib/docker/containers/*.log which
# Ops Agent doesn't tail by default — meaning a failed compose stack
# would be invisible from the mothership. The `tag` keeps each
# container's output queryable separately.
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'DOCKERD'
{
  "log-driver": "journald",
  "log-opts": {
    "tag": "{{.Name}}"
  }
}
DOCKERD

# Substitute the version pin into the compose file at build time so
# every running container references the same tag the image was built
# from. Avoids a separate env-var indirection at boot.
sed -i "s/__UNINC_VERSION__/${UNINC_VERSION}/g" /opt/uninc/docker-compose.yml

# ── Seal the image: no SSH on customer VMs ───────────────────
# The proxy VM is a sealed compute unit. Once running, neither the
# customer nor the operator who deployed it should be able to log in
# and mutate the proxy binary, the chain on disk, or any other byte —
# that's the transparency guarantee. Debug surfaces are limited by
# design to the GCE serial console and Cloud Logging; if a class of
# failure can't be diagnosed from those, the fix is more
# instrumentation in the next release tag, not poking at running
# state.
#
# We deliberately do NOT `apt purge openssh-server` here, because
# Packer's own SSH session is what's running this script — purging
# the package mid-build would kill the session before shutdown_command
# can fire. Instead, we make sshd unable to function on customer VMs
# by removing every prerequisite: host keys, authorized_keys, login-
# capable users, and the systemd unit's enable state. The binary is
# still on disk, but it has no keys to present, no users to admit,
# and no unit to start it. That's cryptographically equivalent to
# "no SSH" without breaking the build.
#
# Removed:
#   - host keys: sshd refuses to start without them
#   - /root/.ssh and any authorized_keys
#   - packer user + home: created by cidata for the build, never
#     belongs in a customer image (carrying packer:packer would be
#     a ridiculous credential leak)
#   - debian default user: shipped by Debian's generic cloud image,
#     and cloud-init seeds an .ssh directory there at first boot
#   - sshd enable state: masked so a fresh-boot sshd never starts
rm -rf /etc/ssh/ssh_host_* /root/.ssh
systemctl disable ssh.service ssh.socket 2>/dev/null || true
systemctl mask ssh.service ssh.socket 2>/dev/null || true
# Empty sshd_config so even if someone unmasks the unit, there's no
# AllowUsers/PasswordAuth/PubkeyAuth that'd let them in.
echo "# sealed image — sshd intentionally non-functional" > /etc/ssh/sshd_config
chmod 0644 /etc/ssh/sshd_config

# NOTE: `userdel -f packer` and `userdel -f debian` are NOT done here.
# Packer's `shutdown_command` opens a fresh SSH session as the packer
# user; deleting it now would 401 the shutdown and Packer would time
# out after 5 minutes. The user deletion is moved into
# `shutdown_command` itself (see *.pkr.hcl) so it happens AS the VM
# is powering off — by the time anyone could exploit the credential,
# the VM is gone. /home/packer and /home/debian are likewise wiped
# from the same shutdown_command.

# ── Cleanup so the snapshot is small + reproducible ──────────
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/uninc-files /tmp/uninc-common /root/.bash_history
# Reset machine-id so cloned VMs get a fresh one at first boot.
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

echo "install-proxy.sh: image baked for ${UNINC_VERSION} (sealed: no sshd)"
