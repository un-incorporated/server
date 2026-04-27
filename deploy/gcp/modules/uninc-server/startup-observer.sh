#!/bin/bash
set -e

# Observer VM startup. Mirrors the www-side observer provisioning flow at
# www/core/services/provisioning/phases/infra/startup-scripts.ts so the
# standalone TF path stays feature-identical to the mothership path. If
# either side changes, update both.

# ── Install Docker (Docker official APT repo) ──────────────────
# Bookworm's default repos don't carry docker-compose-plugin; this
# block adds Docker's official repo so we can install docker-ce and
# the v2 compose plugin used by `docker compose up -d` below.
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release; echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable docker
systemctl start docker

# Observer has no public IP, but disable SSH anyway as belt-and-suspenders.
systemctl disable ssh 2>/dev/null || true
systemctl stop ssh 2>/dev/null || true

docker pull ${observer_image}

mkdir -p /etc/uninc /opt/uninc

# Observer config — shape matches server/crates/observer/src/config.rs
# ObserverConfig. Per-primitive blocks are emitted only when the deployment
# actually uses that primitive.
cat > /etc/uninc/observer.yml <<OBSEOF
deployment_id: "${deployment_id}"
chain_storage_path: /data/observer-chains
http_port: 2026
read_secret: "${observer_read_secret}"
%{ if contains(split(",", databases), "postgres") ~}
postgres:
  host: "${db_primary_ip}"
  port: 5432
  user: "${db_user}"
  password: "${db_password}"
  database: "${db_name}"
  publication: "uninc_observer_pub"
  replication_slot: "uninc_observer_${substr(deployment_id, 0, 8)}"
%{ endif ~}
%{ if contains(split(",", databases), "mongodb") ~}
mongodb:
  uri: "mongodb://${db_user}:${db_password}@${db_primary_ip}:27017/admin"
%{ endif ~}
%{ if contains(split(",", databases), "s3") ~}
minio:
  nats_url: "nats://${nats_ip}:4222"
  subject: "uninc.observer.minio"
%{ endif ~}
OBSEOF
chmod 600 /etc/uninc/observer.yml

cat > /opt/uninc/docker-compose.yml <<COMPOSEEOF
services:
  uninc-observer:
    image: ${observer_image}
    restart: unless-stopped
    ports:
      - "2026:2026"
    environment:
      RUST_LOG: info
      CHAIN_SERVER_SALT: "${deployment_salt}"
      OBSERVER_CONFIG: /etc/uninc/observer.yml
    volumes:
      - /etc/uninc/observer.yml:/etc/uninc/observer.yml:ro
      - observer-chains:/data/observer-chains
    healthcheck:
      test: ["CMD", "wget", "-q", "-O-", "http://localhost:2026/health"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  observer-chains:
COMPOSEEOF

cd /opt/uninc
docker compose up -d
