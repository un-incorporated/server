#!/bin/bash
# startup-observer.sh — runs on the observer VM at first boot.
#
# Config-only. Docker, the observer container, and the static compose
# YAML are already on the disk — they were baked into the
# `uninc-observer` GCE image at release time. See
# server/deploy/gcp/images/install-observer.sh.
#
# This script writes per-deployment observer.yml and starts compose.
# No apt, no docker pull. The observer VM has no public IP and no
# Cloud NAT — internet egress is not available.
set -euo pipefail

mkdir -p /etc/uninc /opt/uninc

cat > /etc/uninc/observer.yml <<OBSEOF
deployment_id: "${deployment_id}"
chain_storage_path: /data/observer-chains
http_port: 2026
read_secret: "${observer_read_secret}"
# MUST match the proxy's chain.server_salt — observer and proxy hash
# the same pre-hash actor identifier and the bytes have to agree.
deployment_salt: "${deployment_salt}"
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

cat > /opt/uninc/.env <<ENVEOF
CHAIN_SERVER_SALT=${deployment_salt}
ENVEOF
chmod 600 /opt/uninc/.env

# /opt/uninc/docker-compose.yml is already on disk from the image bake.
systemctl enable --now docker
cd /opt/uninc
docker compose up -d
