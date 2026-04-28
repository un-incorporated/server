#!/bin/bash
# startup-db.sh — runs on each DB VM at every boot via uninc-boot.sh.
# Output is captured by the wrapper to syslog/serial/file — see
# startup-proxy.sh for the rationale.
#
# Config-only. Postgres 16, MongoDB 8.0, Docker, and the MinIO image
# are already on the disk — they were baked into the `uninc-db` GCE
# image at release time. See server/deploy/gcp/images/install-db.sh.
#
# This script writes per-deployment Postgres/Mongo configs, creates
# users/databases, and starts chain-MinIO + optional customer MinIO
# via `docker run`. No apt, no docker pull. The DB VM lives on the
# private subnet with no public IP and no Cloud NAT — internet egress
# is not available.
set -euo pipefail

phase() { echo "[startup-db phase] $*"; }
trap 'phase "FAILED at line $LINENO with exit $?"' ERR

phase "begin"

# ── Postgres ──────────────────────────────────────────────────
phase "postgres-config"
PG_CONF="/etc/postgresql/16/main/postgresql.conf"
PG_HBA="/etc/postgresql/16/main/pg_hba.conf"

sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" "$PG_CONF"

cat >> "$PG_CONF" <<PGCONF
wal_level = logical
max_replication_slots = 10
max_wal_senders = 10
wal_keep_size = 256MB
hot_standby = on
PGCONF

# Capacity backstop — see ARCHITECTURE.md §"Capacity & overload protection".
MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
SHARED_BUFFERS_KB=$((MEM_KB / 4))
SHARED_BUFFERS_MB=$((SHARED_BUFFERS_KB / 1024))
cat >> "$PG_CONF" <<PGCONF
max_connections = 40
statement_timeout = 30000
idle_in_transaction_session_timeout = 600000
shared_buffers = $${SHARED_BUFFERS_MB}MB
work_mem = 4MB
log_min_duration_statement = 1000
PGCONF

cat >> "$PG_HBA" <<HBA
# Replication — private subnet only
host    replication     ${db_user}    10.0.2.0/24    scram-sha-256
host    all             ${db_user}    10.0.2.0/24    scram-sha-256
host    all             all           10.0.1.0/24    scram-sha-256
HBA

systemctl enable postgresql

if [ "${is_primary}" = "true" ]; then
   phase "postgres-init-primary"
   systemctl start postgresql
   sudo -u postgres psql -c "CREATE USER ${db_user} WITH PASSWORD '${db_password}' REPLICATION SUPERUSER;"
   sudo -u postgres psql -c "CREATE DATABASE ${db_name} OWNER ${db_user};"
   sudo -u postgres psql -d ${db_name} -c "CREATE PUBLICATION uninc_observer_pub FOR ALL TABLES;"
else
   phase "postgres-base-backup"
   # Replica — base-backup from primary
   rm -rf /var/lib/postgresql/16/main/*
   sudo -u postgres pg_basebackup \
      -h ${primary_ip} \
      -U ${db_user} \
      -D /var/lib/postgresql/16/main \
      -Fp -Xs -R -P
   systemctl start postgresql
fi

# ── chain-MinIO sidecar (every replica VM) ────────────────────
phase "chain-minio-up"
# Stores the uninc-chain bucket for quorum-replicated chain data via
# chain-engine's MultiReplicaStorage.
systemctl enable --now docker
mkdir -p /data/chain-minio
chown -R 1000:1000 /data/chain-minio

docker rm -f chain-minio 2>/dev/null || true
docker run -d \
  --name chain-minio \
  --restart always \
  -p 9002:9000 \
  -e MINIO_ROOT_USER='${chain_minio_access_key}' \
  -e MINIO_ROOT_PASSWORD='${chain_minio_secret_key}' \
  -v /data/chain-minio:/data \
  minio/minio:latest server /data

# Wait for MinIO, create the chain bucket.
for i in $(seq 1 20); do
   if curl -sf http://localhost:9002/minio/health/live > /dev/null; then break; fi
   sleep 1
done
docker run --rm --network host \
   -e MC_HOST_replica="http://${chain_minio_access_key}:${chain_minio_secret_key}@localhost:9002" \
   minio/mc:latest mb --ignore-existing replica/uninc-chain || true

# ── MongoDB (if selected) ────────────────────────────────────
%{ if contains(databases, "mongodb") }
phase "mongo-config"
echo "${mongo_password}" | openssl dgst -sha256 -binary | base64 > /etc/mongo-keyfile
chmod 400 /etc/mongo-keyfile
chown mongodb:mongodb /etc/mongo-keyfile

cat > /etc/mongod.conf <<MONGOCONF
storage:
  dbPath: /var/lib/mongodb
  wiredTiger:
    engineConfig:
      cacheSizeGB: $(awk '/MemTotal/ {printf "%.1f", $2/1024/1024/4}' /proc/meminfo)
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
net:
  port: 27017
  bindIp: 0.0.0.0
replication:
  replSetName: uninc-rs
security:
  authorization: enabled
  keyFile: /etc/mongo-keyfile
MONGOCONF

systemctl enable mongod
systemctl start mongod

%{ if is_primary }
sleep 5
mongosh --port 27017 --eval '
   db = db.getSiblingDB("admin");
   try {
      db.createUser({
         user: "${db_user}",
         pwd: "${mongo_password}",
         roles: [{ role: "root", db: "admin" }, { role: "clusterAdmin", db: "admin" }]
      });
   } catch(e) { if (e.codeName !== "DuplicateKey") throw e; }
'
%{ endif }
%{ endif }

# ── Customer MinIO (if selected) ──────────────────────────────
%{ if contains(databases, "s3") }
phase "customer-minio-up"
mkdir -p /data/customer-minio
docker rm -f customer-minio 2>/dev/null || true
docker run -d \
  --name customer-minio \
  --restart always \
  -p 9000:9000 \
  -e MINIO_ROOT_USER='${customer_minio_access_key}' \
  -e MINIO_ROOT_PASSWORD='${customer_minio_secret_key}' \
  -v /data/customer-minio:/data \
  minio/minio:latest server /data

%{ if is_primary }
sleep 5
for i in $(seq 1 20); do
   if curl -sf http://localhost:9000/minio/health/live > /dev/null; then break; fi
   sleep 1
done
docker run --rm --network host \
   -e MC_HOST_local="http://${customer_minio_access_key}:${customer_minio_secret_key}@localhost:9000" \
   minio/mc:latest mb --ignore-existing local/uploads || true
%{ endif }
%{ endif }

phase "done"
