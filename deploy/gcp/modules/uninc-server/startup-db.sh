#!/bin/bash
set -e

# ── Install PostgreSQL 16 ───────────────────────────────────────
apt-get update
apt-get install -y gnupg2 lsb-release
echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
  > /etc/apt/sources.list.d/pgdg.list
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/pgdg.gpg
apt-get update
apt-get install -y postgresql-16

# ── Disable SSH (DB VMs have no public IP; belt-and-suspenders) ─
systemctl disable ssh
systemctl stop ssh

# ── Configure PostgreSQL ─────────────────────────────────────────
PG_CONF="/etc/postgresql/16/main/postgresql.conf"
PG_HBA="/etc/postgresql/16/main/pg_hba.conf"

# Listen on all interfaces (only reachable via VPC)
sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" "$PG_CONF"

# WAL settings for replication
cat >> "$PG_CONF" <<PGCONF
wal_level = logical
max_replication_slots = 10
max_wal_senders = 10
wal_keep_size = 256MB
hot_standby = on
PGCONF

# ── Capacity & overload backstops ───────────────────────────────
# See ARCHITECTURE.md §"Capacity & overload protection" — these are Layer 4,
# the "proxy's defenses failed" backstop. The proxy (Layer 1) should never
# let traffic reach max_connections, but Postgres enforces a hard ceiling
# regardless. The statement_timeout matches the proxy's item-B default.
#
# Sizing rule: max_connections = pgbouncer default_pool_size (25) + admin
# headroom (15) = 40. Raise for bigger VMs in a future revision.
MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
SHARED_BUFFERS_KB=$((MEM_KB / 4))
SHARED_BUFFERS_MB=$((SHARED_BUFFERS_KB / 1024))
cat >> "$PG_CONF" <<PGCONF
max_connections = 40
statement_timeout = 30000
idle_in_transaction_session_timeout = 600000
shared_buffers = ${SHARED_BUFFERS_MB}MB
work_mem = 4MB
log_min_duration_statement = 1000
PGCONF

# Allow replication connections from the private subnet
cat >> "$PG_HBA" <<HBA
# Replication — private subnet only
host    replication     ${db_user}    10.0.2.0/24    scram-sha-256
host    all             ${db_user}    10.0.2.0/24    scram-sha-256
host    all             all           10.0.1.0/24    scram-sha-256
HBA

if [ "${is_primary}" = "true" ]; then
  # ── Primary: create database and user ──────────────────────────
  systemctl restart postgresql

  sudo -u postgres psql -c "CREATE USER ${db_user} WITH PASSWORD '${db_password}' REPLICATION SUPERUSER;"
  sudo -u postgres psql -c "CREATE DATABASE ${db_name} OWNER ${db_user};"
  sudo -u postgres psql -d ${db_name} -c "CREATE PUBLICATION uninc_observer_pub FOR ALL TABLES;"
else
  # ── Replica: base backup from primary ──────────────────────────
  systemctl stop postgresql

  rm -rf /var/lib/postgresql/16/main/*
  sudo -u postgres pg_basebackup \
    -h ${primary_ip} \
    -U ${db_user} \
    -D /var/lib/postgresql/16/main \
    -Fp -Xs -R -P

  systemctl start postgresql
fi

# ── chain-MinIO for the multi-VM durable chain tier ──────────────
# Every replica VM (primary included) runs a MinIO container at :9002
# that holds the uninc-chain bucket for quorum-replicated chain data.
# The proxy's chain-engine writes via MultiReplicaStorage. :9002 is
# chosen to sit adjacent to MinIO's :9000/:9001 family without colliding
# with the customer MinIO console (:9001) or Prometheus node_exporter
# (:9100). See docs/chain-storage-architecture.md.
apt-get install -y docker.io
systemctl enable --now docker

# Create a persistent data directory for the chain MinIO.
mkdir -p /data/chain-minio
chown -R 1000:1000 /data/chain-minio

# Pull and run minio. Bind to 0.0.0.0:9002 so the proxy can reach it;
# the firewall rule limits source tags to uninc-proxy only.
docker pull minio/minio:latest
docker rm -f chain-minio 2>/dev/null || true
docker run -d \
  --name chain-minio \
  --restart always \
  -p 9002:9000 \
  -e MINIO_ROOT_USER='${chain_minio_access_key}' \
  -e MINIO_ROOT_PASSWORD='${chain_minio_secret_key}' \
  -v /data/chain-minio:/data \
  minio/minio:latest server /data

# Wait for it to come up, then create the bucket.
for i in $(seq 1 20); do
  if curl -sf http://localhost:9002/minio/health/live > /dev/null; then
    break
  fi
  sleep 1
done

docker run --rm --network host \
  -e MC_HOST_replica="http://${chain_minio_access_key}:${chain_minio_secret_key}@localhost:9002" \
  minio/mc:latest mb --ignore-existing replica/uninc-chain || true

# ── MongoDB 8.0 (if selected) ──────────────────────────────────
%{ if contains(databases, "mongodb") }
curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/mongodb-server-8.0.gpg
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" \
  > /etc/apt/sources.list.d/mongodb-org-8.0.list
apt-get update
apt-get install -y mongodb-org

# Inter-replica auth keyFile
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

# ── Customer MinIO (if selected) ───────────────────────────────
# Separate from chain-MinIO (:9002). Customer S3 on :9000, console on :9001.
%{ if contains(databases, "s3") }
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
