#!/bin/bash
set -e

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

# ── Pull images ──────────────────────────────────────────────────
docker pull ${proxy_image}
docker pull nats:2.10-alpine
# PgBouncer sidecar for Postgres connection pooling — item A.2 of the
# round-1 overload-protection plan. See ARCHITECTURE.md §"Capacity & overload
# protection" for the role. The repo is `edoburu/pgbouncer` (no `m`)
# and tags are suffixed `-pN` (patch level), so `1.22.1-p0` not `1.22.1`.
docker pull edoburu/pgbouncer:1.22.1-p0

# ── Create NATS config ──────────────────────────────────────────
mkdir -p /opt/uninc/config
cat > /opt/uninc/config/nats.conf <<'NATSEOF'
port: 4222
jetstream {
    store_dir: /data/nats
    max_mem: 64M
    max_file: 1G
}
NATSEOF

# ── Create PgBouncer config ─────────────────────────────────────
# Item A.2: sidecar in front of the real Postgres on the replica VMs,
# transaction-pooling mode. Listens on 127.0.0.1:6433 on the proxy VM
# (loopback-only, localhost-only) — uninc-proxy forwards Postgres-wire
# traffic to it after the audit gate passes.
#
# Port 6433, NOT 6432: the Rust uninc-proxy listens on 0.0.0.0:6432
# externally (the canonical Postgres proxy port per the "+1000 shift"
# in LOCAL-DEV.md), so pgbouncer lives one port over to avoid a collision
# on `network_mode: host`.
#
# The real Postgres backend is on the private subnet at \${db_host}:\${db_port}.
# PgBouncer is the ONLY thing in this VPC that can reach those VMs on port
# 5432 (enforced by the firewall rule in network.tf), so the pgbouncer →
# postgres hop is also the only ingress to the data layer.
mkdir -p /opt/uninc/pgbouncer
cat > /opt/uninc/pgbouncer/pgbouncer.ini <<PGBCONF
[databases]
${db_name} = host=${db_host} port=${db_port} dbname=${db_name}

[pgbouncer]
listen_addr = 127.0.0.1
listen_port = 6433
unix_socket_dir =

auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt

pool_mode = transaction
max_client_conn = 200
default_pool_size = 25
reserve_pool_size = 5
reserve_pool_timeout = 3
query_wait_timeout = 5

server_lifetime = 3600
server_idle_timeout = 600
server_connect_timeout = 10
query_timeout = 30

admin_users = ${db_user}
stats_users = ${db_user}
log_connections = 1
log_disconnections = 1
log_pooler_errors = 1
ignore_startup_parameters = application_name,extra_float_digits,options
server_reset_query = DISCARD ALL
PGBCONF

# userlist.txt — PgBouncer reads credentials from here. For scram-sha-256,
# the second column should be the SCRAM secret. Postgres stores these in
# pg_shadow; we retrieve it from the primary DB VM once it's reachable.
# Until then, fall back to md5 (legacy but functional) using the plaintext
# password from Terraform variables. This is inside the proxy trust boundary
# so cleartext-at-rest in this file is acceptable for v1 — rotate along with
# db_password rotation.
cat > /opt/uninc/pgbouncer/userlist.txt <<USERLIST
"${db_user}" "${db_password}"
USERLIST
chmod 600 /opt/uninc/pgbouncer/userlist.txt

# ── Create Docker Compose file ──────────────────────────────────
cat > /opt/uninc/docker-compose.yml <<COMPOSEEOF
services:
  # All services share host networking so the proxy/chain-engine reach
  # NATS via 127.0.0.1:4222 (the URL baked into proxy.yml). Without
  # host_mode on NATS, bridge-mode NATS would only be reachable via the
  # bridge gateway IP or service DNS, neither of which the proxy
  # resolves to.
  nats:
    image: nats:2.10-alpine
    restart: unless-stopped
    network_mode: host
    volumes:
      - /opt/uninc/config/nats.conf:/etc/nats/nats.conf:ro
    command: ["-c", "/etc/nats/nats.conf"]

  # Item A.2: PgBouncer sidecar. Transaction-pooling Postgres reuse.
  # See ARCHITECTURE.md §"Capacity & overload protection" layer 2.
  pgbouncer:
    image: edoburu/pgbouncer:1.22.1-p0
    restart: unless-stopped
    network_mode: host
    volumes:
      - /opt/uninc/pgbouncer/pgbouncer.ini:/etc/pgbouncer/pgbouncer.ini:ro
      - /opt/uninc/pgbouncer/userlist.txt:/etc/pgbouncer/userlist.txt:ro
    # Auth is scram but the entrypoint writes plaintext to userlist.txt;
    # pgbouncer hashes it on load with auth_type=scram-sha-256. First run
    # may retry while the primary DB finishes bootstrapping.

  proxy:
    image: ${proxy_image}
    restart: unless-stopped
    network_mode: host
    environment:
      RUST_LOG: info
      # Point at the LOCAL pgbouncer (item A.2), not the remote db_host.
      # PgBouncer listens on loopback-only :6433 so it doesn't collide
      # with the uninc-proxy's own 0.0.0.0:6432 external listener.
      POSTGRES_UPSTREAM: "postgres://${db_user}:${db_password}@127.0.0.1:6433/${db_name}"
      NATS_URL: "nats://127.0.0.1:4222"
      JWT_SECRET: "${jwt_secret}"
      CHAIN_SERVER_SALT: "${deployment_salt}"
      CHAIN_STREAM: "uninc.access"
%{ if contains(databases, "mongodb") }      MONGO_UPSTREAM: "mongodb://${db_user}:${mongo_password}@${db_host}:27017/admin?replicaSet=uninc-rs"%{ endif }
%{ if contains(databases, "s3") }      S3_UPSTREAM: "http://${db_host}:9000"%{ endif }
    depends_on:
      - nats
      - pgbouncer

  chain-engine:
    image: ${proxy_image}
    restart: unless-stopped
    network_mode: host
    entrypoint: ["chain-engine"]
    environment:
      RUST_LOG: info
      NATS_URL: "nats://127.0.0.1:4222"
      CHAIN_SERVER_SALT: "${deployment_salt}"
      CHAIN_STREAM: "uninc.access"
    depends_on:
      - nats
COMPOSEEOF

# ── Start services ──────────────────────────────────────────────
cd /opt/uninc
docker compose up -d
