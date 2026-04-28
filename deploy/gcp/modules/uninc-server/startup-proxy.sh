#!/bin/bash
# startup-proxy.sh — runs on the proxy VM at every boot via
# uninc-boot.service. Output is already captured by the wrapper to
# syslog (→ Cloud Logging), /var/log/uninc-boot.log, and /dev/console
# (→ `gcloud compute instances get-serial-port-output`). All this
# script needs to do is emit phase markers so an operator can pick out
# where a boot succeeded or failed in the log stream.
#
# Config-only. Docker, the proxy/nats/pgbouncer/caddy images, and the
# static compose YAML/Caddy template are already on the disk — they
# were baked into the `uninc-proxy` GCE image at release time. See
# server/deploy/gcp/images/install-proxy.sh.
#
# No apt, no curl, no docker pull. The VM has no internet egress
# guarantee at boot.
set -euo pipefail

phase() { echo "[startup-proxy phase] $*"; }
trap 'phase "FAILED at line $LINENO with exit $?"' ERR

phase "begin"

# ── Per-deployment config from Terraform vars ──────────────────
phase "render-config"
mkdir -p /etc/uninc /opt/uninc/pgbouncer /etc/caddy /data/chains \
   /data/caddy /data/caddy-config

# proxy.yml — full Rust-side config (UnincConfig). Loaded by both
# uninc-proxy and chain-engine via UNINC_CONFIG=/etc/uninc/proxy.yml.
cat > /etc/uninc/proxy.yml <<PROXYYAML
proxy:
  postgres:
    enabled: true
    upstream: "postgres://${db_user}:${db_password}@127.0.0.1:6433/${db_name}"
    rate_limit:
      enabled: true
      per_ip_rps: 100
      per_ip_burst: 200
      per_credential_rps: 50
      per_credential_burst: 100
%{ if contains(databases, "mongodb") }  mongodb:
    enabled: true
    upstream: "mongodb://${db_user}:${mongo_password}@${db_host}:27017/admin?replicaSet=uninc-rs"
    rate_limit:
      enabled: true
      per_ip_rps: 100
      per_ip_burst: 200
      per_credential_rps: 50
      per_credential_burst: 100
%{ endif }%{ if contains(databases, "s3") }  s3:
    enabled: true
    upstream: "http://${db_host}:9000"
%{ endif }  nats:
    url: "nats://127.0.0.1:4222"
    subject_prefix: "uninc.access"
  identity:
    mode: "credential"
    admin_credentials: {}
    app_credentials: {}
  schema:
    user_tables: []
    user_collections: []
    excluded_tables: []
mode: greenfield
chain:
  storage_path: "/data/chains"
  shard_size: 10000
  server_salt: "${deployment_salt}"
verification:
  enabled: true
  observer_url: "http://${observer_internal_ip}:2026"
  observer_read_secret: "${observer_read_secret}"
PROXYYAML
chmod 600 /etc/uninc/proxy.yml

# .env — env vars compose's env_file: pulls in for proxy + chain-engine.
cat > /opt/uninc/.env <<ENVEOF
JWT_SECRET=${jwt_secret}
CHAIN_SERVER_SALT=${deployment_salt}
ENVEOF
chmod 600 /opt/uninc/.env

# PgBouncer (sidecar in front of the real Postgres on the replica VMs).
# Same config as before the bake split.
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

cat > /opt/uninc/pgbouncer/userlist.txt <<USERLIST
"${db_user}" "${db_password}"
USERLIST
chmod 600 /opt/uninc/pgbouncer/userlist.txt

# Caddy — initial Caddyfile with a placeholder upstream (localhost:1
# guaranteed 502) so Caddy boots immediately. The sync-caddy.sh timer
# (baked into the image) re-renders the real upstream from GCE
# metadata once the caddyConfig phase pushes it.
echo '${admin_email}' > /etc/caddy/.email
echo '${ask_url_with_secret}' > /etc/caddy/.ask-url
chmod 600 /etc/caddy/.ask-url
sed -e "s#__CADDY_EMAIL__#${admin_email}#" \
    -e "s#__CADDY_ASK_URL__#${ask_url_with_secret}#" \
    -e "s#__CADDY_UPSTREAM__#localhost:1#" \
    /etc/caddy/Caddyfile.template > /etc/caddy/Caddyfile

phase "enable-caddy-sync"
# Activate the caddy-sync systemd timer (units already in /etc/systemd
# from the image bake).
systemctl daemon-reload
systemctl enable --now caddy-sync.timer

# ── Start the compose stack ────────────────────────────────────
# /opt/uninc/docker-compose.yml is already on disk from the image
# bake, with image tags rewritten to this release's UNINC_VERSION.
phase "compose-up"
cd /opt/uninc
docker compose up -d
phase "compose-up-done"

%{ if contains(databases, "mongodb") }
# rs.initiate after all DB VMs are up. mongosh ships in the mongo
# image we already pre-pulled (db tier), but on the proxy VM we don't
# carry it — exec into the proxy container's network namespace by
# running mongosh from a one-shot mongo container we DO carry on the
# db image. Since this is the proxy VM, fall back to a local exec via
# any DB VM the customer can reach. v1 uses the proxy image which
# does not include mongosh, so the rs.initiate is moved to the
# primary DB VM's startup-db.sh in the bake split.
%{ endif }

phase "done"
