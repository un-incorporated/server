# ── VPC ───────────────────────────────────────────────────────────

resource "google_compute_network" "vpc" {
  name                    = "${local.name_prefix}-vpc"
  auto_create_subnetworks = false
  project                 = var.project_id
}

# ── Subnets ──────────────────────────────────────────────────────

resource "google_compute_subnetwork" "public" {
  name          = "${local.name_prefix}-public"
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.vpc.id
}

resource "google_compute_subnetwork" "private" {
  name                     = "${local.name_prefix}-private"
  ip_cidr_range            = "10.0.2.0/24"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  private_ip_google_access = true
}

# ── Firewall Rules ───────────────────────────────────────────────

# 1. Allow external traffic to proxy on protocol ports + metrics + chain API
resource "google_compute_firewall" "allow_proxy_ingress" {
  name    = "${local.name_prefix}-allow-proxy-ingress"
  network = google_compute_network.vpc.id

  # Proxy external listen ports — the "+1000 shift" documented in
  # LOCAL-DEV.md §"Why the proxy is on :6432". These are hard-coded into
  # the Rust binary (server/crates/uninc-common/src/config.rs via the
  # PROXY_*_PORT constants) so external clients always connect to these
  # specific numbers. The primitive VMs below listen on the native
  # 5432/27017/9000 internally — those ports are private-subnet only.
  #
  # :9091 (chain API) is JWT-gated and externally reachable so the
  # browser WASM verifier can fetch chain entries directly. See
  # docs/chain-storage-architecture.md.
  #
  # There is NO :9092 metering API on the proxy — metering runs in www
  # by polling the GCE API directly (control-plane metering).
  allow {
    protocol = "tcp"
    ports    = ["6432", "28017", "10000", "9090", "9091"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["uninc-proxy"]
}

# 2. Allow admin SSH to proxy VM only
resource "google_compute_firewall" "allow_admin_ssh" {
  name    = "${local.name_prefix}-allow-admin-ssh"
  network = google_compute_network.vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = [var.admin_ssh_cidr]
  target_tags   = ["uninc-proxy"]
}

# 3. Allow proxy to reach database VMs on primitive ports
# All three primitive ports open; services only listen if the customer selected the primitive.
resource "google_compute_firewall" "allow_proxy_to_db" {
  name    = "${local.name_prefix}-allow-proxy-to-db"
  network = google_compute_network.vpc.id
  priority = 900

  allow {
    protocol = "tcp"
    ports    = ["5432", "27017", "9000"]
  }

  source_tags = ["uninc-proxy"]
  target_tags = ["uninc-db"]
}

# 3b. Allow proxy to reach each replica's chain-MinIO on port 9002.
# This is the multi-VM durable chain storage tier: each replica VM runs a
# MinIO container exposing the uninc-chain bucket (prefixes chains/user/
# and chains/_deployment/). chain-engine on the proxy writes via
# MultiReplicaStorage quorum fan-out. :9002 sits adjacent to the MinIO
# :9000/:9001 family without colliding with the MinIO console (:9001) or
# Prometheus node_exporter (:9100). See docs/chain-storage-architecture.md
# for the full design.
resource "google_compute_firewall" "allow_proxy_to_replica_chain_storage" {
  name    = "${local.name_prefix}-allow-proxy-to-chain-minio"
  network = google_compute_network.vpc.id
  priority = 900

  allow {
    protocol = "tcp"
    ports    = ["9002"]
  }

  source_tags = ["uninc-proxy"]
  target_tags = ["uninc-db"]
}

# 4. Deny all other traffic to database VMs
resource "google_compute_firewall" "deny_all_to_db" {
  name    = "${local.name_prefix}-deny-all-to-db"
  network = google_compute_network.vpc.id
  priority = 1000

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["uninc-db"]
}
