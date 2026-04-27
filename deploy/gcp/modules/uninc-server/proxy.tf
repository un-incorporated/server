# ── Proxy VM ─────────────────────────────────────────────────────
#
# Boots from the per-role uninc-proxy GCE image (built by
# deploy/gcp/images/proxy.pkr.hcl) so Docker, all container images,
# and the static compose stack are already on disk. The startup
# script renders per-deployment configs and runs `docker compose up`.
# No apt, no docker pull at boot — see deploy/gcp/images/README.md
# for the rationale.

resource "google_compute_address" "observer_internal" {
  name         = "${local.name_prefix}-observer-ip"
  region       = var.region
  subnetwork   = google_compute_subnetwork.private.id
  address_type = "INTERNAL"
  address      = "10.0.2.100"
  purpose      = "GCE_ENDPOINT"
}

resource "google_compute_instance" "proxy" {
  name         = "${local.name_prefix}-proxy"
  machine_type = var.proxy_machine_type
  zone         = var.zone
  tags         = ["uninc-proxy"]
  labels       = local.labels

  boot_disk {
    initialize_params {
      image = local.proxy_image_id
      size  = 30
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.public.id

    # External IP for ingress
    access_config {}
  }

  metadata_startup_script = templatefile("${path.module}/startup-proxy.sh", {
    db_host              = google_compute_instance.db[0].network_interface[0].network_ip
    db_port              = "5432"
    db_name              = var.db_name
    db_user              = var.db_user
    db_password          = var.db_password
    jwt_secret           = var.jwt_secret
    deployment_salt      = var.deployment_salt
    databases            = var.databases
    mongo_password       = var.mongo_password
    observer_internal_ip = google_compute_address.observer_internal.address
    observer_read_secret = var.observer_read_secret
    admin_email          = var.admin_email
    ask_url_with_secret  = var.ask_url_with_secret
  })

  service_account {
    scopes = ["cloud-platform"]
  }

  allow_stopping_for_update = true
}
