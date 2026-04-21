# ── Proxy VM ─────────────────────────────────────────────────────

resource "google_compute_instance" "proxy" {
  name         = "${local.name_prefix}-proxy"
  machine_type = var.proxy_machine_type
  zone         = var.zone
  tags         = ["uninc-proxy"]
  labels       = local.labels

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
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
    proxy_image     = var.proxy_image
    db_host         = google_compute_instance.db[0].network_interface[0].network_ip
    db_port         = "5432"
    db_name         = var.db_name
    db_user         = var.db_user
    db_password     = var.db_password
    jwt_secret      = var.jwt_secret
    databases       = var.databases
    mongo_password  = var.mongo_password
  })

  service_account {
    scopes = ["cloud-platform"]
  }

  allow_stopping_for_update = true
}
