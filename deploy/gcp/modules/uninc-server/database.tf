# ── Database VMs ─────────────────────────────────────────────────

resource "google_compute_instance" "db" {
  count        = var.replica_count
  name         = "${local.name_prefix}-db-${count.index}"
  machine_type = var.db_machine_type
  zone         = var.zone
  tags         = ["uninc-db"]
  labels       = local.labels

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 50
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
    # No access_config — no public IP
  }

  metadata_startup_script = templatefile("${path.module}/startup-db.sh", {
    db_name                = var.db_name
    db_user                = var.db_user
    db_password            = var.db_password
    is_primary             = count.index == 0
    primary_ip             = count.index == 0 ? "" : google_compute_instance.db[0].network_interface[0].network_ip
    replica_index          = count.index
    chain_minio_access_key = var.chain_minio_access_key
    chain_minio_secret_key = var.chain_minio_secret_key
    databases                 = var.databases
    mongo_password            = var.mongo_password
    customer_minio_access_key = var.customer_minio_access_key
    customer_minio_secret_key = var.customer_minio_secret_key
  })

  service_account {
    scopes = ["cloud-platform"]
  }

  allow_stopping_for_update = true
}
