# ── Observer VM ──────────────────────────────────────────────────
#
# Independent replication-stream witness. Reads Postgres WAL, MongoDB change
# streams, and MinIO bucket notifications (via NATS) and writes
# ObservedDeploymentEvent entries to its own chain at /data/observer-chains.
# Exposes /entries and /head on :2026 for the proxy's verification task to
# entry-walk each Tick (spec §5.5.2 / Process 2).
#
# No public IP. Private subnet only. Reachable from the proxy VM service
# account only, per the firewall rules in network.tf.

resource "google_compute_instance" "observer" {
  name         = "${local.name_prefix}-observer"
  machine_type = var.observer_machine_type
  zone         = var.zone
  tags         = ["uninc-observer"]
  labels       = local.labels

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
    # No access_config block — no external IP.
  }

  metadata_startup_script = templatefile("${path.module}/startup-observer.sh", {
    observer_image        = var.observer_image
    deployment_id         = local.name_prefix
    deployment_salt       = var.deployment_salt
    db_primary_ip         = google_compute_instance.db[0].network_interface[0].network_ip
    db_user               = var.db_user
    db_password           = var.db_password
    db_name               = var.db_name
    observer_read_secret  = var.observer_read_secret
    databases             = join(",", var.databases)
    nats_ip               = google_compute_instance.proxy.network_interface[0].network_ip
  })

  service_account {
    scopes = ["cloud-platform"]
  }

  allow_stopping_for_update = true
}
