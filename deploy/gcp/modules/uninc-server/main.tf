terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

locals {
  name_prefix = "uninc"
  labels = {
    managed-by = "terraform"
    app        = "unincorporated"
  }

  # Resolve the GCE image source per role. If gce_image_version is set,
  # we pin to a specific image name (`uninc-{role}-vX-Y-Z`) for full
  # determinism — same shape as pinning a container tag instead of
  # tracking `:latest`. If unset, fall back to the image_family head,
  # which is convenient for self-hosters who track HEAD but means
  # `terraform apply` could pick up a new image silently.
  gce_image_project = var.gce_image_project != "" ? var.gce_image_project : var.project_id
  gce_image_suffix  = replace(var.gce_image_version, ".", "-")

  proxy_image_id = var.gce_image_version != "" ? "projects/${local.gce_image_project}/global/images/uninc-proxy-${local.gce_image_suffix}" : "projects/${local.gce_image_project}/global/images/family/uninc-proxy"
  db_image_id    = var.gce_image_version != "" ? "projects/${local.gce_image_project}/global/images/uninc-db-${local.gce_image_suffix}" : "projects/${local.gce_image_project}/global/images/family/uninc-db"
  observer_image_id = var.gce_image_version != "" ? "projects/${local.gce_image_project}/global/images/uninc-observer-${local.gce_image_suffix}" : "projects/${local.gce_image_project}/global/images/family/uninc-observer"
}
