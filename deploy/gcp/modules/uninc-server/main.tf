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

  # Resolve the per-role baked image source. Images are imported into
  # this same project on first deploy of each release tag (see the
  # mothership's image-import.ts, or run `gcloud compute images create
  # uninc-{role}-vX-Y-Z --source-uri=gs://...` yourself before
  # `terraform apply`). Pinning to a specific image name follows the
  # same shape as pinning a container tag instead of `:latest` — empty
  # `gce_image_version` falls back to the image_family head, convenient
  # for self-hosters tracking HEAD.
  gce_image_suffix  = replace(var.gce_image_version, ".", "-")

  proxy_image_id    = var.gce_image_version != "" ? "projects/${var.project_id}/global/images/uninc-proxy-${local.gce_image_suffix}" : "projects/${var.project_id}/global/images/family/uninc-proxy"
  db_image_id       = var.gce_image_version != "" ? "projects/${var.project_id}/global/images/uninc-db-${local.gce_image_suffix}" : "projects/${var.project_id}/global/images/family/uninc-db"
  observer_image_id = var.gce_image_version != "" ? "projects/${var.project_id}/global/images/uninc-observer-${local.gce_image_suffix}" : "projects/${var.project_id}/global/images/family/uninc-observer"
}
