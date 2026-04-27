# Builds `uninc-db-${version}` GCE image from Debian 12 base.
# Carries Postgres 16, MongoDB 8.0, Docker, MinIO image — boot decides
# which to start based on the `databases` GCE metadata key.

packer {
  required_plugins {
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = "~> 1.1"
    }
  }
}

variable "version" {
  type = string
}

variable "project_id" {
  type = string
}

variable "zone" {
  type    = string
  default = "us-east4-a"
}

locals {
  image_name = "uninc-db-${replace(var.version, ".", "-")}"
}

source "googlecompute" "db" {
  project_id              = var.project_id
  zone                    = var.zone
  source_image_family     = "debian-12"
  source_image_project_id = ["debian-cloud"]
  ssh_username            = "packer"
  # Slightly larger machine than runtime — Postgres + Mongo install
  # benefit from the extra cores during package configuration. Image
  # output is independent of build machine_type.
  machine_type = "e2-standard-2"

  image_name        = local.image_name
  image_family      = "uninc-db"
  image_description = "uninc-db runtime image (postgres + mongo + docker + minio), baked from ${var.version}"
  image_labels = {
    managed-by    = "packer"
    app           = "unincorporated"
    role          = "db"
    uninc-version = replace(var.version, ".", "-")
  }
}

build {
  sources = ["source.googlecompute.db"]

  provisioner "shell" {
    environment_vars = ["UNINC_VERSION=${var.version}"]
    execute_command  = "chmod +x {{ .Path }}; sudo -E bash {{ .Path }}"
    script           = "${path.root}/install-db.sh"
  }
}
