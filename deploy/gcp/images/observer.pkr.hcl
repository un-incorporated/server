# Builds `uninc-observer-${version}` GCE image from Debian 12 base.

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
  image_name = "uninc-observer-${replace(var.version, ".", "-")}"
}

source "googlecompute" "observer" {
  project_id              = var.project_id
  zone                    = var.zone
  source_image_family     = "debian-12"
  source_image_project_id = ["debian-cloud"]
  ssh_username            = "packer"
  machine_type            = "e2-small"

  image_name        = local.image_name
  image_family      = "uninc-observer"
  image_description = "uninc-observer runtime image, baked from ${var.version}"
  image_labels = {
    managed-by    = "packer"
    app           = "unincorporated"
    role          = "observer"
    uninc-version = replace(var.version, ".", "-")
  }
}

build {
  sources = ["source.googlecompute.observer"]

  provisioner "file" {
    source      = "${path.root}/files/observer/"
    destination = "/tmp/uninc-files/"
  }

  provisioner "shell" {
    environment_vars = ["UNINC_VERSION=${var.version}"]
    execute_command  = "chmod +x {{ .Path }}; sudo -E bash {{ .Path }}"
    script           = "${path.root}/install-observer.sh"
  }
}
