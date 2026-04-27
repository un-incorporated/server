# Builds `uninc-proxy-${version}` GCE image from Debian 12 base.
#
# Usage (from server repo root):
#   packer init deploy/gcp/images/proxy.pkr.hcl
#   packer build -var "version=v0.1.3" -var "project_id=lore-agent-memory" \
#     deploy/gcp/images/proxy.pkr.hcl
#
# The release-images.yml workflow runs this on every `v*.*.*` tag.
# Output: a new image in `image_family: uninc-proxy` with name
# `uninc-proxy-vX.Y.Z`. Customer VMs boot from
# `family: uninc-proxy` (latest) or pin a specific name.

packer {
  required_plugins {
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = "~> 1.1"
    }
  }
}

variable "version" {
  type        = string
  description = "Release tag, e.g. v0.1.3. Must start with v and match semver."
}

variable "project_id" {
  type        = string
  description = "GCP project to publish the image into."
}

variable "zone" {
  type    = string
  default = "us-east4-a"
}

# Strip the leading `v` for the image-name component (GCE rejects
# names starting with a digit-after-dash collision pattern in some
# spots; sticking to the convention `uninc-proxy-vX-Y-Z` is safer).
locals {
  image_name = "uninc-proxy-${replace(var.version, ".", "-")}"
}

source "googlecompute" "proxy" {
  project_id              = var.project_id
  zone                    = var.zone
  source_image_family     = "debian-12"
  source_image_project_id = ["debian-cloud"]
  ssh_username            = "packer"
  machine_type            = "e2-medium"

  # Output image — published into the same project that consumes it.
  image_name        = local.image_name
  image_family      = "uninc-proxy"
  image_description = "uninc-proxy runtime image, baked from ${var.version}"
  image_labels = {
    managed-by   = "packer"
    app          = "unincorporated"
    role         = "proxy"
    uninc-version = replace(var.version, ".", "-")
  }
}

build {
  sources = ["source.googlecompute.proxy"]

  # Stage static files into the builder VM at /tmp/uninc-files where
  # install-proxy.sh expects them.
  provisioner "file" {
    source      = "${path.root}/files/proxy/"
    destination = "/tmp/uninc-files/"
  }

  provisioner "shell" {
    environment_vars = ["UNINC_VERSION=${var.version}"]
    execute_command  = "chmod +x {{ .Path }}; sudo -E bash {{ .Path }}"
    script           = "${path.root}/install-proxy.sh"
  }
}
