# Builds a portable qcow2 disk image for the uninc-db VM (Postgres 16
# + MongoDB 8.0 + Docker + MinIO image), then converts it to disk.raw
# + tar.gz for GCE import. Same shape as proxy.pkr.hcl — see that file
# for the rationale on cloud-init / qemu / disk.raw output.

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.1"
    }
  }
}

variable "version" {
  type = string
}

variable "base_image_url" {
  type    = string
  default = "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
}

variable "base_image_checksum" {
  type    = string
  default = "file:https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS"
}

locals {
  image_name = "uninc-db-${replace(var.version, ".", "-")}"
}

source "qemu" "db" {
  iso_url          = var.base_image_url
  iso_checksum     = var.base_image_checksum
  disk_image       = true
  format           = "qcow2"
  output_directory = "build/db"
  vm_name          = "${local.image_name}.qcow2"

  # Slightly larger build VM — Postgres + Mongo install benefits from
  # extra cores during package configuration. Output disk size is
  # independent of build resources.
  cpus      = 4
  memory    = 4096
  # 12G — Postgres + Mongo + Docker + MinIO image bake out to
  # ~3.5GB; 12G leaves headroom for the build's apt cache without
  # forcing the published image to be needlessly large (post-trim
  # below).
  disk_size = "12G"

  cd_label = "cidata"
  cd_files = [
    "${path.root}/cidata/user-data",
    "${path.root}/cidata/meta-data",
  ]

  ssh_username     = "packer"
  ssh_password     = "packer"
  ssh_timeout      = "15m"
  shutdown_command = "echo packer | sudo -S shutdown -h now"

  headless    = true
  accelerator = "kvm"
}

build {
  sources = ["source.qemu.db"]

  provisioner "shell" {
    environment_vars = ["UNINC_VERSION=${var.version}"]
    execute_command  = "chmod +x {{ .Path }}; sudo -E bash {{ .Path }}"
    script           = "${path.root}/install-db.sh"
  }

  post-processor "shell-local" {
    inline = [
      "set -euxo pipefail",
      "cd build/db",
      "qemu-img convert -f qcow2 -O raw ${local.image_name}.qcow2 disk.raw",
      "tar -czf ${local.image_name}.tar.gz disk.raw",
      "rm -f disk.raw",
      "echo 'wrote build/db/${local.image_name}.tar.gz'",
    ]
  }
}
