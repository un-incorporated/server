# Builds a portable qcow2 disk image for the uninc-observer VM, then
# converts it to disk.raw + tar.gz for GCE import. Same shape as
# proxy.pkr.hcl — see that file for the qemu/cloud-init rationale.

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
  image_name = "uninc-observer-${replace(var.version, ".", "-")}"
}

source "qemu" "observer" {
  iso_url          = var.base_image_url
  iso_checksum     = var.base_image_checksum
  disk_image       = true
  format           = "qcow2"
  output_directory = "build/observer"
  vm_name          = "${local.image_name}.qcow2"

  cpus      = 2
  memory    = 2048
  disk_size = "8G"

  cd_label = "cidata"
  cd_files = [
    "${path.root}/cidata/user-data",
    "${path.root}/cidata/meta-data",
  ]

  ssh_username     = "packer"
  ssh_password     = "packer"
  ssh_timeout      = "10m"
  shutdown_command = "echo packer | sudo -S shutdown -h now"

  headless    = true
  accelerator = "kvm"
}

build {
  sources = ["source.qemu.observer"]

  # See proxy.pkr.hcl for why we mkdir before the file upload.
  provisioner "shell" {
    inline = ["mkdir -p /tmp/uninc-files"]
  }

  provisioner "file" {
    source      = "${path.root}/files/observer/"
    destination = "/tmp/uninc-files/"
  }

  # See proxy.pkr.hcl for why we use `sudo env {{.Vars}}` instead of
  # `sudo -E`.
  provisioner "shell" {
    environment_vars = ["UNINC_VERSION=${var.version}"]
    execute_command  = "chmod +x {{ .Path }}; sudo env {{ .Vars }} bash '{{ .Path }}'"
    script           = "${path.root}/install-observer.sh"
  }

  post-processor "shell-local" {
    inline = [
      "set -euxo pipefail",
      "cd build/observer",
      "qemu-img convert -f qcow2 -O raw ${local.image_name}.qcow2 disk.raw",
      "tar -czf ${local.image_name}.tar.gz disk.raw",
      "rm -f disk.raw",
      "echo 'wrote build/observer/${local.image_name}.tar.gz'",
    ]
  }
}
