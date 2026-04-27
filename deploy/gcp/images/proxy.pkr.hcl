# Builds a portable qcow2 disk image for the uninc-proxy VM, then
# converts it to the `disk.raw` + tar.gz layout that GCE's
# `gcloud compute images create --source-uri=` accepts. The artifact is
# uploaded to GitHub Releases by .github/workflows/release-images.yml
# — no GCP credentials are needed in CI, and the same artifact is
# downloadable by anyone running KVM/Proxmox/their own datacenter.
#
# Usage (from server repo root):
#   packer init deploy/gcp/images/proxy.pkr.hcl
#   packer build -var "version=v0.1.3" deploy/gcp/images/proxy.pkr.hcl
#
# Output: build/proxy/uninc-proxy-vX-Y-Z.tar.gz containing disk.raw,
# ready for `gcloud compute images create ... --source-uri=...` or for
# direct boot under qemu/KVM.

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.1"
    }
  }
}

variable "version" {
  type        = string
  description = "Release tag, e.g. v0.1.3. Must start with v and match semver."
}

# Debian 12 generic cloud image (qcow2, cloud-init aware). Boots clean
# under qemu without an installer, so the build is a few minutes
# instead of the 30+ a full ISO install would take. Pinned by SHA512
# because cloud.debian.org's `latest/` symlink moves and we want
# byte-identical builds.
variable "base_image_url" {
  type    = string
  default = "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
}

variable "base_image_checksum" {
  type    = string
  default = "file:https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS"
}

locals {
  # Image-name component — same shape as the ghcr.io tag. The tar.gz
  # the workflow uploads is named uninc-proxy-vX-Y-Z.tar.gz, and on
  # the consumer side the imported GCE image inherits this name.
  image_name = "uninc-proxy-${replace(var.version, ".", "-")}"
}

source "qemu" "proxy" {
  iso_url          = var.base_image_url
  iso_checksum     = var.base_image_checksum
  disk_image       = true
  format           = "qcow2"
  output_directory = "build/proxy"
  vm_name          = "${local.image_name}.qcow2"

  # Resources for the build VM. Build is short — the install script
  # apt-installs Docker + pulls four small container images.
  cpus      = 2
  memory    = 2048
  disk_size = "8G"

  # Debian's cloud image expects cloud-init data on a CD labelled
  # cidata. Packer assembles this ISO from the files in cidata/.
  cd_label = "cidata"
  cd_files = [
    "${path.root}/cidata/user-data",
    "${path.root}/cidata/meta-data",
  ]

  # SSH login — matches the user cloud-init creates. Packer SSHs in,
  # uploads files, runs the install script, then shuts the VM down.
  ssh_username     = "packer"
  ssh_password     = "packer"
  ssh_timeout      = "10m"
  shutdown_command = "echo packer | sudo -S shutdown -h now"

  # Headless: no display, KVM acceleration if /dev/kvm is available
  # (it is on GitHub-hosted Linux runners as of late 2024). Falls back
  # to TCG (software emulation, slower) if KVM is unavailable.
  headless = true
  accelerator = "kvm"
}

build {
  sources = ["source.qemu.proxy"]

  # Pre-create the destination — Packer's file provisioner with a
  # trailing-slash source uploads *contents* into an *existing* dir on
  # the target. A fresh Debian VM doesn't have /tmp/uninc-files/ yet,
  # so without this scp fails with "Is a directory" (which actually
  # means "the parent doesn't exist as a directory").
  provisioner "shell" {
    inline = ["mkdir -p /tmp/uninc-files"]
  }

  # Stage static files into the builder VM at /tmp/uninc-files where
  # install-proxy.sh expects them.
  provisioner "file" {
    source      = "${path.root}/files/proxy/"
    destination = "/tmp/uninc-files/"
  }

  # `sudo -E` doesn't preserve arbitrary environment variables under
  # Debian's default sudoers (env_reset + minimal env_keep whitelist),
  # so `environment_vars` set on this provisioner gets dropped by the
  # time install-proxy.sh runs. Workaround: invoke `env VAR=VAL bash`
  # under sudo — `env` sets them inline on its own command line, and
  # bash inherits them like any other process.
  provisioner "shell" {
    environment_vars = ["UNINC_VERSION=${var.version}"]
    execute_command  = "chmod +x {{ .Path }}; sudo env {{ .Vars }} bash '{{ .Path }}'"
    script           = "${path.root}/install-proxy.sh"
  }

  # Convert the qcow2 to the disk.raw + tar.gz layout GCE's image
  # import expects. `gcloud compute images create --source-uri=...`
  # consumes a tar.gz containing exactly one file named `disk.raw`.
  # The shell-local post-processor runs on the host, not inside the
  # build VM, so it has access to qemu-img + tar.
  post-processor "shell-local" {
    inline = [
      "set -eux",
      "cd build/proxy",
      "qemu-img convert -f qcow2 -O raw ${local.image_name}.qcow2 disk.raw",
      "tar -czf ${local.image_name}.tar.gz disk.raw",
      "rm -f disk.raw",
      "echo 'wrote build/proxy/${local.image_name}.tar.gz'",
    ]
  }
}
