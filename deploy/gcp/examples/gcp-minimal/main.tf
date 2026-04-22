# Minimal GCP deployment — single zone, default replica count (3).
#
# Source pinning: `ref=main` floats with the default branch. Copy-paste of
# this file into a self-host infra repo Just Works because Terraform fetches
# the module over HTTPS, but every `terraform init -upgrade` absorbs whatever
# module-surface changes have landed on `main` since the last init — fine
# for initial bring-up, risky for long-lived infra. Replace `main` with a
# tagged release (e.g. `ref=v0.1.0`) once a tag is cut and pin deliberately.
# Until then, `ref=main` is the only value that resolves.
#
# In-repo workflow: if you're editing the module itself and want Terraform
# to consume the working tree, swap to a local path:
#   # source = "../../modules/uninc-server"
# Keep remote for copy-and-go self-hosting; keep local for module development.

module "uninc" {
  source = "git::https://github.com/un-incorporated/server.git//deploy/gcp/modules/uninc-server?ref=main"

  project_id     = var.project_id
  region         = "us-west1"
  zone           = "us-west1-a"

  db_name     = var.db_name
  db_user     = var.db_user
  db_password = var.db_password

  admin_ssh_cidr = var.admin_ssh_cidr
  admin_emails   = var.admin_emails

  jwt_secret             = var.jwt_secret
  deployment_salt        = var.deployment_salt
  observer_read_secret   = var.observer_read_secret
  chain_minio_access_key = var.chain_minio_access_key
  chain_minio_secret_key = var.chain_minio_secret_key
}

variable "project_id" {
  type = string
}

variable "db_name" {
  type = string
}

variable "db_user" {
  type = string
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "admin_ssh_cidr" {
  type    = string
  default = "35.235.240.0/20" # Google IAP tunnel CIDR — use `gcloud compute ssh --tunnel-through-iap`
}

variable "admin_emails" {
  type = list(string)
}

variable "jwt_secret" {
  type      = string
  sensitive = true
}

variable "deployment_salt" {
  type      = string
  sensitive = true
  # Generate once: openssl rand -hex 32
}

variable "observer_read_secret" {
  type      = string
  sensitive = true
}

variable "chain_minio_access_key" {
  type      = string
  sensitive = true
}

variable "chain_minio_secret_key" {
  type      = string
  sensitive = true
}

output "proxy_endpoint" {
  value = module.uninc.proxy_endpoint
}

output "chain_api_url" {
  value = module.uninc.chain_api_url
}
