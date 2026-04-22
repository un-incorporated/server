# Full GCP deployment — custom machine types, 5 replicas, custom images.
#
# Source selection (pick one):
#
#   1. REMOTE (default below) — consumes the module straight from the GitHub
#      repo at the branch or tag named by `ref=`. Copy-this-file-into-my-own-
#      infra-repo scenarios work with no other setup: `terraform init` fetches
#      the module over HTTPS. `ref=main` is unpinned and floats with the
#      default branch — fine for initial bring-up, risky for long-lived
#      infra because `terraform init -upgrade` will silently absorb module-
#      surface breaks. Replace `main` with a tagged release (e.g. `ref=v0.1.0`)
#      once a tag exists and pin deliberately in the same PR that touches
#      the module contract. Until that first tag is cut, `ref=main` is the
#      only value that resolves.
#
#   2. LOCAL — if you have cloned the repo and want Terraform to consume the
#      module from the working tree (to edit the module and this example
#      together), comment out the `source` below and uncomment the local
#      path version:
#        # source = "../../modules/uninc-server"
#
# Never mix the two — switching `source` between remote and local forces
# `terraform init` to re-download state, which on a running deployment is
# indistinguishable from a module re-init and may recreate resources.

module "uninc" {
  source = "git::https://github.com/un-incorporated/server.git//deploy/gcp/modules/uninc-server?ref=main"

  project_id = var.project_id
  region     = var.region
  zone       = var.zone
  mode       = "full"

  db_name     = var.db_name
  db_user     = var.db_user
  db_password = var.db_password

  replica_count      = var.replica_count
  proxy_machine_type = var.proxy_machine_type
  db_machine_type    = var.db_machine_type

  proxy_image    = var.proxy_image
  observer_image = var.observer_image

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

variable "region" {
  type    = string
  default = "us-west1"
}

variable "zone" {
  type    = string
  default = "us-west1-a"
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

variable "replica_count" {
  type    = number
  default = 5
}

variable "proxy_machine_type" {
  type    = string
  default = "e2-standard-4"
}

variable "db_machine_type" {
  type    = string
  default = "e2-standard-2"
}

variable "proxy_image" {
  type    = string
  default = "ghcr.io/un-incorporated/proxy:latest"
}

variable "observer_image" {
  type    = string
  default = "ghcr.io/un-incorporated/observer:latest"
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

output "postgres_port" {
  value = module.uninc.postgres_port
}

output "mongodb_port" {
  value = module.uninc.mongodb_port
}

output "s3_port" {
  value = module.uninc.s3_port
}

output "observer_internal_ip" {
  value = module.uninc.observer_internal_ip
}
