# Full GCP deployment — custom machine types, 5 replicas, custom images.

module "uninc" {
  source = "../../modules/uninc-server"

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

  proxy_image     = var.proxy_image

  admin_ssh_cidr = var.admin_ssh_cidr
  admin_emails   = var.admin_emails
  jwt_secret     = var.jwt_secret
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
  default = "ghcr.io/uninc-app/proxy:latest"
}

variable "admin_ssh_cidr" {
  type = string
}

variable "admin_emails" {
  type = list(string)
}

variable "jwt_secret" {
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
