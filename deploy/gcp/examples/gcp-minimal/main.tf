# Minimal GCP deployment — single zone, default replica count (3).

module "uninc" {
  source = "../../modules/uninc-server"

  project_id     = var.project_id
  region         = "us-west1"
  zone           = "us-west1-a"

  db_name     = var.db_name
  db_user     = var.db_user
  db_password = var.db_password

  admin_ssh_cidr = var.admin_ssh_cidr
  admin_emails   = var.admin_emails
  jwt_secret     = var.jwt_secret
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
