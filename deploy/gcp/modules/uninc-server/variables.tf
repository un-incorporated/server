# ── Required ──────────────────────────────────────────────────────

variable "project_id" {
  description = "GCP project ID where resources will be created."
  type        = string
}

variable "db_name" {
  description = "Name of the PostgreSQL database."
  type        = string
}

variable "db_user" {
  description = "PostgreSQL admin username."
  type        = string
}

variable "db_password" {
  description = "PostgreSQL admin password."
  type        = string
  sensitive   = true
}

variable "admin_ssh_cidr" {
  description = "CIDR block allowed to SSH into the proxy VM (e.g. 203.0.113.0/24)."
  type        = string
}

variable "admin_emails" {
  description = "List of admin email addresses for IAM and alerting."
  type        = list(string)
}

variable "jwt_secret" {
  description = "JWT signing secret for the chain API (:9091) and health-detailed (:9090) endpoints."
  type        = string
  sensitive   = true
}

variable "chain_minio_access_key" {
  description = "Access key for the chain-MinIO container on each replica VM. Used by chain-engine (on the proxy) to quorum-write to the replica chain tier via MultiReplicaStorage. See docs/chain-storage-architecture.md."
  type        = string
  sensitive   = true
}

variable "chain_minio_secret_key" {
  description = "Secret key for the chain-MinIO container on each replica VM."
  type        = string
  sensitive   = true
}

# ── Optional (with defaults) ─────────────────────────────────────

variable "region" {
  description = "GCP region for all resources."
  type        = string
  default     = "us-west1"
}

variable "zone" {
  description = "GCP zone for compute instances."
  type        = string
  default     = "us-west1-a"
}

variable "mode" {
  description = "Deployment mode: 'full' provisions databases, 'proxy-only' skips them."
  type        = string
  default     = "full"
}

variable "replica_count" {
  description = "Number of database VM replicas (odd numbers only for quorum)."
  type        = number
  default     = 3

  validation {
    condition     = contains([3, 5, 7], var.replica_count)
    error_message = "replica_count must be 3, 5, or 7."
  }
}

variable "proxy_machine_type" {
  description = "GCE machine type for the proxy VM."
  type        = string
  default     = "e2-medium"
}

variable "db_machine_type" {
  description = "GCE machine type for database VMs."
  type        = string
  default     = "e2-medium"
}

variable "proxy_image" {
  description = "Container image for the uninc-proxy service."
  type        = string
  default     = "ghcr.io/uninc-app/proxy:latest"
}

variable "databases" {
  description = "Primitives to install on DB VMs: postgres, mongodb, s3"
  type        = list(string)
  default     = ["postgres"]
}

variable "mongo_password" {
  description = "MongoDB admin password. Only used when databases contains mongodb."
  type        = string
  sensitive   = true
  default     = ""
}

variable "customer_minio_access_key" {
  description = "Customer S3/MinIO root access key. Only used when databases contains s3."
  type        = string
  default     = ""
}

variable "customer_minio_secret_key" {
  description = "Customer S3/MinIO root secret key. Only used when databases contains s3."
  type        = string
  sensitive   = true
  default     = ""
}
