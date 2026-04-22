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
  description = "CIDR block allowed to SSH into the proxy VM. Defaults to Google IAP's tunnel CIDR (35.235.240.0/20), so operators reach the VM via `gcloud compute ssh --tunnel-through-iap` and direct internet SSH is rejected. Set to a specific bastion CIDR or 0.0.0.0/0 only if you have a reason."
  type        = string
  default     = "35.235.240.0/20"
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

variable "deployment_salt" {
  description = "Per-deployment HMAC salt for chain_id_user (§3.2 of the Data Access Transparency spec). MUST be 32 bytes of CSPRNG entropy, hex-encoded (64 hex chars). MUST NOT change across the life of the deployment — rotating re-derives every user's chain id and orphans their existing entries. Generate once: `openssl rand -hex 32`."
  type        = string
  sensitive   = true
}

variable "observer_image" {
  description = "Container image for the uninc-observer service."
  type        = string
  default     = "ghcr.io/un-incorporated/observer:latest"
}

variable "observer_read_secret" {
  description = "Shared secret the proxy's verification task uses to authenticate to the observer's /entries endpoint."
  type        = string
  sensitive   = true
}

variable "observer_machine_type" {
  description = "GCE machine type for the observer VM."
  type        = string
  default     = "e2-small"
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
  default     = "ghcr.io/un-incorporated/proxy:latest"
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
