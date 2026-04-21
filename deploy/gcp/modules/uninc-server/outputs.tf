output "proxy_endpoint" {
  description = "External IP address of the proxy VM."
  value       = google_compute_instance.proxy.network_interface[0].access_config[0].nat_ip
}

output "chain_api_url" {
  description = "URL for the chain read API (JWT-gated). Single source of truth for chain visualization."
  value       = "http://${google_compute_instance.proxy.network_interface[0].access_config[0].nat_ip}:9091"
}

output "postgres_port" {
  description = "Proxy Postgres listener port (the +1000 shift — clients connect here, not to native 5432)."
  value       = 6432
}

output "mongodb_port" {
  description = "Proxy MongoDB listener port (the +1000 shift — clients connect here, not to native 27017)."
  value       = 28017
}

output "s3_port" {
  description = "Proxy S3-compatible listener port (the +1000 shift — clients connect here, not to native 9000)."
  value       = 10000
}
