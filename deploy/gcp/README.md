# GCP deploy recipe

Terraform module + examples for provisioning the Unincorporated server stack on Google Cloud Platform. Provisions the multi-VM topology (per-deployment VPC, proxy VM, 3/5/7 DB replicas, Observer VM).

## What this module provisions

A full per-deployment GCP topology:

- **One VPC per deployment** with a public and private subnet.
- **Proxy VM** (GCE e2-medium) in the public subnet running `ghcr.io/un-incorporated/proxy` + `chain-engine` + NATS via Docker Compose.
- **Database replica VMs** (3/5/7 depending on replica count) in the private subnet, each running Postgres + MongoDB + MinIO co-located.
- **Firewall rules** that open the DB wire ports (`6432/28017/10000`) and the chain API port (`9091`) to `0.0.0.0/0` for customer-app reach, and lock down private-subnet DB ports to proxy-only traffic.
- **Startup scripts** that install Docker, pull the latest `ghcr.io/un-incorporated/*` images, and bring up the stack.

## Directory layout

```
gcp/
├── modules/uninc-server/      ← reusable Terraform module
│   ├── main.tf, network.tf, proxy.tf, database.tf, outputs.tf, variables.tf
│   ├── startup-proxy.sh, startup-db.sh
├── examples/
│   ├── gcp-full/              ← full multi-VM example (3 replicas)
│   └── gcp-minimal/           ← minimal single-replica example for testing
```

## How to use it (self-host the multi-VM topology on your own GCP project)

All paths below are relative to the repo root (`server/`).

```bash
cd deploy/gcp/examples/gcp-full
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: set project_id, region, db_password
terraform init
terraform apply
```

After ~10 minutes you have a running proxy + replica cluster in your own GCP project. Point your app at the proxy's public IP on `:6432` (Postgres), `:28017` (MongoDB), or `:10000` (S3).

## Cloud portability

Everything in `modules/uninc-server/*.tf` is GCP-specific (`google_compute_*` resources). The **stack it runs** — the Docker Compose with proxy + chain-engine + NATS + DB primitives — is cloud-agnostic. A contributor porting this recipe to AWS or Azure would rewrite the `.tf` files to use `aws_*` or `azurerm_*` resources but keep the startup scripts and Docker Compose unchanged. See [../aws/README.md](../aws/README.md) and [../bare-metal/README.md](../bare-metal/README.md).
