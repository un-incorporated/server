# Deploy recipes

This directory holds **reference deployment recipes** for running the Unincorporated server stack (proxy + chain-engine + NATS + DB primitives) on specific infrastructures. None of these are "the canonical way" to deploy — they are examples you can use as starting points.

The **core software in [../crates/](../crates/) and [../docker/](../docker/) is cloud-agnostic**. Any of these recipes boils down to "provision a VM (or a couple of VMs), install Docker, run `docker compose up -d`, open the right ports." The only thing that changes between recipes is the Infrastructure-as-Code layer used to provision the VM(s) and network.

## What's here

| Recipe | Status | What it provisions |
|---|---|---|
| [`gcp/`](gcp/) | Shipping | Full multi-VM topology on GCP: per-deployment VPC, proxy VM, 3/5/7 DB replica VMs, firewall rules, Cloud DNS integration, startup scripts. Terraform (HCL) module + examples. |
| [`aws/`](aws/) | Not yet written | Placeholder. See [aws/README.md](aws/README.md) for what a contributor would need to port. |
| [`bare-metal/`](bare-metal/) | Not yet written | Placeholder. See [bare-metal/README.md](bare-metal/README.md) for running the stack on a single Linux host you already own. |

## Which one should you use?

- **You're a self-hoster evaluating the product** → use [`../docker/docker-compose.yml`](../docker/docker-compose.yml) on your laptop. You don't need any recipe in this directory.
- **You're a self-hoster running in production on your own cloud** → pick the recipe that matches your cloud; if yours isn't listed, `bare-metal/` gets you going on a single VM, then you adapt `gcp/` as a template for your IaC layer.
- **You're operating a multi-tenant platform** → `gcp/` is the authoritative topology reference.

## AGPL note

The `server/` stack is AGPL v3. The deployment recipes in this directory are a convenience — you can write your own, take any recipe and adapt it, or skip all of this and run the Docker Compose stack directly. The license attaches to the running binary, not the deployment mechanism.
