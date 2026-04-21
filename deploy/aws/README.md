# AWS deploy recipe (placeholder)

**Not yet written.** The Unincorporated server stack is cloud-agnostic, but the only production-shipped deploy recipe today is [`../gcp/`](../gcp/). This directory is a placeholder to signal that AWS is a supported target **in principle** — PRs welcome.

## What you'd need to write

If you're porting `gcp/` to AWS, the work is almost entirely in the Infrastructure-as-Code layer. The Rust binaries, Docker Compose stack, and chain protocol are identical. The mapping from GCP resources to AWS equivalents is straightforward:

| GCP (`gcp/modules/uninc-server/`) | AWS equivalent |
|---|---|
| `google_compute_network` + `google_compute_subnetwork` | `aws_vpc` + `aws_subnet` |
| `google_compute_firewall` | `aws_security_group` + `aws_security_group_rule` |
| `google_compute_instance` (proxy VM, DB VMs) | `aws_instance` |
| `google_compute_instance`'s `metadata_startup_script` | `aws_instance`'s `user_data` (cloud-init) |
| `google_compute_address` (static public IP) | `aws_eip` |
| `google_dns_managed_zone` + `google_dns_record_set` | `aws_route53_zone` + `aws_route53_record` |
| Cloud Run (if the app is co-located) | **Not straightforward.** AWS App Runner is the closest analog but doesn't support VPC-attached egress the same way Cloud Run does with Direct VPC Egress. Alternatives: ECS Fargate in the same VPC as the proxy (proven), or EKS if you already run Kubernetes. This is the main architectural difference and the reason full app-hosting on AWS isn't a drop-in port. |

The startup scripts ([`../gcp/modules/uninc-server/startup-proxy.sh`](../gcp/modules/uninc-server/startup-proxy.sh) and [`startup-db.sh`](../gcp/modules/uninc-server/startup-db.sh)) are generic bash — they install Docker, pull images, bring up Compose. They'd work unmodified as `user_data` on an Ubuntu AMI.

## Single-VM on AWS is easy

If you only need a single-VM topology (proxy + DB primitives on one box, no co-located customer app), the AWS port is basically one `aws_instance` + security group + Elastic IP + the existing `startup-proxy.sh` as `user_data`. A contributor could ship that in a weekend. The multi-VM-with-co-located-app shape is the hard one because of Cloud Run.

## If you need this now

Run [`../bare-metal/`](../bare-metal/) on an EC2 instance. It works exactly the same — install Docker, run the Compose stack. You lose the Terraform automation but nothing else.
