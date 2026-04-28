# Ops Debugging — what to do when a deployment is broken

Concrete recipes for debugging a broken deployment. Aimed at on-call
operators staring at a failed `next dev` provision or a paged "stack
not responding."

The boot orchestration is documented in
[ARCHITECTURE.md §VM boot orchestration](../ARCHITECTURE.md#vm-boot-orchestration);
this doc focuses on **how to use it** when something has gone wrong.

---

## Customer VMs are sealed — no SSH

Before anything else: **customer VMs do not have working SSH.** This
is deliberate, and not a v0.1 simplification. The product's pitch vs
every other database audit tool (pgaudit, CloudTrail, Google Access
Transparency, the DAM category) is that the operator cannot tamper
with the chain *or* with the proxy that produces it. The moment SSH
exists, that guarantee evaporates: an operator with shell access can
`echo forged >> /data/chains/...` or swap the proxy binary, and the
verification proxy becomes "trust us" with extra steps.

The image build (`install-{proxy,db,observer}.sh`) removes every
prerequisite for sshd: host keys deleted, `sshd_config` emptied,
`ssh.service` masked, all login-capable users (`packer`, `debian`,
root password) wiped. The package binary is still on disk — Packer's
own build session uses it — but on customer VMs, sshd cannot start
and would have nobody to admit if it did.

That means the debug surfaces are:

| Surface | When to reach for it | Always works? |
|---|---|---|
| Serial console | The VM is unreachable, HTTP is broken, Cloud Logging is empty. The "is the VM even alive" check. | Yes — works on every running VM, no agent required. Survives any in-VM state. |
| Cloud Logging | The VM is/was alive but you want a queryable log across multiple deployments, or the VM is gone but you still need its history. | Only after the Ops Agent is up (boot+~5s). Persists past VM teardown. |
| Disk-detach inspection | Last resort: corrupted state where logs aren't enough and you accept stopping the VM. Read-only, audit-trailed. | Only when you've stopped the original VM and have permission to attach disks. |

Start with serial console. It needs zero setup and tells you whether
the VM has even reached our boot orchestration.

---

## 1. Serial console — `gcloud compute instances get-serial-port-output`

```bash
gcloud compute instances get-serial-port-output VM_NAME \
   --zone=us-east4-a \
   --project=YOUR_PROJECT \
   | tail -300
```

What you'll see (in order, on a healthy VM):

1. Kernel boot, systemd targets reaching `multi-user.target`
2. cloud-init finishes (Debian's stock cloud-init for filesystem grow,
   locale, hostname)
3. `[uninc-boot YYYY-MM-DDTHH:MM:SSZ] uninc-boot starting`
4. `[uninc-boot ...] startup-script fetched from GCE metadata (N bytes)`
5. `[uninc-boot ...] executing startup script`
6. `[startup-{proxy|db|observer} phase] begin`
7. `[startup-{role} phase] render-config`, `[startup-{role} phase]
   compose-up`, etc.
8. `[startup-{role} phase] done`
9. `[uninc-boot ...] startup script exited with code 0 after Ns`

Any **missing step** narrows the failure window:

- No "uninc-boot starting" → systemd or cloud-init failed; check the
  earlier kernel/systemd lines for an OOM, disk-full, or service start
  failure.
- "fetched from GCE metadata" but no "executing startup script" →
  the metadata script is empty or unreadable. Check the
  `startup-script` metadata key is set:
  `gcloud compute instances describe VM_NAME --format='value(metadata.items.filter("key:startup-script").firstof(value))'`.
- Phase marker present but next phase missing → the failure is
  between those two markers. Add narrower markers for the next
  release tag.
- `[startup-{role} phase] FAILED at line N with exit C` → the bash
  `ERR` trap fired. Read line N of `startup-{role}.sh` in the
  Terraform module (or in the metadata directly).

Serial console scrollback is finite (~1 MB). For long-running issues,
prefer Cloud Logging.

---

## 2. Cloud Logging — Ops Agent ships journald + container stdout

The Cloud Ops Agent (installed in every image) tails journald and
ships to Cloud Logging. Two log streams matter:

```bash
# uninc-boot orchestration + startup-script phase markers
gcloud logging read \
   'resource.type="gce_instance"
    AND jsonPayload.SYSLOG_IDENTIFIER="uninc-boot"' \
   --project=YOUR_PROJECT \
   --limit=300 \
   --format='value(timestamp,jsonPayload.MESSAGE)'

# Container stdout (proxy/observer/nats/pgbouncer/caddy/minio).
# Tagged by container name via /etc/docker/daemon.json's log-opts.
gcloud logging read \
   'resource.type="gce_instance"
    AND jsonPayload.SYSLOG_IDENTIFIER=~"^uninc-"' \
   --project=YOUR_PROJECT \
   --limit=1000
```

Container stdout reaches Cloud Logging because we set the Docker
daemon's log driver to `journald` in the image build — the default
`json-file` driver writes to `/var/lib/docker/containers/*.log` which
Ops Agent doesn't tail.

Filter by VM with `resource.labels.instance_id=VM_ID`. Logs persist
past VM teardown — for a deploy that briefly came up and crashed,
this is often the only place the failure history lives.

---

## 3. Disk-detach inspection (last resort)

For state that lives on disk but isn't in any log — corrupted chain
file, mismatched compose configuration, stuck Postgres WAL — the
escape hatch is:

1. Stop the production VM (this is visible in the GCP audit log,
   so the seal isn't silently broken — every disk-attach is recorded).
2. Detach the persistent disk.
3. Attach it **read-only** to a separate, ephemeral debug VM that
   you control (a stock Debian instance with sshd, your key in
   metadata, etc — like any normal GCE VM).
4. Mount the disk read-only on the debug VM and inspect.
5. Detach from debug VM, reattach to original, restart.

```bash
# 1. Stop the production VM
gcloud compute instances stop VM_NAME --zone=ZONE --project=PROJECT

# 2. Spin up a debug VM (use a stock Debian image, your normal SSH key)
gcloud compute instances create debug-$(date +%s) \
   --zone=ZONE --project=PROJECT \
   --image-family=debian-12 --image-project=debian-cloud \
   --machine-type=e2-small

# 3. Detach the disk from the production VM
gcloud compute instances detach-disk VM_NAME \
   --disk=VM_NAME --zone=ZONE --project=PROJECT

# 4. Attach to debug VM read-only
gcloud compute instances attach-disk debug-... \
   --disk=VM_NAME --mode=ro \
   --device-name=inspect --zone=ZONE --project=PROJECT

# 5. Mount on debug VM and look around
gcloud compute ssh debug-... --zone=ZONE --project=PROJECT \
   --command="sudo mkdir -p /mnt/inspect && \
              sudo mount -o ro /dev/disk/by-id/google-inspect-part1 /mnt/inspect && \
              ls /mnt/inspect/data/chains"

# 6. When done, reverse the dance.
```

This pattern is documented because it is the *only* fallback for
disk-state debugging that preserves the trust model:

- The production VM is **offline** before any byte is touched —
  no live traffic is observing different data than the chain reflects.
- The disk attach is **read-only** — you literally cannot write to
  the chain or the proxy binary during inspection.
- Every disk-attach operation appears in the GCP audit log as
  `compute.instances.attachDisk`, so the act of inspection is itself
  an auditable event. If a customer asks "did anyone look at our
  data?", the audit log answers honestly.

It's not pleasant — stopping a production VM has obvious downsides —
which is why we want serial console + Cloud Logging to be sufficient
for ~95% of debugging. Reach for this only when they aren't.

---

## What this debug stack DOESN'T cover

**Pre-boot failures** — image import errors, GCE quota exhaustion,
Terraform plan errors. These are mothership-side; check the
provisioning logs in `www/` and the GCP project's
**Compute Engine → Operations** page.

**Network-partition failures** — if the VM can't reach the metadata
server or Cloud Ops Agent's endpoint, neither serial console nor
Cloud Logging will help fully. Serial console still works (it's GCP
control plane, not VM network), and shows the curl failure.

**Live RAM state** — proxy in-memory caches, NATS JetStream queue
depth, etc. These vanish on any restart. The only way to capture
them is to have the proxy export them as Prometheus metrics or
periodic structured log lines, which is a code change in the next
release tag.

---

## Adding more visibility

If a class of failure is hard to debug from these surfaces, add
**narrower phase markers** to `startup-{role}.sh` first — they're
the cheapest signal and end up in both serial console and Cloud
Logging via the inheritance from `uninc-boot.sh`'s tee redirection.

If RAM-only state is the bottleneck, add an **always-on metrics
exporter** to the proxy (already on the roadmap, currently spec'd as
Prometheus on `:9090/metrics`). Metrics over a pull-based read API
expose state without needing a shell.

What we will NEVER add: a `/diag` endpoint that proxies host-level
state (docker ps, compose logs, etc.) over HTTP. Even gated by JWT,
that re-creates the SSH escape hatch we just sealed — except worse,
because now any compromise of the JWT key gives the attacker a
window into every customer's host. The sealing has to hold.
