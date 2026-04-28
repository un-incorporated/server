#!/bin/bash
# uninc-boot.sh — fetch per-deployment startup script and execute it.
#
# Why this exists: the un-incorporated disk images boot from a vanilla
# Debian 12 cloud image with no GCE guest-agent installed. Without the
# guest-agent there's no `google-startup-scripts.service` watching the
# `startup-script` instance metadata key, so the per-deployment config
# script set by Terraform would otherwise never run. This script is
# baked into every image and invoked by `uninc-boot.service` to fill
# that gap.
#
# The other behaviors a guest-agent would provide — SSH key sync, OS
# Login integration, account daemon — we don't want. Customer VMs are
# sealed: once running, neither the operator nor anyone else should be
# able to log in and mutate the proxy binary or the chain on disk.
# That's the transparency guarantee. Debug surfaces are limited to
# the GCE serial console and Cloud Logging by design.
#
# Output capture:
#   /var/log/uninc-boot.log  — local file for shell debugging
#   journald (tag uninc-boot) — picked up by Cloud Ops Agent and
#                                shipped to Cloud Logging
#   /dev/console             — visible in `get-serial-port-output`,
#                                the only debug surface available when
#                                SSH is broken
# Three destinations because each fails differently — disk fills, agent
# crashes, console scrollback overflows — and a failed boot is exactly
# when you need observability most.
#
# Source priority for the per-deployment script:
#   1. GCE metadata: instance attribute `startup-script`. Production
#      path on GCP. Reached over plain HTTP at metadata.google.internal
#      with the `Metadata-Flavor: Google` header — no SDK, no agent.
#   2. /etc/uninc/boot-config.sh on disk. Fallback for non-GCP hosts
#      (KVM/Proxmox/bare-metal) where an operator can drop a config
#      file via cloud-init or by mounting the disk.
# A missing script in both places is logged and the unit exits 0; the
# VM still comes up so an operator can investigate.

set -uo pipefail

LOG=/var/log/uninc-boot.log
mkdir -p "$(dirname "$LOG")"
# Fan-out: stdin → tee writes to $LOG and /dev/console, AND its stdout
# pipes to logger which puts it on syslog (→ journald → Cloud Logging
# via the Ops Agent). Three destinations, one redirection. Doing it
# once at the top means every later command's stdout/stderr inherits.
exec > >(tee -a "$LOG" /dev/console | logger -t uninc-boot) 2>&1

ts() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
log() { echo "[uninc-boot $(ts)] $*"; }

log "uninc-boot starting (uname=$(uname -srm), uptime=$(uptime -p))"

METADATA_URL="http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script"
LOCAL_FALLBACK="/etc/uninc/boot-config.sh"
SCRIPT_PATH=$(mktemp /tmp/uninc-boot.XXXXXX.sh)
trap 'rm -f "$SCRIPT_PATH"' EXIT

# Fetch from GCE metadata. --max-time 10s caps wait on non-GCP hosts
# where metadata.google.internal isn't resolvable. -f makes curl exit
# non-zero on HTTP errors (404, etc) so we cleanly fall through.
HTTP_CODE=$(curl -sS -f \
   -H 'Metadata-Flavor: Google' \
   -o "$SCRIPT_PATH" \
   -w '%{http_code}' \
   --max-time 10 \
   "$METADATA_URL" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" == "200" && -s "$SCRIPT_PATH" ]]; then
   log "startup-script fetched from GCE metadata ($(wc -c < "$SCRIPT_PATH") bytes)"
elif [[ -s "$LOCAL_FALLBACK" ]]; then
   log "GCE metadata unreachable (http=$HTTP_CODE), using $LOCAL_FALLBACK"
   cp "$LOCAL_FALLBACK" "$SCRIPT_PATH"
else
   log "no startup script found (GCE http=$HTTP_CODE, $LOCAL_FALLBACK absent or empty)"
   log "VM is up but unconfigured — drop a script at $LOCAL_FALLBACK and reboot, or set the startup-script metadata key"
   exit 0
fi

chmod +x "$SCRIPT_PATH"

log "executing startup script"
START=$(date +%s)
set +e
bash "$SCRIPT_PATH"
EXIT_CODE=$?
set -e
END=$(date +%s)
log "startup script exited with code $EXIT_CODE after $((END - START))s"

exit $EXIT_CODE
