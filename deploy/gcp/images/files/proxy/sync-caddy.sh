#!/bin/bash
# sync-caddy.sh
#
# Re-render /etc/caddy/Caddyfile whenever GCE metadata key
# `caddy-upstream-url` changes. Idempotent; safe to run every 30s.
# Full-file render (not sed-in-place on the running Caddyfile) so the
# upstream URL is free of escape concerns.
#
# Baked into the uninc-proxy image. The systemd timer caddy-sync.timer
# fires this every 30s.
set -euo pipefail

META_URL="http://metadata.google.internal/computeMetadata/v1/instance/attributes/caddy-upstream-url"
UPSTREAM=$(curl -sf -H "Metadata-Flavor: Google" "$META_URL" 2>/dev/null || echo "")
if [[ -z "$UPSTREAM" ]]; then exit 0; fi

CURRENT=$(grep -oE "reverse_proxy[[:space:]]+[^[:space:]{]+" /etc/caddy/Caddyfile 2>/dev/null | head -1 | awk '{print $2}')
if [[ "$UPSTREAM" == "$CURRENT" ]]; then exit 0; fi

EMAIL=$(cat /etc/caddy/.email)
ASK=$(cat /etc/caddy/.ask-url)

# Render to .new then atomically move — Caddy never sees a half-written file.
sed -e "s#__CADDY_EMAIL__#${EMAIL}#" \
    -e "s#__CADDY_ASK_URL__#${ASK}#" \
    -e "s#__CADDY_UPSTREAM__#${UPSTREAM}#" \
    /etc/caddy/Caddyfile.template > /etc/caddy/Caddyfile.new
mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile

# If container isn't up yet (timer can run during early boot), skip reload.
# Next tick (30s later) picks it up once caddy is running.
if docker ps --format '{{.Names}}' | grep -q '^uninc-caddy$'; then
   docker exec uninc-caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 || true
fi
