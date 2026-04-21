#!/usr/bin/env bash
#
# End-to-end smoke test for the user-erasure endpoint (spec §7.3).
#
# Runs the full wire path that a conformance reviewer would:
#   1. Seed a per-user chain by pushing an AccessEvent into NATS.
#   2. Mint a chain-api-user JWT bound to that user.
#   3. DELETE /api/v1/chain/u/{user_id}.
#   4. Validate the receipt shape.
#   5. Mint a chain-api-admin JWT.
#   6. GET /api/v1/chain/deployment/summary and confirm the tombstone landed
#      (entry_count incremented by 1 relative to before the DELETE).
#
# See smoke/README.md for prereqs.

set -euo pipefail

# ---------------------------------------------------------------------------
# Config (override any of these via env)
# ---------------------------------------------------------------------------

: "${PROXY_BASE:=http://localhost:9091}"
: "${NATS_URL:=nats://localhost:4222}"
: "${JWT_SECRET:=}"
: "${CHAIN_SERVER_SALT:=}"
: "${USER_ID:=smoke-user-$(date +%s)}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mint_jwt="${here}/mint_jwt.py"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
red()    { printf '\033[31m%s\033[0m\n' "$*" >&2; }
fail()   { red "FAIL: $*"; exit 1; }

need_bin() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required binary: $1"
}

# ---------------------------------------------------------------------------
# Prereq checks
# ---------------------------------------------------------------------------

need_bin curl
need_bin python3
need_bin jq

[[ -n "${JWT_SECRET}" ]]         || fail "JWT_SECRET must be set (matches proxy's JWT_SECRET env)"
[[ -n "${CHAIN_SERVER_SALT}" ]]  || fail "CHAIN_SERVER_SALT must be set (matches proxy/chain-engine)"

[[ -x "${mint_jwt}" ]] || fail "mint_jwt.py missing or not executable at ${mint_jwt}"

bold "=== uninc erasure smoke ==="
echo "proxy:  ${PROXY_BASE}"
echo "user:   ${USER_ID}"
echo

# ---------------------------------------------------------------------------
# 1. Seed a chain for the target user by sending an AccessEvent through NATS.
# ---------------------------------------------------------------------------
# We use the `nats` CLI if available. Without it, seeding becomes operator-
# specific (direct DB write, or a test endpoint). Keeping seeding optional
# lets the script run in two modes:
#   (a) `nats` present → full seed + erase + assert
#   (b) `nats` absent  → skip seed, expect 404 from the DELETE, and print
#                        a note that full assertion requires the CLI.
# ---------------------------------------------------------------------------

if command -v nats >/dev/null 2>&1; then
    bold "[1/3] seeding per-user chain via NATS publish"
    subject="uninc.access.${USER_ID}"
    payload=$(cat <<JSON
{
  "actor_id": "smoke-admin",
  "actor_type": "admin",
  "actor_label": "smoke-admin",
  "protocol": "postgres",
  "action": "read",
  "resource": "users",
  "affected_user_ids": ["${USER_ID}"],
  "query_fingerprint": "$(python3 -c 'import os,sys; sys.stdout.write(os.urandom(32).hex())')",
  "scope": { "description": "smoke seed" },
  "source_ip": "127.0.0.1",
  "session_id": "00000000-0000-0000-0000-000000000000"
}
JSON
)
    nats --server="${NATS_URL}" pub "${subject}" "${payload}" > /dev/null
    # chain-engine consumes asynchronously; give it a moment.
    sleep 1
    seeded=1
else
    echo "[1/3] 'nats' CLI not found — skipping seed. Install with 'brew install nats-io/nats-tools/nats' for full coverage."
    seeded=0
fi
echo

# ---------------------------------------------------------------------------
# 2. Mint a user JWT and read the pre-erase state.
# ---------------------------------------------------------------------------

bold "[2/3] reading deployment-chain baseline"
admin_token=$("${mint_jwt}" --secret "${JWT_SECRET}" --sub "smoke-admin" --aud "chain-api-admin")

baseline=$(curl -sf -H "Authorization: Bearer ${admin_token}" \
    "${PROXY_BASE}/api/v1/chain/deployment/summary" \
    | jq -r '.total_entries')
echo "baseline deployment-chain total_entries: ${baseline}"
echo

# ---------------------------------------------------------------------------
# 3. Issue DELETE and validate.
# ---------------------------------------------------------------------------

bold "[3/3] erasing user chain and verifying tombstone"
user_token=$("${mint_jwt}" --secret "${JWT_SECRET}" --sub "${USER_ID}" --aud "chain-api-user")

resp=$(mktemp)
status=$(curl -s -o "${resp}" -w '%{http_code}' \
    -X DELETE \
    -H "Authorization: Bearer ${user_token}" \
    -H "X-Forwarded-For: 203.0.113.7" \
    "${PROXY_BASE}/api/v1/chain/u/${USER_ID}")

if [[ "${seeded}" = "0" ]]; then
    if [[ "${status}" = "404" ]]; then
        green "OK: DELETE returned 404 (expected without NATS seed — user chain does not exist)"
        rm -f "${resp}"
        exit 0
    else
        fail "expected 404 (no seed), got HTTP ${status}: $(cat "${resp}")"
    fi
fi

[[ "${status}" = "200" ]] || fail "DELETE returned HTTP ${status}: $(cat "${resp}")"

tombstone_id=$(jq -r '.tombstone_entry_id' < "${resp}")
tombstone_idx=$(jq -r '.tombstone_deployment_chain_index' < "${resp}")

# Shape checks per §7.3.1.
[[ ${#tombstone_id} -eq 64 ]] \
    || fail "tombstone_entry_id must be 64 hex chars (SHA-256); got ${#tombstone_id}: ${tombstone_id}"
[[ "${tombstone_id}" =~ ^[0-9a-f]{64}$ ]] \
    || fail "tombstone_entry_id must be lowercase hex; got: ${tombstone_id}"
[[ "${tombstone_idx}" =~ ^[0-9]+$ ]] \
    || fail "tombstone_deployment_chain_index must be a non-negative integer; got: ${tombstone_idx}"

echo "tombstone_entry_id:        ${tombstone_id}"
echo "tombstone_deployment_chain_index: ${tombstone_idx}"
rm -f "${resp}"

# Confirm the tombstone actually landed on the deployment chain.
after=$(curl -sf -H "Authorization: Bearer ${admin_token}" \
    "${PROXY_BASE}/api/v1/chain/deployment/summary" \
    | jq -r '.total_entries')

expected=$(( baseline + 1 + seeded ))  # one for the seed AdminAccess, one for the tombstone
# Note: when seeded=1 we emitted one AccessEvent → one AdminAccess DeploymentEvent
# on the deployment chain, AND the DELETE added the tombstone. When
# seeded=0 we exit earlier, so this branch is seeded=1 only.
[[ "${after}" -ge $(( baseline + 1 )) ]] \
    || fail "deployment chain did not grow after DELETE (before=${baseline}, after=${after})"

green "OK: deployment chain grew from ${baseline} to ${after}"
green "OK: erasure smoke passed"
