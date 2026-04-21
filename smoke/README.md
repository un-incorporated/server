# Smoke tests

End-to-end smoke tests against a running Unincorporated Server. They exercise the wire contract defined in [protocol/draft-wang-data-access-transparency-00.md](../protocol/draft-wang-data-access-transparency-00.md) from outside the proxy, over real HTTP / real NATS. These are **not** unit tests — they assume the full stack (proxy, chain-engine, NATS) is already running, typically via [docker/docker-compose.yml](../docker/docker-compose.yml).

Think of these as happy-path sanity checks: run the stack, run this, see the expected codes and response shapes on the wire. Unit tests cover logic in isolation; these exercise the deployed runtime.

> **Scope note.** These scripts are **not** the full conformance surface the spec's Appendix C.1 "Runtime conformance (non-hash) vectors" section calls for. They currently cover §7.3 + §8.1 (erasure ordering). Three other runtime vectors — JWT `jti` single-use within `exp` window (§10.5), subject binding (§6.3), audience separation (§6.2) — are not yet scripted. `smoke/` is the natural landing pad for them when someone writes them. See [../protocol/SPEC-DELTA.md §Conformance test vectors](../protocol/SPEC-DELTA.md#conformance-test-vectors-uat-v1-appendix-c1) for the full list.

## Scripts

| Script | What it tests | Spec reference |
|--------|--------------|----------------|
| [`erasure.sh`](./erasure.sh) | User-initiated erasure: tombstone commits to the deployment chain, per-user chain is deleted, receipt shape matches §7.3.1 | §7.3, §8.1 |
| [`mint_jwt.py`](./mint_jwt.py) | Helper: mints an HS256 JWT (pure stdlib, no deps). Called by the other scripts. Also runnable standalone for ad-hoc curl. | §6.1 |

## Prerequisites

Install these once:

```bash
# macOS
brew install jq nats-io/nats-tools/nats

# Linux (example for Debian/Ubuntu)
sudo apt-get install jq
# nats CLI: https://github.com/nats-io/natscli/releases
```

`python3` is expected to be already on PATH (all recent macOS / Linux). `curl` too.

`nats` (the CLI, not `nats-server`) is **optional**. Without it, `erasure.sh` skips the seeding step and expects a `404` on DELETE — still validates the 404-without-tombstone invariant, but doesn't exercise the full write path.

## Running against a local docker-compose stack

All commands run from the repo root (`server/`).

```bash
# 1. Bring up the stack
cp .env.example .env   # if you haven't already
# edit .env: set JWT_SECRET and CHAIN_SERVER_SALT to any values — just remember them
docker compose -f docker/docker-compose.yml up --build -d

# 2. Wait for the proxy to be healthy
curl -sf http://localhost:9090/health && echo " proxy ready"

# 3. Run the smoke test
JWT_SECRET="$(grep ^JWT_SECRET .env | cut -d= -f2)" \
CHAIN_SERVER_SALT="$(grep ^CHAIN_SERVER_SALT .env | cut -d= -f2)" \
./smoke/erasure.sh
```

Expected output (with `nats` CLI installed):

```
=== uninc erasure smoke ===
proxy:  http://localhost:9091
user:   smoke-user-1745194500

[1/3] seeding per-user chain via NATS publish
[2/3] reading deployment-chain baseline
baseline deployment-chain total_entries: 0

[3/3] erasing user chain and verifying tombstone
tombstone_entry_id:        3a1e...<64 hex>
tombstone_deployment_chain_index: 1
OK: deployment chain grew from 0 to 2
OK: erasure smoke passed
```

Without the `nats` CLI you'll see `[1/3] 'nats' CLI not found — skipping seed` followed by `OK: DELETE returned 404`. That's still a valid partial assertion.

## Environment variables

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `JWT_SECRET` | yes | — | Must match the proxy's `JWT_SECRET` env. Any string. |
| `CHAIN_SERVER_SALT` | yes | — | Must match the proxy's/chain-engine's salt. Any string. |
| `PROXY_BASE` | no | `http://localhost:9091` | Chain API base URL. |
| `NATS_URL` | no | `nats://localhost:4222` | For the optional seeding step. |
| `USER_ID` | no | `smoke-user-<epoch>` | Lets you re-run with a fresh user each time. |

## Running against a remote deployment

Override `PROXY_BASE` and supply the deployment's secrets:

```bash
JWT_SECRET="<from your secret manager>" \
CHAIN_SERVER_SALT="<from your secret manager>" \
PROXY_BASE="https://proxy.your-deployment.example.com:9091" \
./smoke/erasure.sh
```

If the remote proxy enforces TLS, `curl` picks that up automatically. Make sure the calling machine has network reach to both the proxy's chain-API port (default `9091`) AND NATS (default `4222`) if you want seeding to work.

## Troubleshooting

**`DELETE returned HTTP 503: tombstone write failed ...`** — chain-engine can't be reached via NATS. Common causes: chain-engine container crashed; NATS address unreachable from the proxy; the `erasure_handler` task failed at startup. Check `docker compose logs chain-engine`.

**`DELETE returned HTTP 401: unauthorized`** — `JWT_SECRET` in the script's env doesn't match the proxy's. Check `docker-compose config | grep JWT_SECRET` against your local env.

**`DELETE returned HTTP 403: jwt sub must match path user_id`** — the minted JWT is for a different user than the URL path. Happens if you set `USER_ID` but something else is using `sub`. Don't override both inconsistently.

**`DELETE returned HTTP 404: no chain for user hash ...`** — the user has no chain to erase. Either (a) the NATS seed step was skipped and that's expected, or (b) `CHAIN_SERVER_SALT` in the script doesn't match the server's (different salt → different hashed directory name → server looks for the wrong dir).

## Relationship to the Rust integration test

The in-process integration test at [crates/chain-engine/tests/erasure_roundtrip.rs](../crates/chain-engine/tests/erasure_roundtrip.rs) covers the **same wire contract** but with a single `nats-server` spawned inside the test and the handler running as a tokio task — no Docker, no proxy binary. Run with:

```bash
cargo test --package chain-engine --test erasure_roundtrip -- --nocapture
```

It skips cleanly if `nats-server` isn't on PATH, so CI runners without NATS don't fail.

Use the integration test when iterating on handler logic. Use this smoke script when validating a full deployment before publishing a release.
