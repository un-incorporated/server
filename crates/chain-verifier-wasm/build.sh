#!/usr/bin/env bash
#
# Build the WASM chain verifier. Produces three artifacts in ./pkg/ that
# any frontend can serve:
#
#   pkg/chain_verifier_wasm_bg.wasm   — the verifier binary
#   pkg/chain_verifier_wasm.js        — ES module glue
#   pkg/chain-verifier.sha256         — digest for reproducible-build checks
#
# Host these on whatever origin your frontend loads the verifier from. For
# best-effort trust separation, serve them from a different origin than the
# one that issues the chain entries — so a compromised server cannot swap
# the verifier out at the same time it forges entries.
#
# Prereqs: rustup target add wasm32-unknown-unknown && cargo install wasm-pack
#
# Reproducible-build check: the sha256 printed at the end should be stable
# across identical source checkouts. If it drifts, something non-deterministic
# entered the build graph (e.g. a compiler upgrade or an unpinned dep).

set -euo pipefail

cd "$(dirname "$0")"

if ! command -v wasm-pack >/dev/null 2>&1; then
    echo "error: wasm-pack not installed. Install with:" >&2
    echo "  cargo install wasm-pack" >&2
    exit 1
fi

echo ">>> Building chain-verifier-wasm (release, target=web)..."
wasm-pack build --target web --out-dir pkg --release

WASM=pkg/chain_verifier_wasm_bg.wasm
if command -v shasum >/dev/null 2>&1; then
    DIGEST=$(shasum -a 256 "$WASM" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
    DIGEST=$(sha256sum "$WASM" | awk '{print $1}')
else
    echo "error: neither shasum nor sha256sum available" >&2
    exit 1
fi
printf '%s\n' "$DIGEST" > pkg/chain-verifier.sha256

echo
echo ">>> Artifacts in pkg/:"
echo "    $WASM"
echo "    pkg/chain_verifier_wasm.js"
echo "    pkg/chain-verifier.sha256"
echo
echo ">>> sha256: $DIGEST"
