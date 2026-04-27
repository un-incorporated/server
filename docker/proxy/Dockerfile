# ── Stage 1: Build ────────────────────────────────────────────────
#
# Builds TWO binaries into the same image: `uninc-proxy` (the wire-protocol
# proxy) and `chain-engine` (the NATS consumer that persists chain entries).
# The two deploy together on the same VM and are composed as separate
# containers with different entrypoints — shipping a single image avoids
# a second pull + second registry push per release while keeping the
# process isolation Docker gives us.
#
# If the two ever need to scale independently (e.g., chain-engine runs on
# its own VM), split this into two Dockerfiles at that point; today
# they're joined by a core-NATS subject and always colocated.

# Pin builder to bookworm so the binary links against glibc 2.36 — the
# runtime stage is debian:bookworm-slim (also glibc 2.36). The default
# `rust:1-slim` tracks Debian Trixie (glibc 2.39+), which produces
# binaries that fail to start on the bookworm runtime with
# "GLIBC_2.38 not found". Keep both stages pinned to the same release.
FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build both binaries in one cargo invocation so compile artifacts are
# shared between crates.
RUN cargo build --release -p uninc-proxy -p chain-engine

# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/uninc-proxy   /usr/local/bin/uninc-proxy
COPY --from=builder /src/target/release/chain-engine  /usr/local/bin/chain-engine

# Canonical proxy external ports — the "+1000 shift" from LOCAL-DEV.md.
# These are hard-coded into the Rust binary via PROXY_*_PORT constants in
# uninc-common/src/config.rs and cannot be overridden at runtime.
# chain-engine exposes no ports — it talks to NATS.
EXPOSE 6432 28017 10000 9090

# Default entrypoint is the proxy. Callers that want the chain-engine
# side of the image override the entrypoint at runtime:
#   docker run --entrypoint chain-engine ghcr.io/un-incorporated/proxy:<tag>
CMD ["uninc-proxy"]
