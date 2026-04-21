# ── Stage 1: Build ────────────────────────────────────────────────
FROM rust:1.78-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release -p uninc-proxy

# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/uninc-proxy /usr/local/bin/uninc-proxy

# Canonical proxy external ports — the "+1000 shift" from LOCAL-DEV.md.
# These are hard-coded into the Rust binary via PROXY_*_PORT constants in
# uninc-common/src/config.rs and cannot be overridden at runtime.
EXPOSE 6432 28017 10000 9090

CMD ["uninc-proxy"]
