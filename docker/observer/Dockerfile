# ── Stage 1: Build ────────────────────────────────────────────────
#
# The independent observer VM — subscribes to each primitive's native
# replication stream (Postgres logical replication, MongoDB change
# streams, MinIO bucket notifications) and writes its own chain for
# cross-verification against the proxy's chain (spec §5.5). Deploys on
# a dedicated VM in the private subnet — no public IP.

FROM rust:1.78-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release -p observer

# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM debian:bookworm-slim

# ca-certificates: TLS to the upstream primitives. curl: used by
# container health probes / startup scripts on the observer VM.
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/observer /usr/local/bin/observer

# The observer's HTTP endpoint on :2026 is what the proxy's verification
# task reads from (spec §5.5). Firewalled to the proxy VM only in the
# provisioned multi-VM topology.
EXPOSE 2026

CMD ["observer"]
