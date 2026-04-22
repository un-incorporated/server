# Contributing to the Unincorporated Server

Thanks for considering a contribution. This file covers how to send a change; for build/test/run mechanics see [DEVELOPMENT.md](DEVELOPMENT.md).

> ⚠️ **Experimental / pre-1.0.** Test coverage is sparse, the protocol surface can still shift, and we are looking for contributors to harden the untested paths and port the deploy recipes.

## License

The server is **AGPLv3**. The license is load-bearing for the protocol's trust story: modifications to a running transparency service MUST be published, or end users cannot verify what the service is doing. By contributing, you agree that your contribution is licensed under AGPLv3. No CLA.

## Where to start

- **Bugs / small fixes** — open a PR directly. Reference an issue if one exists.
- **New features or anything touching the protocol** — open a discussion or issue first. Protocol-level changes must be considered against the spec at [`protocol/draft-wang-data-access-transparency-00.md`](protocol/draft-wang-data-access-transparency-00.md); a breaking change to the chain format is a hard "no" without a version bump and a migration plan.
- **Cloud-deploy recipes** — `deploy/aws/` and `deploy/bare-metal/` are currently placeholders and a great place to start. Port the [`deploy/gcp/`](deploy/gcp/) topology to your target. Mapping hints in each recipe's README.

## Development flow

1. Fork and clone. Create a feature branch off `main`.
2. Follow [DEVELOPMENT.md](DEVELOPMENT.md) to set up the Rust workspace and run the stack locally.
3. Write the change. Add tests (we don't merge untested code — see "Testing" below).
4. Run the checks:

   ```bash
   cargo fmt --all                                             # auto-format every crate to rustfmt defaults
   cargo clippy --workspace --all-targets -- -D warnings       # lint; -D turns warnings into build errors so CI won't silently accept them
   cargo test --workspace --lib                                # run library unit tests across the workspace (integration tests live under tests/ and need containers)
   ```
5. Commit with a message that explains *why*. "Fix bug" is not enough; "fix audit-gate fail-closed behavior when NATS ack times out — was forwarding queries anyway, violating the log-before-access invariant" is.
6. Open a PR against `main`. Describe the problem, the approach, and the blast radius.

## Code style

- **Rust** — `rustfmt` with workspace defaults (no overrides). `clippy` with `-D warnings`; if a lint is wrong for a specific case, `#[allow(...)]` with a one-line comment explaining why.
- **Error handling** — `thiserror` for library crates, `anyhow` for binaries. No `.unwrap()` in non-test code except for invariants that truly cannot fail (document why in a comment).
- **Logging** — `tracing` with structured fields. Never log secrets (DB passwords, JWT tokens, raw SQL). Query text is always stored as a SHA-256 fingerprint; if you find yourself about to log raw SQL, stop.
- **Markdown** — we don't fight the repo's existing markdownlint config. Match the style of the files around what you're editing.

## Testing

Pull requests that touch the proxy, chain engine, or verification code require tests. Specifically:

- **Audit-gate changes** — must include a fail-closed test (assert that a query is rejected when NATS is unreachable). The log-before-access invariant is load-bearing.
- **Chain format changes** — must include a round-trip test that appends N entries, rebuilds the chain from disk, and checks every `entry_hash`. Include a stability test against a golden fixture if the hash algorithm is touched.
- **Verification changes** — must include a divergence test (two replicas disagree) and a panic-recovery test (the nightly scheduler must survive a single bad run).

Integration tests that need real Postgres / MongoDB / MinIO live under `crates/proxy/tests/` and spin up containers via `testcontainers`. Unit tests for logic that doesn't need a DB live in `src/` with `#[cfg(test)]`.

## Cutting a release

One tag ships three artifacts: the WASM verifier, the Terraform module, and
the Docker images. Full mechanics — how each is distributed, how consumers
pin a version, and the open CI gap for Docker image release-on-tag — live in
[RELEASES.md](RELEASES.md). The quick version for maintainers:

```bash
git checkout main
git pull --ff-only                                # refuse non-fast-forward
bash crates/chain-verifier-wasm/build.sh          # local sanity-check rebuild
git tag -a v0.1.0 -m "v0.1.0"                     # annotated tag; release-wasm.yml keys off semver tags
git push origin v0.1.0                            # fires release-wasm.yml
```

The tag push fires [`release-wasm.yml`](.github/workflows/release-wasm.yml),
which attaches the WASM assets to the GitHub Release. The Terraform module
is instantly consumable at `?ref=v0.1.0` (Git is its distribution — no
workflow needed). **Docker images are still a manual push to ghcr.io
until `release-docker.yml` lands** — see `RELEASES.md §Gaps`.

One-time per-maintainer setup for the WASM local pre-check:

```bash
rustup target add wasm32-unknown-unknown   # adds the browser/wasm compile target to your Rust toolchain
cargo install wasm-pack --locked --version 0.13.1  # the build driver `build.sh` shells out to
```

## Security issues

Do **not** open a public issue for security bugs. Email the maintainers (see the root repository metadata) or use GitHub's private security advisory feature. Coordinated disclosure is appreciated; we'll credit you in the release notes unless you ask us not to.

## Pull request review

- One approving maintainer review is required to merge. Large or protocol-touching PRs will usually want two.
- We squash-merge. Your commits on the branch can be messy; the merged commit will be rewritten to a single clean message.
- If CI is red, we don't review until it's green — please fix before requesting review.

## What we probably won't merge

- Changes that make the audit gate less strict (e.g., "skip the NATS ack when latency is high"). The audit gate is the product.
- Code that broadens what's stored in a chain entry beyond the normalized-fingerprint model. Raw SQL in chain entries is a security and privacy regression.
- Cosmetic refactors with no behavioral change, unless they're a prerequisite for a larger change you're about to make.
- Dependencies that aren't open source. See [TECHSTACK.md](TECHSTACK.md) for our standing picks and rationale.

## Questions

Open a GitHub Discussion or join the community chat (link in the root README). For anything privacy- or security-sensitive, email first.
