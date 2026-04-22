# Releases

One git tag, three downstream artifacts. Cutting a release means tagging
`main` with a semver tag (`vX.Y.Z`), pushing the tag, and letting the
downstream consumption paths pick up the new version.

This file is the single source of truth for what's released, how it's
consumed, and which piece of CI owns which artifact. If a detail here
drifts from reality, fix this file first and whatever else second.

| Artifact | Source | CI workflow | Destination | Consumer |
| --- | --- | --- | --- | --- |
| **WASM verifier** | `crates/chain-verifier-wasm/` | [`.github/workflows/release-wasm.yml`](.github/workflows/release-wasm.yml) | GitHub **Releases** (file assets: `.wasm` + JS glue + `.sha256`) | Browser-side chain verification; `unincorporated.app` pins the tag in `www/wasm-version.txt` and fetches via `www/scripts/sync-wasm.sh` |
| **Docker images** | `docker/proxy/Dockerfile` (builds both `uninc-proxy` + `chain-engine` binaries into one image), `docker/observer/Dockerfile` | [`.github/workflows/release-docker.yml`](.github/workflows/release-docker.yml) | **ghcr.io** (container registry, multi-arch amd64+arm64): `ghcr.io/un-incorporated/proxy:<tag>`, `ghcr.io/un-incorporated/observer:<tag>` | Self-hosters via Docker Compose; the managed `unincorporated.app` provisioning pipeline |
| **Terraform module** | `deploy/gcp/modules/uninc-server/` | None needed — Git IS the distribution | A Git ref: `git::https://github.com/un-incorporated/server.git//deploy/gcp/modules/uninc-server?ref=<tag>` | Self-hosters running on GCP; in-repo example consumers in `deploy/gcp/examples/gcp-{minimal,full}/main.tf` |

One tag, three artifacts — standard monorepo pattern (tokio, AWS CDK,
Kubernetes all ship multiple artifacts per tag).

Two workflows fire on the same `v*.*.*` tag push (`release-wasm.yml` and
`release-docker.yml`) and run in parallel; Terraform needs no workflow
because Git is its distribution. WASM failures never block Docker, Docker
failures never block WASM — they publish to different destinations and
fail independently.

**WASM goes to GitHub Releases. Docker goes to ghcr.io. Those are different
systems.** Visiting the Releases page for `v0.1.0` shows the ~200 KB of
WASM assets; it does not show Docker images. Images live in the Packages
tab and are consumed via `docker pull`, not downloaded as files. That's
why "attaching Docker images to a GitHub Release" would be huge — we don't
do that; nobody does.

## How to cut a release

One-time setup per maintainer machine (only needed for the WASM local
pre-check; CI does the authoritative build):

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --locked --version 0.13.1
```

Cut the release:

```bash
git checkout main
git pull --ff-only

# Optional but cheap: rebuild the WASM locally so CI doesn't surface
# a wasm-pack failure as the first sign of trouble.
bash crates/chain-verifier-wasm/build.sh

# Annotated tag (stores author + date + message), NOT lightweight —
# release-wasm.yml keys off semver tags and expects an annotated tag.
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

What happens next:

- `release-wasm.yml` fires on the tag push, builds the WASM, uploads the
  three GitHub Release assets.
- `release-docker.yml` fires on the same push, runs two matrix jobs in
  parallel (proxy, observer), each building a multi-arch (amd64 + arm64)
  image and pushing it to `ghcr.io/un-incorporated/<image>:<tag>` plus
  `:latest`. Provenance + SBOM attestations are attached by buildx so
  consumers can verify what they pulled was built from this repo at this
  commit.
- The Terraform module is instantly consumable at `?ref=v0.1.0` — no
  build step, the tag *is* the release.
- The WASM and Docker workflows are independent: a WASM break doesn't
  block images landing on ghcr.io, and a Docker build break doesn't
  block the WASM GitHub Release.

## How consumers pin a version

- **WASM** — edit `www/wasm-version.txt` in the mothership repo to the
  new tag string and redeploy; `scripts/sync-wasm.sh` fetches the
  three assets from the Release page and drops them into `public/wasm/`.
- **Terraform module** — change `source = "...?ref=vX.Y.Z"` in the
  consumer's `main.tf`. Pin deliberately in the same PR that adapts to
  any module-surface change. Never pin `ref=main`; it silently absorbs
  breaking changes on `terraform init -upgrade`.
- **Docker images** — edit whichever compose file the consumer uses
  (`docker/docker-compose*.yml`) to set `image: ghcr.io/un-incorporated/proxy:vX.Y.Z`,
  or for the managed `unincorporated.app` mothership, bump
  `UNINC_PROXY_IMAGE` / `UNINC_OBSERVER_IMAGE` in the `www/` provisioning
  config. The proxy image contains both the `uninc-proxy` binary (default
  entrypoint) and the `chain-engine` binary — callers switch between
  them by overriding the entrypoint at container-start time.

## Gaps

- **Dashboard image is not built from this repo.** `www/` provisions a
  third container image (`ghcr.io/un-incorporated/dashboard:<tag>`) onto every
  proxy VM on port 3000, but the dashboard's source code does not live
  in `server/`. That image is either produced from a sibling repository
  or is not yet built. `release-docker.yml` intentionally does NOT
  include a dashboard step — adding one would silently publish an image
  with no provenance to this tag. When the dashboard source lands (here
  or clearly pointed-to from here), add a matching matrix entry.
- **Conformance test vectors** (`testdata/dat-v1-vectors/`) do not exist
  yet. Appendix C.1 of the spec treats them as a first-class artifact
  for third-party implementers; once published, they become a fourth
  per-tag artifact shipped alongside the WASM on the GitHub Release.
  Design covered in `protocol/SPEC-DELTA.md §"Conformance test vectors"`.

## Why the repo layout isn't reorganized around releases

A recurring question: "should `crates/chain-verifier-wasm/` and
`deploy/gcp/modules/uninc-server/` move under a unified `release/`
folder?" Short answer, no:

- **WASM is source code, not a release artifact.** The crate compiles
  to the `.wasm` binary; the binary is the release. Pulling the crate
  out of `crates/` breaks the Rust workspace symmetry (every other
  workspace member stays under `crates/`).
- **Terraform module** lives in `deploy/gcp/modules/` because it's one
  of several deploy recipes (Docker Compose in `docker/`, AWS in
  `deploy/aws/`, bare-metal in `deploy/bare-metal/`). Moving just the
  GCP Terraform to a top-level `release/` creates asymmetry with the
  other recipes.
- **Docker images** have no source folder — the Dockerfiles live next
  to the build context they need (`docker/`), and the binaries come
  from the Rust crates.

The repo layout is idiomatic Rust-workspace + infra-recipes. This file
(`RELEASES.md`) plus the per-artifact docs linked from it are the
correct solution to "how do I find everything releasable".
