# Releases

One git tag, four downstream artifacts. Cutting a release means tagging
`main` with a semver tag (`vX.Y.Z`), pushing the tag, and letting the
downstream consumption paths pick up the new version.

This file is the single source of truth for what's released, how it's
consumed, and which piece of CI owns which artifact. If a detail here
drifts from reality, fix this file first and whatever else second.

| Artifact | Source | CI workflow | Destination | Consumer |
| --- | --- | --- | --- | --- |
| **WASM verifier** | `crates/chain-verifier-wasm/` | [`.github/workflows/release-wasm.yml`](.github/workflows/release-wasm.yml) | GitHub **Releases** (file assets: `.wasm` + JS glue + `.sha256`) | Browser-side chain verification; `unincorporated.app` pins the tag in `www/wasm-version.txt` and fetches via `www/scripts/sync-wasm.sh` |
| **Docker images** | `docker/proxy/Dockerfile` (builds both `uninc-proxy` + `chain-engine` binaries into one image), `docker/observer/Dockerfile` | [`.github/workflows/release-docker.yml`](.github/workflows/release-docker.yml) | **ghcr.io** (container registry, multi-arch amd64+arm64): `ghcr.io/un-incorporated/proxy:<tag>`, `ghcr.io/un-incorporated/observer:<tag>` | Self-hosters via Docker Compose; the managed `unincorporated.app` provisioning pipeline |
| **Per-role disk images** | `deploy/gcp/images/{proxy,db,observer}.pkr.hcl` | [`.github/workflows/release-images.yml`](.github/workflows/release-images.yml) | GitHub **Releases** (file assets: `uninc-{proxy,db,observer}-vX-Y-Z.tar.gz`, each containing one `disk.raw`) | Customer VM boot disks. The managed `unincorporated.app` mothership lazy-imports each role's tar.gz into its GCP project on first deploy of every release tag, then customer VMs in that project boot from the imported GCE image. Self-hosters on GCP run the import once with `gcloud compute images create --source-uri=gs://...`; on bare KVM/Proxmox, untar and boot directly |
| **Terraform module** | `deploy/gcp/modules/uninc-server/` | None needed — Git IS the distribution | A Git ref: `git::https://github.com/un-incorporated/server.git//deploy/gcp/modules/uninc-server?ref=<tag>` | Self-hosters running on GCP; in-repo example consumers in `deploy/gcp/examples/gcp-{minimal,full}/main.tf` |

One tag, four artifacts — standard monorepo pattern (tokio, AWS CDK,
Kubernetes all ship multiple artifacts per tag).

Three workflows fire on the same `v*.*.*` tag push (`release-wasm.yml`,
`release-docker.yml`, `release-images.yml`) and run in parallel;
Terraform needs no workflow because Git is its distribution. The three
workflows publish to different destinations and fail independently —
a WASM break never blocks Docker or images, etc.

**WASM and disk images go to GitHub Releases. Docker images go to
ghcr.io.** Visiting the Releases page for `v0.1.0` shows the ~200 KB of
WASM assets plus three multi-GB disk-image tar.gz files; it does not
show Docker images. Container images live in the Packages tab and are
consumed via `docker pull`, not downloaded as files.

**No cloud-vendor registry for the disk images.** GitHub Releases hosts
them, anyone can `curl`, anyone can sha256, no GCP secrets in CI. On the
GCP side, the customer mothership stages the tar.gz through its own
Cloud Storage bucket and creates the GCE image once per release tag —
see [`deploy/gcp/images/README.md`](deploy/gcp/images/README.md) and
the `image-import.ts` worker in `un-incorporated/www`.

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
- `release-images.yml` fires on the same push, runs three matrix jobs in
  parallel (proxy, db, observer). Each builds a Debian 12-based disk
  image under `qemu`, pre-bakes Docker + every container image + the
  static compose YAML for that role, then uploads the resulting
  `uninc-{role}-vX-Y-Z.tar.gz` (containing `disk.raw`) as a GitHub
  Release asset. No GCP credentials needed — distribution is purely via
  GitHub.
- The Terraform module is instantly consumable at `?ref=v0.1.0` — no
  build step, the tag *is* the release.
- All three workflows are independent: a WASM break doesn't block
  images landing, a Docker build break doesn't block disk-image
  publishing, etc.

## How consumers pin a version

- **WASM** — edit `www/wasm-version.txt` in the mothership repo to the
  new tag string and redeploy; `scripts/sync-wasm.sh` fetches the
  three assets from the Release page and drops them into `public/wasm/`.
- **Terraform module** — change `source = "...?ref=vX.Y.Z"` in the
  consumer's `main.tf`. Pin deliberately in the same PR that adapts to
  any module-surface change. Never pin `ref=main`; it silently absorbs
  breaking changes on `terraform init -upgrade`.
- **Docker images** — edit whichever compose file the consumer uses
  (`docker/docker-compose*.yml`) to set `image: ghcr.io/un-incorporated/proxy:vX.Y.Z`.
  In the managed `unincorporated.app` mothership these images are no
  longer pulled at customer-VM boot; they're consumed at *image-build*
  time by the `release-images.yml` workflow, which bakes them into the
  per-role disk image. The proxy image contains both the `uninc-proxy`
  binary (default entrypoint) and the `chain-engine` binary — callers
  switch between them by overriding the entrypoint at container-start
  time.
- **Disk images** — bump `UNINC_GCE_IMAGE_VERSION` (defaulted in
  `www/core/services/provisioning/config.ts`) to the new tag via
  `npm run www:bump-images -- vX.Y.Z`. New deployments call
  `ensureAllImages` on the new tag during the infra phase: first
  deploy of each release pays a one-time per-role import (~3-5min,
  in parallel across the three roles) which downloads the tar.gz from
  GitHub, stages it through `UNINC_GCE_IMAGE_STAGING_BUCKET`, and runs
  `gcloud compute images create`. Subsequent deploys reuse the imported
  image. Existing VMs keep running their pinned image until
  re-provisioned.

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
