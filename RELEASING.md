# Releasing

Publishing is irreversible (crates.io and PyPI never let a version be
re-uploaded), so the order matters: nothing goes public until CI is green
on the exact commit being released.

## Once, before the first release

1. **PyPI Trusted Publishing.** On pypi.org → *Your account → Publishing →
   Add a pending publisher*: project `witness-log`, owner `0xAndersen`,
   repository `witness-log`, workflow `release.yml`, environment `pypi`.
   Then in GitHub → *Settings → Environments* create an environment named
   `pypi` (add yourself as a required reviewer if you want a manual gate).
2. **crates.io.** Log in with GitHub at crates.io, create an API token
   scoped to *publish-new* and *publish-update*, and run `cargo login`
   locally.
3. **npm.** Create the `witness-log` organisation on npmjs.com, make a
   granular automation token (publish, packages `@witness-log/*` and
   `create-witness-log`, 2FA bypass), and store it as the secret
   `NPM_TOKEN` in a GitHub environment named `npm`. The `npm.yml` and
   `npm-node.yml` workflows use it for the first publish of each package
   when the tags are pushed (`ts-v0.3.0`, `node-v0.2.0`, `ai-sdk-v0.2.0`,
   `create-witness-log-v0.2.0`). Afterwards configure Trusted Publishing
   on each package (GitHub Actions, repo `0xAndersen/witness-log`,
   workflow `npm.yml` or `npm-node.yml`, environment `npm`) and delete the
   secret; an empty token falls back to OIDC.
4. **Container image.** The `docker` workflow pushes
   `ghcr.io/0xandersen/witness-log`; make the package public once in its
   GitHub settings. `image-public-check.yml` confirms an anonymous pull
   and `/health` from a clean runner.
5. **Branch protection** on `main`: require the `ci` workflow to pass.
6. **Browser verifier on Pages.** *Settings → Pages → Source: GitHub
   Actions*, then *Settings → Secrets and variables → Actions → Variables*:
   `PAGES_ENABLED` = `true`. Until both are set, `pages.yml` builds and
   browser-tests the page on every push but skips the deploy job.
7. **Repository profile.** *Settings → General*: website
   `https://github.com/0xAndersen/witness-log/wiki`; topics
   `transparency-log audit-log merkle-tree ai-agents tamper-evident rfc6962
   c2sp tlog-witness mcp rust cryptography`. *Settings → Code security*:
   enable Dependabot alerts and security updates (`.github/dependabot.yml`
   already schedules action and Cargo updates).

## Every release

1. Bump `version` in `Cargo.toml` (workspace) and
   `crates/witness-log-python/Cargo.toml`, and the `version = "…"` on the
   inter-crate dependencies in `crates/*/Cargo.toml`. Move the CHANGELOG's
   top section under the new version and date. Bump the pinned tag in
   `deploy/witness/cloud-init.yaml` (`WL_REF="vX.Y.Z"`, twice: the env file
   and the `${WL_REF:-...}` default), the matching replacement string in
   `.github/workflows/cloud-init-test.yml`, and `VER=` in
   `deploy/witness/AGENT_OPERATOR.md`; `grep -rn 'v0\.[0-9]*\.[0-9]' deploy
   .github/workflows/cloud-init-test.yml` finds them. Bump the npm
   packages when their code changed (`clients/*/package.json`, the node
   platform packages under `clients/node/npm/`, the inter-package ranges
   and the create-witness-log templates), then `npm install
   --package-lock-only` in `clients/`, and the Go wasm engine's `version`
   in `clients/go/cmd/witness-log-wasm/main.go`.
2. Push to `main` and wait for **every** CI job to go green (Linux, macOS,
   Windows, release mode, MSRV, clippy, fmt, corpus, Python 3.9 + 3.13,
   cargo-deny).
3. Publish the crates **in dependency order**, waiting for each to appear
   on crates.io before the next (each depends on the previous one):
   Preferred: Actions → *publish-crates* → Run workflow → tag `v0.5.0`.
   The token lives in the `crates-io` environment as
   `CARGO_REGISTRY_TOKEN`; the job publishes core → network → cli in
   order, skips versions already on crates.io, and verifies with
   `cargo install`. Locally, the equivalent is:
   ```sh
   cargo publish -p witness-log-core
   cargo publish -p witness-log-network
   cargo publish -p witness-log-cli
   ```
4. Release. Either push a tag, or run the `release` workflow manually
   (Actions → release → Run workflow → tag `v0.5.0`); the workflow then
   creates the tag on the chosen commit. It refuses to run if the tag
   does not equal the version in `Cargo.toml`. This builds wheels
   for Linux (x86_64, aarch64, musl), macOS (Intel, Apple Silicon) and
   Windows plus an sdist, publishes them to PyPI, and creates a GitHub
   Release with CLI binaries and `SHA256SUMS`:
   ```sh
   git tag -a v0.5.0 -m "witness-log 0.5.0" && git push origin v0.5.0
   ```
5. Tag the Go module so `go get …/clients/go@vX.Y.Z` resolves to a real
   version rather than a pseudo-version:
   ```sh
   git tag -a clients/go/v0.5.0 -m "witness-log Go client 0.5.0" && git push origin clients/go/v0.5.0
   ```
   and the npm packages whose version changed (`ts-v…`, `node-v…`,
   `ai-sdk-v…`, `create-witness-log-v…`; each tag runs its publish job).
6. Check from a clean machine: `cargo install witness-log-cli && witness-log
   demo`, and `pip install witness-log && python -c "import witness_log"`.

## If something goes wrong

- A crate published with a bug: `cargo yank --version X -p <crate>`, fix,
  release X+1 (a version can never be reused).
- PyPI upload failed partway: fix and re-run the failed job; files already
  uploaded are skipped. A bad PyPI release: yank it in the web UI.
- `v0.3.0` exists only as a git tag and was never published. It is
  superseded; do not publish it.
