# npm publishing (@lib-q/*)

Scoped packages are built with [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) and published as `@lib-q/<name>`. The matrix and feature flags match [`.github/workflows/cd.yml`](../.github/workflows/cd.yml) job `publish-wasm-packages`.

## Prerequisites

- Workspace version in root `Cargo.toml` `[workspace.package].version` matches the release you intend to ship (CD uses the git tag without the `v` prefix).
- **Rust** `wasm32-unknown-unknown` and **wasm-pack** installed locally (or let the script install wasm-pack).
- **Node.js 24+** (CI/CD uses Node 24; Node 20+ may still work locally) and `npm login` (or `NODE_AUTH_TOKEN` in the environment).
- **crates.io**: CD publishes Rust crates before npm. For a manual run, finish [crates.io publishing](crates-io-publish.md) through `lib-q-zkp` (tier 16) so path dependencies resolve when you build from a clean tree with version-pinned deps—or build from this repo with path deps as usual.

## Ordered publish script

```bash
# Linux / macOS / Git Bash
./scripts/publish-npm-ordered.sh

# Windows (PowerShell wrapper → bash)
./scripts/publish-npm-ordered.ps1
```

Options (environment variables or PowerShell parameters):

| Control | Bash | PowerShell |
|---------|------|------------|
| Resume at package index | `START_AT=3 ./scripts/publish-npm-ordered.sh` | `-StartAt 3` |
| Dry-run (no upload) | `DRY_RUN=1 ./scripts/publish-npm-ordered.sh` | `-DryRun` |
| Skip wasm rebuild (publish only) | `SKIP_BUILD=1 ./scripts/publish-npm-ordered.sh` | `-SkipBuild` |
| Override version | `VERSION=0.0.2 ./scripts/...` | `-Version 0.0.2` |

Log file: `scripts/publish-npm-ordered.log`.

The script skips packages that are already published at the target version (npm 403 “cannot publish over”).

## Package list (CD order)

| npm package | Crate / directory | Notes |
|-------------|-------------------|--------|
| `@lib-q/core` | `lib-q/` | `wasm,all-algorithms,ml-kem` |
| `@lib-q/ml-kem` | `lib-q-ml-kem` | |
| `@lib-q/kem` | `lib-q-kem` | |
| `@lib-q/sig` | `lib-q-sig` | `out-dir`: `pkg-sig` |
| `@lib-q/hash` | `lib-q-hash` | `pkg-hash` |
| `@lib-q/utils` | `lib-q-utils` | `pkg-utils` |
| `@lib-q/fn-dsa` | `lib-q-fn-dsa` | |
| `@lib-q/aead` | `lib-q-aead` | `wasm,saturnin,romulus,rocca-s,duplex-sponge-aead` |
| `@lib-q/hpke` | `lib-q-hpke` | |
| `@lib-q/zkp` | `lib-q-zkp` | |
| `@lib-q/random` | `lib-q-random` | |
| `@lib-q/hqc` | `lib-q-hqc` | |
| `@lib-q/slh-dsa` | `lib-q-slh-dsa` | |
| `@lib-q/cb-kem` | `lib-q-cb-kem` | single compile-time parameter set |
| `@lib-q/ring-sig` | `lib-q-ring-sig` | pilot |
| `@lib-q/prf` | `lib-q-prf` | pilot |
| `@lib-q/types` | `npm/lib-q-types` | TypeScript only; no wasm-pack |
| `@lib-q/stark` | `lib-q-stark` | `wasm` |
| `@lib-q/plonky` | `lib-q-plonky` | `wasm` |
| `@lib-q/poseidon` | `lib-q-poseidon` | `wasm`, `alloc` |
| `@lib-q/lattice-zkp` | `lib-q-lattice-zkp` | `wasm`, `random` |
| `@lib-q/ring` | `lib-q-ring` | `wasm`, `alloc` |
| `@lib-q/mac` | `lib-q-mac` | `wasm`, `random` |
| `@lib-q/blind-pcs` | `lib-q-blind-pcs` | `wasm`, `blind-pcs`; EXPERIMENTAL_NON_NIST |
| `@lib-q/dkg` | `lib-q-dkg` | `wasm`, `std`, `random`; PROVISIONAL |
| `@lib-q/threshold-raccoon` | `lib-q-threshold-raccoon` | `wasm`, `std`, `random`; PROVISIONAL |
| `@lib-q/threshold-kem-lattice` | `lib-q-threshold-kem-lattice` | `wasm`, `std`, `random`; PROVISIONAL |

**Total: 27 packages** (indices 0–26 in `publish-npm-ordered.sh`). See [npm-coverage.md](npm-coverage.md).
`@lib-q/fhe` and `@lib-q/threshold-kem` were withdrawn and removed in 0.0.10 — see
[Removed crates](npm-coverage.md#removed-crates) and board cards t_2a349708 / t_8ca3fd06.

This table is checked against `cd.yml` on every pull request by [`scripts/ci-guard-publish-order.sh`](../scripts/ci-guard-publish-order.sh) — it claimed 22 packages against `cd.yml`'s 30 at 0.0.10. Regenerate with `python3 scripts/cd_publish_manifest.py --format npm` rather than editing by hand.

Dual-target layout (`pkg/web` + `pkg/nodejs`) and `integrity-manifest.json` are applied by [`scripts/npm-publish-annotate.mjs`](../scripts/npm-publish-annotate.mjs), same as [`.github/actions/npm-publish`](../.github/actions/npm-publish/action.yml).

## CI / secrets

- GitHub CD uses `secrets.NPM_TOKEN` and `npm publish --access public --provenance`.
- Local runs use your npm user or `NODE_AUTH_TOKEN` (automation token with publish rights on `@lib-q/*`).

| `NPM_OTP` | One-time password for `npm publish --otp` (required when 2FA is enabled) |
| `BUILD_ONLY` | `1` = wasm-pack only, no upload |
| `PUBLISH_ONLY` | `1` = upload only (skip build; needs existing `pkg/`) |
| `END_AT` | Last matrix index to process (inclusive) |

See also [npm-packages.md](npm-packages.md), [npm-wasm-api.md](npm-wasm-api.md), [npm-coverage.md](npm-coverage.md), and [CI_CD_SETUP.md](../CI_CD_SETUP.md).
