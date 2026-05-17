# WASM SBOM (CycloneDX)

The continuous delivery pipeline generates a **CycloneDX** JSON SBOM for the dependency graph of `lib-q` when resolved for:

- **Target:** `wasm32-unknown-unknown`
- **Features:** `wasm,ml-kem` (aligned with the `@lib-q/core` npm build in `.github/workflows/cd.yml`)

## Generation

Locally (requires Rust stable + `wasm32-unknown-unknown`):

```bash
bash ./scripts/generate-wasm-sbom.sh
```

The script installs `cargo-cyclonedx` 0.5.9 if the `cargo cyclonedx` subcommand is missing, writes `sbom/lib-q-wasm-wasm32.cdx.json`, and deletes transient `*.json` copies `cargo-cyclonedx` emits next to other workspace manifests.

The `sbom/` directory is gitignored; artifacts are published as **GitHub Release attachments** from the `post-release` job.

## Scope

The SBOM describes **Rust crate dependencies** as resolved by Cargo for the WASM target. It does not replace npm lockfile auditing for JavaScript tooling; it answers “which crates are linked into this WASM graph?” for security and license review.
