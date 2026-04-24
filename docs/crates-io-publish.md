# Crates.io publishing (lib-Q workspace)

Internal `path` dependencies must include a **version** (same as `[workspace.package].version` in the root `Cargo.toml`) so `cargo publish` and `cargo publish --dry-run` can produce a valid manifest for crates.io. The helper script `scripts/add-internal-crate-versions.py` adds `, version = "…"` after each in-repo `path = \"../…\"` line; it is scoped to workspace crates only (not `reference/` or other trees).

**First-time or clean-machine dry-run** may still report `no matching package named 'lib-q-…' on crates.io` until upstream workspace crates are published in order. Follow `.github/workflows/cd.yml`: `lib-q-types` → tier 0 (`lib-q-core`, `lib-q-keccak`) → `lib-q-sha3` → tier 1 (including `lib-q-keccak-digest` after `lib-q-sha3`).

**Bump:** When the workspace version changes, update every internal `version = "…"` on path dependencies to match, or re-run the script with `WS_VERSION` updated.
