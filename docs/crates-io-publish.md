# Crates.io publishing (lib-Q workspace)

Internal `path` dependencies must include a **version** (same as `[workspace.package].version` in the root `Cargo.toml`) so `cargo publish` and `cargo publish --dry-run` can produce a valid manifest for crates.io. The helper script `scripts/add-internal-crate-versions.py` adds `, version = "…"` after each in-repo `path = \"../…\"` line; it is scoped to workspace crates only (not `reference/` or other trees).

**First-time or clean-machine dry-run** may still report `no matching package named 'lib-q-…' on crates.io` until upstream workspace crates are published in order. Follow `.github/workflows/cd.yml`: `lib-q-types` → tier 0 (`lib-q-core`, `lib-q-keccak`) → `lib-q-sha3` → tier 1 (including `lib-q-keccak-digest` after `lib-q-sha3`).

**FN-DSA nested crates** publish as `lib-q-fn-dsa-comm`, `lib-q-fn-dsa-kgen`, `lib-q-fn-dsa-sign`, `lib-q-fn-dsa-vrfy`, and `lib-q-fn-dsa-alg` (not `fn-dsa-*`; those names belong to [pornin/rust-fn-dsa](https://github.com/pornin/rust-fn-dsa) on crates.io). Use `scripts/publish-crates-io-ordered.ps1` for the full ordered list.

**`lib-q` umbrella**: publish last (after `lib-q-zkp` and other path dependencies). Configure Trusted Publishing on the crate the same way as the rest of the workspace ([docs](https://crates.io/docs/trusted-publishing)).

**Bump:** When the workspace version changes, update every internal `version = "…"` on path dependencies to match, or re-run the script with `WS_VERSION` updated.

**Not every workspace member is in `cd.yml`.** Research, fuzz-only, or internal crates (for example `lib-q-lattice-zkp`, `lib-q-ring-sig`, `lib-q-prf`, `lib-q-sca-test`, `lib-q-ring`) stay path-only until explicitly added to a publish tier; see [CI_CD_SETUP.md](../CI_CD_SETUP.md) and the root `Cargo.toml` `[workspace].members` list.

**npm:** After Rust tiers through `lib-q` (umbrella), publish `@lib-q/*` with [npm-publish.md](npm-publish.md) (`scripts/publish-npm-ordered.sh` / `.ps1`).
