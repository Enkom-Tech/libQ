# Crates.io publishing (lib-Q workspace)

Internal `path` dependencies must include a **version** (same as `[workspace.package].version` in the root `Cargo.toml`) so `cargo publish` and `cargo publish --dry-run` can produce a valid manifest for crates.io. The helper script `scripts/add-internal-crate-versions.py` adds `, version = "…"` after each in-repo `path = \"../…\"` line; it is scoped to workspace crates only (not `reference/` or other trees).

**First-time or clean-machine dry-run** may still report `no matching package named 'lib-q-…' on crates.io` until upstream workspace crates are published in order. Follow `.github/workflows/cd.yml`: `lib-q-types` → tier 0 (`lib-q-core`, `lib-q-keccak`) → `lib-q-sha3` → tier 1 (including `lib-q-keccak-digest` after `lib-q-sha3`).

**FN-DSA nested crates** publish as `lib-q-fn-dsa-comm`, `lib-q-fn-dsa-kgen`, `lib-q-fn-dsa-sign`, `lib-q-fn-dsa-vrfy`, and `lib-q-fn-dsa-alg` (not `fn-dsa-*`; those names belong to [pornin/rust-fn-dsa](https://github.com/pornin/rust-fn-dsa) on crates.io). Use `scripts/publish-crates-io-ordered.ps1` for the full ordered list.

**`lib-q-stark-baby-bear` (tier 10)**: the BabyBear prime field (`p = 2^31 - 2^27 + 1`) implemented as a `lib-q-stark-monty31` instance; it is the base field for the Arm B membership STARK. Its dependencies — `lib-q-stark-field` (tier 6) and `lib-q-stark-monty31` (tier 9) — are already published by the time tier 10 runs, and its dependents — `lib-q-poseidon` (tier 11) and `lib-q-zkp` (tier 16) — come later, so tier 10 is the correct slot. It is published alongside `lib-q-stark-challenger` and `lib-q-stark-interpolation` in the `publish-rust-tier-10` matrix.

**`lib-q-mve` + `lib-q-transcript` (tier 16b)**: both publish in the new `publish-rust-tier-16b` matrix, after `lib-q-zkp` (tier 16) and before the `lib-q` umbrella (tier 17). `lib-q-mve` (multi-recipient verifiable encryption / "verifiable rekey") depends on `lib-q-zkp` (tier 16); `lib-q-transcript` (shared Fiat-Shamir / CFRG-sigma duplex-transcript discipline, K12 out-of-circuit + Poseidon-256 in-circuit) depends on `lib-q-poseidon` (tier 11) and `lib-q-k12`. Neither has any in-workspace dependents, so nothing downstream needs them; they are threaded before the umbrella so a failure here still blocks the release (the post-release / `cd-summary` gate keys off tier 17). Both are **RED / experimental** — pending human cryptographer sign-off (under IACR review); publish them only with that caveat understood, and they ship to crates.io only (no npm / WASM packages).

> **RED tiers — do not over-claim.** `lib-q-mve`, `lib-q-transcript`, and the `lib-q-zkp` unlinkable set-membership proof (both Arm A and Arm B) are research/experimental: NOT proven sound, NOT audited, NOT production-ready, pending human cryptographer review (ADR-113 freeze gate). Their crate descriptions already carry the `RED, PENDING HUMAN SIGN-OFF` marker; keep release notes and any downstream docs consistent with that.

**`lib-q` umbrella (tier 17)**: publish last (after `lib-q-zkp`, `lib-q-mve` + `lib-q-transcript`, and other path dependencies). Configure Trusted Publishing on the crate the same way as the rest of the workspace ([docs](https://crates.io/docs/trusted-publishing)).

**Bump:** When the workspace version changes, update every internal `version = "…"` on path dependencies to match, or re-run the script with `WS_VERSION` updated.

**Not every workspace member is in `cd.yml`.** Research, fuzz-only, or internal crates (for example `lib-q-lattice-zkp`, `lib-q-ring-sig`, `lib-q-prf`, `lib-q-sca-test`, `lib-q-ring`) stay path-only until explicitly added to a publish tier; see [CI_CD_SETUP.md](../CI_CD_SETUP.md) and the root `Cargo.toml` `[workspace].members` list.

**crates.io-only crates (no npm parity).** A few crates publish to crates.io but ship **no npm / WASM package**, and are exempt from the npm-parity CI guards in `scripts/ci-guard-new-crates-and-npm.sh`:

- `lib-q-blind-token` (tier 4b) is `crate-type = ["rlib"]` with no `wasm-pack` bindings (its secure-params keygen is also impractical in WASM), so it is explicitly listed in the guard's `crates_io_only` set and skipped by the **tier-4b npm-parity guard**.
- `lib-q-stark-baby-bear` (tier 10), `lib-q-mve`, and `lib-q-transcript` (tier 16b) are also crates.io-only; they are not in any tier whose guard requires a matching npm package, so they need no explicit exemption.

**npm:** After Rust tiers through `lib-q` (umbrella), publish `@lib-q/*` with [npm-publish.md](npm-publish.md) (`scripts/publish-npm-ordered.sh` / `.ps1`).
