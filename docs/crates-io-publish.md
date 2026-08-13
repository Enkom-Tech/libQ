# Crates.io publishing (lib-Q workspace)

Internal `path` dependencies must include a **version** (same as `[workspace.package].version` in the root `Cargo.toml`) so `cargo publish` and `cargo publish --dry-run` can produce a valid manifest for crates.io. The helper script `scripts/add-internal-crate-versions.py` adds `, version = "…"` after each in-repo `path = \"../…\"` line; it is scoped to workspace crates only (not `reference/` or other trees).

**First-time or clean-machine dry-run** may still report `no matching package named 'lib-q-…' on crates.io` until upstream workspace crates are published in order. Follow `.github/workflows/cd.yml`: `lib-q-types` → tier 0 (`lib-q-core`, `lib-q-keccak`) → `lib-q-sha3` → tier 1 (including `lib-q-keccak-digest` after `lib-q-sha3`).

**FN-DSA nested crates** publish as `lib-q-fn-dsa-comm`, `lib-q-fn-dsa-kgen`, `lib-q-fn-dsa-sign`, `lib-q-fn-dsa-vrfy`, and `lib-q-fn-dsa-alg` (not `fn-dsa-*`; those names belong to [pornin/rust-fn-dsa](https://github.com/pornin/rust-fn-dsa) on crates.io). Use `scripts/publish-crates-io-ordered.ps1` for the full ordered list — it restates `cd.yml`, and `scripts/ci-guard-publish-order.sh` fails CI if the two ever disagree (at 0.0.10 the script listed 65 of `cd.yml`'s 80 crates and skipped the other 15 without erroring). Regenerate it with `python3 scripts/cd_publish_manifest.py --format crates`.

**`lib-q-stark-baby-bear` (tier 10)**: the BabyBear prime field (`p = 2^31 - 2^27 + 1`) implemented as a `lib-q-stark-monty31` instance; it is the base field for the Arm B membership STARK. Its dependencies — `lib-q-stark-field` (tier 6) and `lib-q-stark-monty31` (tier 9) — are already published by the time tier 10 runs, and its dependents — `lib-q-poseidon` (tier 11) and `lib-q-zkp` (tier 16) — come later, so tier 10 is the correct slot. It is published alongside `lib-q-stark-challenger` and `lib-q-stark-interpolation` in the `publish-rust-tier-10` matrix.

**`lib-q-mve` + `lib-q-transcript` (tier 16b)**: both publish in the new `publish-rust-tier-16b` matrix, after `lib-q-zkp` (tier 16) and before the `lib-q` umbrella (tier 17). `lib-q-mve` (multi-recipient verifiable encryption / "verifiable rekey") depends on `lib-q-zkp` (tier 16); `lib-q-transcript` (shared Fiat-Shamir / CFRG-sigma duplex-transcript discipline, K12 out-of-circuit + Poseidon-256 in-circuit) depends on `lib-q-poseidon` (tier 11) and `lib-q-k12`. Neither has any in-workspace dependents, so nothing downstream needs them; they are threaded before the umbrella so a failure here still blocks the release (the post-release / `cd-summary` gate keys off tier 17). Both are **RED / experimental** — pending human cryptographer sign-off (under IACR review); publish them only with that caveat understood, and they ship to crates.io only (no npm / WASM packages).

> **RED tiers — do not over-claim.** `lib-q-mve`, `lib-q-transcript`, and the `lib-q-zkp` unlinkable set-membership proof (both Arm A and Arm B) are research/experimental: NOT proven sound, NOT audited, NOT production-ready, pending human cryptographer review (ADR-113 freeze gate). Their crate descriptions already carry the `RED, PENDING HUMAN SIGN-OFF` marker; keep release notes and any downstream docs consistent with that.

**`lib-q` umbrella (tier 17)**: publish last (after `lib-q-zkp`, `lib-q-mve` + `lib-q-transcript`, and other path dependencies). Configure Trusted Publishing on the crate the same way as the rest of the workspace ([docs](https://crates.io/docs/trusted-publishing)).

**Bump:** When the workspace version changes, every internal `version = "…"` on a path dependency must move with it — 434 pins across 84 manifests at 0.0.11. Use the bumper rather than doing it by hand or with a blanket search-and-replace:

```bash
python3 scripts/bump-workspace-version.py --to 0.0.12 --npm                  # dry run first
python3 scripts/bump-workspace-version.py --to 0.0.12 --npm --apply
python3 scripts/bump-workspace-version.py --to 0.0.11 --report-docs          # triage docs BY HAND
```

`--npm` also fixes `npm/**/package.json`, which drifts invisibly because CD overwrites the version at publish time (`npm pkg set version=`) — at 0.0.11 `npm/lib-q-types/package.json` still said `0.0.2`. `--report-docs` **lists and never rewrites**: most matches are history (a CHANGELOG heading, a "fixed in 0.0.10" note) and some are deliberately pinned to the old version. At 0.0.11 both `lib-q-hqc/SECURITY.md` and `lib-q-types/src/hqc.rs` correctly said `lib-q-types <= 0.0.10`, describing a break that ships *in* 0.0.11; a blanket replace falsifies them.

**Not every workspace member is in `cd.yml`.** A member stays path-only until it is added to a publish tier. As of 0.0.10 the only members `cd.yml` does not publish are the ones that carry `publish = false` in their own `[package]` (a withdrawn crate, and `examples/`) — the research and internal crates this note used to list as path-only (`lib-q-lattice-zkp`, `lib-q-ring-sig`, `lib-q-prf`, `lib-q-sca-test`, `lib-q-ring`) have all since been added to tiers and do publish. Do not read a crate's publish status off this paragraph; derive it:

```bash
python3 scripts/cd_publish_manifest.py --format crates    # what cd.yml publishes, in CD order
```

`scripts/ci-guard-new-crates-and-npm.sh` fails CI when a publishable workspace member is missing from `cd.yml`; see also [CI_CD_SETUP.md](../CI_CD_SETUP.md) and the root `Cargo.toml` `[workspace].members` list.

**crates.io-only crates (no npm parity).** A few crates publish to crates.io but ship **no npm / WASM package**, and are exempt from the npm-parity CI guards in `scripts/ci-guard-new-crates-and-npm.sh`:

- `lib-q-blind-token` (tier 4b) is `crate-type = ["rlib"]` with no `wasm-pack` bindings (its secure-params keygen is also impractical in WASM), so it is explicitly listed in the guard's `crates_io_only` set and skipped by the **tier-4b npm-parity guard**.
- `lib-q-stark-baby-bear` (tier 10), `lib-q-mve`, and `lib-q-transcript` (tier 16b) are also crates.io-only; they are not in any tier whose guard requires a matching npm package, so they need no explicit exemption.

**npm:** After Rust tiers through `lib-q` (umbrella), publish `@lib-q/*` with [npm-publish.md](npm-publish.md) (`scripts/publish-npm-ordered.sh` / `.ps1`).

## The failure class CI cannot see: `cargo publish --verify`'s build

`cargo publish --verify` builds each crate with **bare default features, on the host**. No CI job
builds that combination — CI builds `--all-features`, `std,all-algorithms`, and
`--no-default-features` cross-compiled to `thumbv7em-none-eabi`. So a crate can be green everywhere
and still fail to package.

v0.0.11 shipped 35 crates and then died at tier 3:

```
error: unwinding panics are not supported without std
error: could not compile `lib-q-core` (lib) due to 1 previous error
```

`lib-q-kem` declares `crate-type = ["cdylib", "rlib"]`, and a native cdylib needs a panic runtime.
That cycle tightened its dependency to `lib-q-core = { default-features = false }` while its own
`default` was `[]`, so the bare-default host build put `lib-q-core` in `no_std`. `--all-features`
structurally cannot catch this (it turns `std` on); the `thumbv7em` no_std build is a different
target with no cdylib to link. Fixed with `default = ["std"]`.

`scripts/ci-guard-cdylib-default-link.sh` now covers it, in two modes:

```bash
bash scripts/ci-guard-cdylib-default-link.sh            # static shape check — every PR (ci.yml)
bash scripts/ci-guard-cdylib-default-link.sh --build    # really links them — release path (cd.yml)
```

The static shape (cdylib whose `default` does not reach `std`) is **necessary but not sufficient**:
`lib-q-blind-pcs`, `lib-q-hpke` and `lib-q-stark` have exactly that shape and link fine, so they sit
in the guard's `KNOWN_LINKABLE` allowlist. `--build` re-proves every allowlist entry with a real
`cargo build -p <crate> --lib` before anything is published, so an entry cannot rot into a stale
claim. **Do not add a crate to that allowlist without running the build and recording the date.**

If you add a crate with `crate-type = ["cdylib", …]`, give it `default = ["std"]` — the pattern
`lib-q-core`, `lib-q-intrinsics` and `lib-q-kem` all use. `no_std` consumers are unaffected: they
depend with `default-features = false` and select algorithm features explicitly.
