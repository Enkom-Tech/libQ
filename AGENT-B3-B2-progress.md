# Agent B3/B2 progress log

Branch: TBD (will create `fix/b3-neon-shake256-b2-stark-degree-bits` off `main`)
Worktree: C:\Users\Xtreme-W\Transfer\Enkom\Enkom\Git\libQ\.claude\worktrees\agent-abacbc6185f7fa64d

## Status: STARTING

## ITEM 1 — B3: aarch64 NEON x2::shake256

### Verification against source (before any change)
File: lib-q-ml-dsa/src/sha3_shim.rs, `neon::x2::shake256` (lines ~511-613 pre-fix).
Confirmed against actual source (line numbers in this repo state, may differ slightly from brief):
- line 531: `state[0] = 0x06;` — SHA3 (not SHAKE) separator, pre-set at lane 0 BEFORE absorbing. CONFIRMED.
- lines 535-564: absorb loop XORs input bytes into `state[lane_index]` for `lane_index < 25`, with
  NO call to the permutation between blocks (no rate-boundary handling at all). For inputs between
  136 and 200 bytes this clobbers capacity lanes 17..24. CONFIRMED.
- line 571: `state[padding_lane] ^= 0x1F << ...` — a second, conflicting domain-separator write
  (in addition to the `0x06` preset at line 531). CONFIRMED.
- line 587: `lib_q_keccak::keccak_p(state, 24)` called exactly once (only reachable when
  `ml_dsa_keccak_portable_simd` is NOT set — i.e. non-nightly builds), no matter how many output
  bytes were requested. CONFIRMED — no loop/permute-between-blocks for squeeze.
- line 599: `let bytes_available = output.len().min(200);` — output beyond 200 bytes (both the 576-
  and 640-byte ExpandMask requests) is left at its initial `0u8` value. CONFIRMED.

Call chain confirmed: `hash_functions.rs` `neon::shake256_x4` (a private free fn, ~line 956-968)
calls `x2::shake256(input0,input1,out0,out1)` / `x2::shake256(input2,input3,out2,out3)` directly
(NOT via `x2::incremental`) and is wired as the `shake256::XofX4` impl for the neon `Shake256x4`
struct used at `sample.rs::sample_mask_vector` (ExpandMask, 576/640-byte masks) via
`ml_dsa_generic.rs`. `multiplexing.rs` selects this NEON backend whenever `simd128` is enabled on
aarch64 (backed check pending — need to re-locate multiplexing.rs; brief cites lines 55-58).

ADDITIONAL DEFECT FOUND (not in brief's Item 1 scope, flagging only, not fixing in this pass):
`sha3_shim.rs` `neon::x2::incremental::KeccakStateX2::new()` unconditionally builds its two
`KeccakState`s via `incremental::shake128_init()`. `hash_functions.rs`'s neon `Shake256x4`
(`init_absorb_x4`, used by `sample.rs::sample_four_error_ring_elements` for s1/s2 error-vector
sampling in ML-DSA keygen) calls `x2::incremental::init()` then
`x2::incremental::shake256_absorb_final(...)`, which forwards to the crate-root
`incremental::shake256_absorb_final`, whose match arms are `KeccakState::Shake256{..} => ..` /
`_ => panic!("Invalid state for SHAKE-256 operation")`. Since the state is always the `Shake128`
variant, this looks like a guaranteed panic on first ML-DSA keygen on aarch64+simd128 — a second,
independent release blocker in the same NEON path. NOT fixing (out of the two-item scope given),
reporting to caller.

### aarch64 execution attempt — SUCCEEDED (real emulated execution via cross+QEMU+Docker)
- `cross` is installed (0.2.5), Docker is running.
- `cross build/test --target aarch64-unknown-linux-gnu` initially failed on THIS Windows host with:
  `error: toolchain 'nightly-2026-07-24-x86_64-unknown-linux-gnu' may not be able to run on this
  system` / `couldn't install toolchain ... rustup toolchain add ... failed with exit code: 1`
  — cross pre-checks by trying to install a matching Linux-triple rustup toolchain locally (the repo
  pins `nightly-2026-07-24` via rust-toolchain.toml) and rustup refuses to fetch a Linux ELF
  toolchain on a Windows host.
- Workaround: `rustup toolchain add nightly-2026-07-24-x86_64-unknown-linux-gnu --force-non-host
  --profile minimal` installs the toolchain *metadata* only (no working rustc, "error reading rustc
  version"), which is enough to satisfy cross's local pre-check.
- After that, `cross build -p lib-q-ml-dsa --target aarch64-unknown-linux-gnu --features simd128`
  succeeded (pulled `ghcr.io/cross-rs/aarch64-unknown-linux-gnu:0.2.5`, compiled clean).
- `cross test -p lib-q-ml-dsa --target aarch64-unknown-linux-gnu --features simd128 --lib` ALSO
  WORKS — the cross Docker image bundles qemu-user binfmt, so tests genuinely execute under aarch64
  emulation (confirmed baseline: 12/12 sha3_shim tests passed pre-change).
  **This means Item 1's RED/GREEN evidence below is REAL aarch64 execution, not a host proxy.**

### RED (observed via real `cross test` execution on emulated aarch64, pre-fix code)
Added 3 tests exercising the actual production NEON code path (`sha3_shim::neon_x2_equiv::*` in
lib-q-ml-dsa/src/sha3_shim.rs, `hash_functions::neon_mask_shake_equiv::portable_vs_neon_shake256_x4_640`
in lib-q-ml-dsa/src/hash_functions.rs), ran:
`cross test -p lib-q-ml-dsa --target aarch64-unknown-linux-gnu --features simd128 --lib -- neon_x2_equiv neon_mask_shake_equiv`
Actual output (pre-fix):
```
test hash_functions::neon_mask_shake_equiv::portable_vs_neon_shake256_x4_640 ... FAILED
  assertion `left == right` failed: portable vs neon mask SHAKE256 diverge
test sha3_shim::neon_x2_equiv::shake256_x2_differs_from_sha3_domain_separator ... FAILED
  assertion `left == right` failed: neon x2 shake256(empty) must equal scalar SHAKE256(empty)
test sha3_shim::neon_x2_equiv::shake256_x2_matches_scalar_640 ... FAILED
  assertion `left == right` failed: neon x2 shake256 diverges from scalar SHAKE256
  (right-hand/expected tail all zero from byte 200 on for the 640-byte case)
test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 116 filtered out; finished in 0.04s
```
Also added a host-executable (x86_64, no aarch64 needed) verbatim reproduction of the pre-fix
algorithm in `sha3_shim::neon_x2_shake256_defect_host_repro` (a byte-for-byte copy of the original
buggy body, kept permanently as a regression pin independent of target arch) — ran
`cargo test -p lib-q-ml-dsa --lib neon_x2_shake256_defect_host_repro`, both tests PASS (they assert
the defect's exact symptoms: bytes 200.. of a 640-byte zero-initialized output stay zero, and even a
32-byte output diverges from real SHAKE256).

### Fix — DONE
`lib-q-ml-dsa/src/sha3_shim.rs`, `neon::x2::shake256`: replaced the entire hand-rolled Keccak state
manipulation with a delegate to the crate's own already-correct portable `shake256(out, input)`
(itself `lib_q_sha3::Shake256::digest_xof`), called once per lane. Removed the now-unused
`#[cfg(ml_dsa_keccak_portable_simd)] use lib_q_keccak::advanced::parallel;` import. Rationale for
not routing through a 4-lane `lib_q_sha3::parallel::shake256_x4` batch (as the AVX2 sibling does):
`lib-q-keccak`'s `p1600x4` only vectorizes on x86_64/AVX2 — every other target (aarch64 included)
takes an unconditional scalar fallback — so there is no NEON-specific batching primitive to gain
throughput from today, and padding to 4 lanes would need runtime-length scratch buffers (alloc) for
no benefit. Two direct scalar calls are simplest and provably correct.

### GREEN (observed via real `cross test` execution on emulated aarch64, post-fix code)
`cross test -p lib-q-ml-dsa --target aarch64-unknown-linux-gnu --features simd128 --lib`:
`test result: ok. 119 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.73s`
(includes both new tests, now passing, plus the full pre-existing lib-q-ml-dsa test suite compiled
for aarch64+simd128 — no other tests regressed.)

### SECOND DEFECT — now OBSERVED (was SUSPECTED), NOT fixed (out of this pass's two-item scope)
`sha3_shim.rs` `neon::x2::incremental::KeccakStateX2::new()` unconditionally builds both inner
`KeccakState`s via `incremental::shake128_init()`. `hash_functions.rs`'s neon `Shake256x4`
(`init_absorb_x4`, wired as the `Shake256X4` type for the neon ML-DSA instantiation — see
`ml_dsa_generic/instantiations.rs:213-220`, used by `sample.rs::sample_four_error_ring_elements` for
s1/s2 error-vector sampling during **keygen**) calls `x2::incremental::init()` then
`x2::incremental::shake256_absorb_final(...)`, which forwards to the crate-root
`incremental::shake256_absorb_final`, whose match arms are `KeccakState::Shake256{..} => ..` /
`_ => panic!("Invalid state for SHAKE-256 operation")`.
Confirmed via a throwaway test (added, run under `cross test` on emulated aarch64, observed the
panic, then reverted — not left in the tree since fixing it is out of this task's declared scope):
```
thread 'hash_functions::scratch_confirm_incremental_bug::confirm' panicked at
lib-q-ml-dsa/src/sha3_shim.rs:247:18:
Invalid state for SHAKE-256 operation
```
This means **every ML-DSA key generation on aarch64 with `simd128` enabled panics immediately** —
likely more severe than the silent-corruption ExpandMask bug (which at least produces a signature,
just an insecure one), since keygen never completes. Flagging prominently for the human/caller;
not fixed here since it is a distinct defect from the one named in this task's Item 1.

## ITEM 2 — B2: STARK verifier MAX_DEGREE_BITS

### Verification against source (before any change)
Confirmed against lib-q-stark/src/verifier.rs (pre-fix):
- `MAX_DEGREE_BITS = 30` (field-independent).
- `verify_with_preprocessed`: `*degree_bits > MAX_DEGREE_BITS` check, then
  `pcs.natural_domain_for_degree(degree)` (panics), `create_disjoint_domain(...)`, and the
  `randomized_quotient_chunks_domains` map (another `natural_domain_for_degree` call) — ALL before
  `valid_shape` (opened_values-length check).
- `two_adic_pcs.rs:227` `TwoAdicMultiplicativeCoset::new(...).unwrap()`, `domain.rs:175` same
  pattern in `create_disjoint_domain` — confirmed both panic when the requested log-size exceeds
  `Val::TWO_ADICITY` (BabyBear = 27).
- ALSO CHECK confirmed: `initial_fri_eval_for_query` and `all_fri_reduced_openings_for_query` carry
  the IDENTICAL unguarded pattern (construct all 5 domains with zero shape/degree validation
  before them at all — these two don't even have a `valid_shape` check before domain construction
  in the original code).
- Traced both audit repro paths to confirm they hit lib-q-stark's `verifier::verify_with_preprocessed`:
  `lib_q_zkp::stark_baby_bear::verify_membership_envelope_bb` -> `verify_membership_bb_bytes`/
  `verify_membership_bb_zk` -> `lib_q_stark::verify` (re-exported `verifier::verify`).
  `lib_q_mve::producer::mve_verify` -> `lib_q_zkp::stark::StarkVerifier::verify` -> same
  `lib_q_stark::verify`. So the lib-q-stark/src/verifier.rs fix directly closes BOTH repros.
- Doc-claim check confirmed: `lib_q_zkp::stark_baby_bear::verify_membership_envelope_bb` doc says
  "Never panics"; `lib_q_mve::producer::mve_verify` doc says "Never panics"; both false pre-fix.
  `lib-q-stark/src/verifier.rs::verify_from_bytes` doc claims byte-size validation "prevent[s] DoS
  attacks" — technically true for huge-blob DoS but misleadingly implies it also covers the
  degree_bits-driven panic, which it does NOT (an 84-byte proof is nowhere near
  MAX_PROOF_SIZE_BYTES).

### RED (observed, host x86_64 — no cross-compilation needed for this item)
Added `lib-q-stark/tests/degree_bits_two_adicity.rs` (new file, plus `lib-q-stark-baby-bear` as a
new dev-dependency in `lib-q-stark/Cargo.toml` — BabyBear, TWO_ADICITY=27, is required to
reproduce this: `Complex<Mersenne31>` used by the existing `dos_protection_tests.rs` has
TWO_ADICITY=32, so `MAX_DEGREE_BITS=30` can never exceed it there). Built one real, honestly-proved
small proof (a 2-column, degree-1-constraint AIR, height 32 -> `degree_bits=5`), then tampered only
`proof.degree_bits` to 27/28/30 before re-verifying with the UNMODIFIED
commitments/opened_values/opening_proof.

To get genuine pre-fix execution evidence (rather than reasoning about it), temporarily reverted
just the fix itself via `git stash push -- lib-q-stark/src/verifier.rs
lib-q-stark-commit/src/domain.rs lib-q-stark-commit/src/pcs.rs lib-q-stark-fri/src/hiding_pcs.rs
lib-q-stark-fri/src/two_adic_pcs.rs` (the new test file is untracked so the stash left it alone),
ran:
`cargo test -p lib-q-stark --test degree_bits_two_adicity -- --nocapture`
Actual output (pre-fix, real panic, not simulated):
```
running 6 tests

thread 'degree_bits_30_rejected_not_panicking' (23912) panicked at lib-q-stark-fri\src\two_adic_pcs.rs:227:78:
called `Option::unwrap()` on a `None` value
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

thread 'degree_bits_28_rejected_not_panicking' (35172) panicked at lib-q-stark-fri\src\two_adic_pcs.rs:227:78:
called `Option::unwrap()` on a `None` value

thread 'verify_with_preprocessed_degree_bits_30_rejected_not_panicking' (31652) panicked at lib-q-stark-fri\src\two_adic_pcs.rs:227:78:
called `Option::unwrap()` on a `None` value
test degree_bits_27_at_two_adicity_boundary_does_not_panic ... ok
test degree_bits_30_rejected_not_panicking ... FAILED
test degree_bits_28_rejected_not_panicking ... FAILED
test verify_with_preprocessed_degree_bits_30_rejected_not_panicking ... FAILED
test baseline_proof_verifies ... ok
test small_degree_bits_still_verifies ... ok

test result: FAILED. 3 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```
Then `git stash pop` to restore the fix.

### Fix — DONE
1. `lib-q-stark-commit/src/pcs.rs`: added `Pcs::try_natural_domain_for_degree` (new default trait
   method, delegates to the infallible one by default — purely additive, zero blast radius).
2. `lib-q-stark-commit/src/domain.rs`: added `PolynomialSpace::try_create_disjoint_domain` (same
   pattern); `TwoAdicMultiplicativeCoset`'s `create_disjoint_domain` now calls
   `try_create_disjoint_domain(...).unwrap_or_else(|| panic!(...))` with a clear message instead of
   a bare `.unwrap()`; its own `try_create_disjoint_domain` override is the genuinely fallible one
   (`Self::new(...)` without `.unwrap()`).
3. `lib-q-stark-fri/src/two_adic_pcs.rs`: same pattern for `natural_domain_for_degree` /
   `try_natural_domain_for_degree` (kept as two independent bodies rather than one delegating to
   the other, because `self.try_natural_domain_for_degree(...)` from within the same
   `Pcs<Challenge, Challenger>` impl is a genuine rustc ambiguity — E0283/E0284, "cannot satisfy
   `<_ as GrindingChallenger>::Witness == Val`" — since neither method's signature mentions
   Challenge/Challenger so method resolution can't pick an instantiation; documented in-code).
4. `lib-q-stark-fri/src/hiding_pcs.rs`: `HidingFriPcs` overrides `try_natural_domain_for_degree`
   too, delegating to the inner `TwoAdicFriPcs` (UFCS call, no ambiguity there).
5. `lib-q-stark/src/verifier.rs`:
   - Added `degree_fits_two_adicity::<F: TwoAdicField>(degree_bits, log_num_quotient_chunks, is_zk)
     -> bool` checking `degree_bits + log_num_quotient_chunks + is_zk <= F::TWO_ADICITY` (exactly
     the brief's formula).
   - `verify_with_preprocessed`, `initial_fri_eval_for_query`, `all_fri_reduced_openings_for_query`
     all reordered: process_preprocessed_trace -> log_num_quotient_chunks -> the new
     `degree_fits_two_adicity` guard (returns `Err(InvalidProofShape)`) -> `valid_shape` (+
     opened-size / commitment-count DoS checks) -> ONLY THEN construct any domain, and now via
     `try_natural_domain_for_degree`/`try_create_disjoint_domain` mapped to
     `Err(InvalidProofShape)` (defense in depth; `degree_fits_two_adicity` already makes the `None`
     case unreachable, but this removes the last theoretical panic surface too).
   - Added `Val<SC>: TwoAdicField` where-bound to `verify`, `verify_with_preprocessed`,
     `initial_fri_eval_for_query`, `all_fri_reduced_openings_for_query`, `verify_from_bytes` (needed
     for `Val::<SC>::TWO_ADICITY`) — propagated to every call site across the workspace that this
     broke (see below).
   - `MAX_DEGREE_BITS`'s doc now explains it is NOT sufficient alone; `verify_from_bytes`'s doc
     corrected to say it only bounds serialized-blob size, not internal field values like
     `degree_bits` (that validation happens in the subsequent `verify()`).
6. Doc corrections (the "Never panics" / DoS overclaim ask):
   - `lib-q-zkp/src/stark_baby_bear.rs::verify_membership_envelope_bb`: kept "Never panics" (now
     true) but added the specific historical caveat (84-byte proof, degree_bits 25..=30 used to
     panic; now `Err(InvalidProofShape)` -> `false`).
   - `lib-q-mve/src/producer.rs::mve_verify`: same treatment (111-byte proof, degree_bits=30).
7. Ripple-effect fixes required by the new `Val<SC>: TwoAdicField` bound (verified via
   `cargo check --workspace --all-features --all-targets`, see below):
   - `lib-q-zkp/src/stark.rs`: `StarkVerifier::<C>::verify` needed `Val<C>: TwoAdicField` added
     (it calls `lib_q_stark::verify` generically).
   - `lib-q-zkp/src/aggregation.rs`: `verify_batch` and the `recursive-proofs-experimental`
     `verify_aggregated_proof` needed the same bound added (both call `StarkVerifier::verify`
     generically).
   - `lib-q-stark/tests/mul_air.rs`: `do_test` needed the bound (calls `verify` directly).
   - Confirmed lib-q-plonky-uni-stark / lib-q-plonky-batch-stark are INDEPENDENT forked copies of
     the whole STARK stack (their own `StarkGenericConfig`/`Pcs`/`PolynomialSpace`/`verifier.rs`,
     not importing lib-q-stark-commit/lib-q-stark-fri) — confirmed by `cargo check
     --workspace --all-features --all-targets` passing with ZERO changes needed in either crate.
   - lib-q-zk-encryption-proof: also unaffected (uses `natural_domain_for_degree` directly with its
     own internally-controlled degrees, not user/verifier-facing in the affected way) — compiles
     unchanged.

### GREEN (observed)
After `git stash pop` restored the fix, re-ran the identical command:
`cargo test -p lib-q-stark --test degree_bits_two_adicity -- --nocapture`
```
running 6 tests
test verify_with_preprocessed_degree_bits_30_rejected_not_panicking ... ok
test degree_bits_28_rejected_not_panicking ... ok
test degree_bits_27_at_two_adicity_boundary_does_not_panic ... ok
test degree_bits_30_rejected_not_panicking ... ok
test small_degree_bits_still_verifies ... ok
test baseline_proof_verifies ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```
`cargo check --workspace --all-features --all-targets` -> `Finished` with zero errors (full
before/after diff: introduced the two new fallible trait methods, the `degree_fits_two_adicity`
guard, and 4 small ripple-fix bound additions; nothing else in the 190-crate workspace needed to
change).
Full test-suite evidence (`cargo test -p lib-q-stark -p lib-q-stark-fri -p lib-q-stark-commit`)
captured in the "Final test/lint runs" section below.

### ADDITIONAL FINDING — not fixed (out of this pass's two-item scope)
`lib-q-zkp/src/stark.rs::StarkVerifier::derive_challenges` (used for recursive-aggregation
challenge replay) has its OWN independent copy of the same unguarded
`natural_domain_for_degree`/`create_disjoint_domain` sequence (lines ~330-360-ish), with no
`degree_fits_two_adicity`-style guard and no shape validation before domain construction. It does
NOT go through `lib_q_stark::verifier::verify_with_preprocessed`, so my fix does not cover it.
Flagging for awareness; lib-q-zkp is outside the task's stated verification scope
(`-p lib-q-ml-dsa`, `-p lib-q-stark -p lib-q-stark-fri -p lib-q-stark-commit`) and this task named
two specific items only.

## Final test/lint runs

All actually executed (real output, not summarized-from-memory):

1. `cargo test -p lib-q-ml-dsa` -> every test binary `test result: ok`, 0 failed anywhere
   (main lib unittests: `114 passed; 0 failed`; 8 further integration-test binaries, all `0
   failed`, 1 pre-existing `#[ignore]`d test unrelated to this change).
2. `cargo test -p lib-q-stark -p lib-q-stark-fri -p lib-q-stark-commit` -> every test binary
   `test result: ok`, 0 failed anywhere (includes the new `degree_bits_two_adicity.rs`: `6 passed;
   0 failed`; 2 pre-existing `#[ignore]`d tests in `lib-q-stark-fri`, unrelated).
3. `cargo clippy -p lib-q-ml-dsa -p lib-q-stark --all-targets -- -D warnings` -> `Finished`, zero
   warnings/errors.
4. `cargo fmt --check` on every touched crate (`lib-q-ml-dsa`, `lib-q-stark`, `lib-q-stark-commit`,
   `lib-q-stark-fri`, `lib-q-zkp`, `lib-q-mve`) -> first run found formatting diffs (import
   ordering, long-line wrapping) introduced by my edits; ran `cargo fmt` to fix, then re-ran
   `--check` -> clean, zero diffs. Re-ran the full test suites (1) and (2) again after the fmt pass
   to confirm no behavior change -> still all green.
5. `cargo check --workspace --all-features --all-targets` -> `Finished`, zero errors (confirms no
   crate outside the two items' declared scope was broken by the `Val<SC>: TwoAdicField` bound
   ripple).
6. `cross test -p lib-q-ml-dsa --target aarch64-unknown-linux-gnu --features simd128 --lib` (real
   QEMU-emulated aarch64 execution via `cross`+Docker) -> `test result: ok. 119 passed; 0 failed`,
   re-run one final time after the `cargo fmt` pass to confirm nothing regressed.

## Anything NOT verified / could not do

- Could not run the actual `wasm-pack`/`wasm32` build+test path (not requested; not touched by
  either fix).
- Did not fix, only observed-and-reported, two OUT-OF-SCOPE findings (see each item's "ADDITIONAL
  FINDING" section above): the `neon::x2::incremental::KeccakStateX2` Shake128-only-init panic
  (Item 1), and `lib-q-zkp::stark::StarkVerifier::derive_challenges`'s independent unguarded
  domain-construction copy (Item 2).
- Did not exhaustively audit every other panic surface in the STARK/FRI/Merkle verification stack
  beyond the specific `degree_bits`/two-adicity class named in the brief (e.g. malformed
  commitment/digest bytes causing a different panic elsewhere) — the "Never panics" doc claims on
  `verify_membership_envelope_bb`/`mve_verify` are now true FOR THIS defect class, which is what
  was asked; I did not attempt to prove them true for all possible malformed inputs.

## Status: DONE (both items fixed, tested RED->GREEN with real execution evidence, full test/lint
suite green, workspace-wide compile confirmed, ready to commit on a branch)
