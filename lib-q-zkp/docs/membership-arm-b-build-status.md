# Membership Arm B (BabyBear / Poseidon2) — Build Status & Findings Log

**Branch:** `feat/membership-arm-b-babybear` · **Card:** `t_437f3820` · **Tier: RED** (functional
build in progress; soundness obligations unmet — see `membership-arm-b-babybear-build-spec.md` §5).

> This is a living log updated each build iteration. It records (a) what is actually built and
> tested, (b) discrepancies found between the build spec / task brief and the real repo, and
> (c) the honest scope. **Green functional tests prove the construction RUNS correctly; they do
> NOT prove soundness.** Arm B stays tier RED until a human cryptographer signs its obligations.

---

## Progress by build-order step

| Step | Item | State |
|------|------|-------|
| 1 | `lib-q-stark-baby-bear` base field (modulus, Montgomery, 2-adic table) | **BUILT + KAT-GREEN** (24 tests; wasm + no_std clean) |
| 1 | …degree-4 binomial extension for FRI challenges + DFT exposure | TODO (deferred to step 6 — only the PCS needs it; steps 2-5 are base-field) |
| 2 | BabyBear Poseidon2 value-level permutation + KAT vs reference | **BUILT + KAT-GREEN** (3 vectors; wasm + no_std clean). F6 RESOLVED: the random-input vector is byte-identical to Plonky3's published **production-constant** KAT (`test_default_babybear_poseidon2_width_16`) — Rust == Python ref == Plonky3 published output |
| 3 | Poseidon2 in-circuit gadget (AIR) + property test | **BUILT + TESTED** (7 tests: in-circuit==permute + valid `check_constraints` + 5 corruption rejections); default-features wasm32 clean — see F7 |
| 4 | wide sponge over BabyBear (t16/r7/c9/w9) | **BUILT + TESTED** (6 tests; reusable `constrain_permutation` factored out) |
| 4 | 2-to-1 compress + wide Merkle path AIR over BabyBear | **BUILT + TESTED** (6 tests; `compress_bb` + `WideMerklePathBbAir`; wide_hash/wide_merkle folded into these) |
| 5 | `unlinkable_membership` AIR over BabyBear | **BUILT + TESTED** (10 tests incl unlinkability-across-ctx / linkability-within-ctx / 5 corruption); domain mirrors Arm A — see F8 |
| 6 | …degree-4 challenge extension F_{p^4} (W=11) | **BUILT + KAT** (30 field tests; 124-bit challenge field) |
| 6 | prover/verifier — **transparent** (BabyBear TwoAdicFriPcs) | **BUILT + WORKS** (prove→verify roundtrip + tampered-reject, depth 4) — see F9 |
| 6 | prover/verifier — ZK/hiding (HidingFriPcs) | NEXT |
| — | dual-arm measurement table | **DONE** — `membership-arm-b-measurement.md` (both arms measured; Arm B proofs ~17× smaller) |
| — | Arm B obligation packet | **DONE** — `membership-arm-b-obligation-packet.md` (6 obligations, GREEN/RED; tier RED) |
| — | red-team / known-weaknesses list | **DONE** — `membership-arm-b-redteam.md` (both arms; 10-item open-questions list) |

**Build complete.** All 6 build-order steps + measurement + obligation packet + red-team delivered.
~58 Arm-B tests green (field 30, Poseidon2 4, lib-q-zkp Arm-B AIRs/prover 24), transparent + ZK
prove→verify working, default-features wasm32 clean. **Tier RED** — functionally built, tested, and
measured; soundness obligations enumerated, none discharged (no human cryptographer sign-off).

---

## Step 1 — `lib-q-stark-baby-bear` (DONE for the base field)

A new workspace crate, the **first `MontyField31` instance in this fork** (see Finding F2). It
supplies the BabyBear parameter struct over the generic `lib-q-stark-monty31`:

- `p = 2^31 − 2^27 + 1 = 2013265921 = 0x78000001`, `MONTY_BITS = 32`,
  `MONTY_MU = 0x88000001` (`p^{-1} mod 2^32`, non-negated convention per `data_traits.rs`),
  multiplicative generator `31`, two-adicity `27`.
- Full 28-entry `TWO_ADIC_GENERATORS` table + `ROOTS_8/16` and inverses.

**Every constant is derived from first principles AND cross-checked against the canonical Plonky3
reference values** by `lib-q-stark-baby-bear/tools/gen_constants.py` (committed, reproducible):

- `MONTY_MU == 0x88000001` ✓ · `2^27` generator `== 0x1a427a41` ✓ · `p−1 = 2^27·3·5` ✓
- chain invariant `TWO_ADIC_GENERATORS[i]^2 == [i−1]` ✓ · `ROOTS_8[1]==[3]`, `ROOTS_16[1]==[4]` ✓

**Tests (24, all green)** via the family harness (`test_field!`, `test_prime_field!`,
`test_prime_field_32/64!`, `test_two_adic_field!`) — same shape Mersenne31 uses. Notably
`test_generator` (31 generates F_p\*), `test_inverse`, and the two `test_two_adic_*` cases
(the 2-adic table is FFT-consistent). **Verified `wasm32-unknown-unknown` clean, `--no-default-features`
clean.** The default host build and the wasm build both take the scalar `no_packing` path (no
avx2/neon target-feature by default) — the same path, so wasm cleanliness is structural, not luck.

---

## Findings / discrepancies (RED-TEAM, honest)

### F1 — The "vendored Plonky3" reference crates do NOT exist in this worktree. **(blocker for steps 2–6)**
The task brief states *"Vendored Plonky3 available: p3-baby-bear, p3-poseidon2, p3-poseidon2-air,
p3-field, p3-fri."* **This is false for `feat/membership-arm-b-babybear`.** `vendor/` contains only
`dudect-bencher` and `proc-macro-error2`. There are no `p3-*` directories and no git deps on
Plonky3. Consequence: the canonical BabyBear **Poseidon2** round constants / internal-diagonal
matrix cannot be "ported verbatim" from a local copy — they must be sourced from upstream
Plonky3/SP1 and **independently KAT-validated** against published Poseidon2 BabyBear test vectors
before any gadget work (build-spec step 2 gate). The base-field constants had no such problem
because they are standard and were reproduced + checked by `gen_constants.py`.

*Mitigation in progress:* treat every Poseidon2 constant the same way as the field constants —
derive/transcribe, then validate against an independent reference vector in a committed test.

### F2 — `lib-q-stark-monty31` had **zero instances** in this fork before this work.
No crate in the workspace instantiated `MontyField31` (Mersenne31 is a *separate, non-Monty*
field). The Monty-31 abstraction was carried but untested in-situ. `lib-q-stark-baby-bear` is the
first instance; the fact that the full `test_two_adic_field!` harness passes is the first evidence
the abstraction is correct end-to-end here. Worth stating in the paper rather than implying a
long-exercised code path.

### F3 — Poseidon2 was **deliberately removed** from `lib-q-stark-monty31` as "non-NIST hash".
`lib-q-stark-monty31/src/lib.rs:10` — `// mod poseidon2; // Removed: non-NIST hash`. So Arm B
re-introduces an algebraic hash the fork's policy previously excluded as a *general primitive*.
This is consistent with Arm A (which already uses an in-circuit Poseidon for the ZK statement, not
as a general-purpose hash), but the paper must frame Poseidon2 as an **in-circuit STARK hash for
the membership relation**, not a NIST-track primitive. Not a soundness bug; a scoping/claims point.

### F4 — `lib-q-poseidon` is Poseidon-**1** (HADES, x⁵, over `Complex<Mersenne31>`), not Poseidon2.
Confirmed: it carries its own caveat that round counts/sponge params are **not** verified for the
GF(p²) extension field (`lib-q-poseidon/src/lib.rs:18–23`). This is the Arm-A "Poseidon STATE over
GF(p²)" off-envelope concern, stated by the code itself. Arm B's whole rationale is to avoid this by
using a textbook prime field — but Arm B's Poseidon2 instance still needs its own KAT + obligation.

### F5 — Caught a wrong constant from an automated source.
A WebFetch of the BabyBear constants returned the modulus decimal as `2061584001`; the correct value
is `0x78000001 = 2013265921`. The hex/formula were right, the decimal was a hallucination. Flagging
because it is exactly the class of error this task exists to keep out of the paper — hence every
numeric constant is now machine-verified by `gen_constants.py`, not transcribed.

---

### F6 — RESOLVED: our permutation matches Plonky3's published **production-constant** binary KAT.
The earlier open-item rested on a false premise — that Plonky3's only width-16 vector used the
**RNG** instance (`new_from_rng_128(Xoroshiro128Plus(1))`). It does not. Plonky3's
`baby-bear/src/poseidon2.rs` *also* contains `tests::test_default_babybear_poseidon2_width_16`, which
runs the **deployed** `default_babybear_poseidon2_16()` (Grain-LFSR: field_type=1, alpha=7, n=31,
t=16) and asserts a **hardcoded `expected: [F;16]` literal** — i.e. a vector computed by Plonky3's
*compiled* code and committed as data. Reading that literal needs no upstream execution (so the
sandbox block on running external crates is irrelevant). The decisive finding:

> Our existing `kat_file_random_input` (in `poseidon2_baby_bear.rs`) uses an input+output that is
> **byte-for-byte identical** to that Plonky3 production literal — and our Rust `permute` reproduces
> it (test green).

So three independent implementations agree on the deployed-constant width-16 permutation for this
input: **(1)** Plonky3's published binary output, **(2)** the independent Python scalar reference
`gen_poseidon2_ref.py` (re-confirmed: parses the constants from source, runs a separate permute,
emits the same `516096821, 90309867, …` output), and **(3)** our Rust. The original worry ("a shared
misreading of the round structure could pass both [Rust + Python]") is now strongly mitigated: a
shared misreading would have to be replicated across all three — including THE reference deployment.

Validation stack, for the record:
- **Constants**: parsed mechanically from the upstream source file by `gen_poseidon2_ref.py`; no
  hand-retyping of the 141 field constants.
- **Linear layers**: each algebraically cross-checked against its documented matrix form (external
  `M_E` block-circulant from `M4=[[2,3,1,1],…]`; internal `1+diag(V)`) by the generator's self-checks.
- **Permutation**: Rust == independent Python == **Plonky3 published binary vector** (this fix).

Residual caveat (honest): all three share the *same constants* (parsed from Plonky3) — by design,
since Arm B deliberately uses the deployed Plonky3 instance; the constants are validated separately
(mechanical parse). Tier RED still holds — this anchors the permutation, it is not a parameter-
soundness proof. **No longer a freeze blocker.**

## Step 2 — value-level Poseidon2-BabyBear (DONE, KAT-green; see F6 for caveat)

`lib-q-poseidon/src/poseidon2_baby_bear.rs`: the deployed Plonky3/SP1 width-16 instance
(`R_F=8=4+4`, `R_P=13`, S-box `x^7`). Constants Grain-LFSR (`field_type=1, alpha=7, n=31, t=16`).
4 tests green (3 KAT + a diffusion smoke), `wasm32` + `--no-default-features` clean. Generator:
`lib-q-poseidon/tools/gen_poseidon2_ref.py`.

### F7 — RESOLVED: the membership verify path now builds **true no_std** (`no_std + alloc`).
The project's wasm path (CI `ci.yml` "full workspace wasm32 compile, default features") builds
`lib-q-zkp` with its **default `std` feature**, and `std` *does* compile for
`wasm32-unknown-unknown` (providing `format!`/`ToString`). That always worked. The gap was the
**true no_std** build — `--no-default-features --features alloc,zkp` — which failed to compile in a
handful of **untouched-by-Arm-B modules**:
- `ip/recovery_policy.rs`, `ip/recovery_policy_hybrid.rs`: `use alloc::vec::Vec` but called `format!`
  (no `use alloc::format`) and `.to_string()` on `AirError` (no `use alloc::string::ToString`).
- `air/mod.rs`: two `alloc::string::String::from(...)` sites tripped `#![deny(unused_qualifications)]`
  in the no_std config (`String` is already imported).

**Fix (this branch):** added `use alloc::format;` + `use alloc::string::ToString;` to both
`recovery_policy*` files, and dequalified the two `String::from` sites in `air/mod.rs`. Purely
additive imports + a cosmetic dequalification — **no behavior change** (recovery_policy 7 + membership
46 lib tests still green; default `std` build + `wasm32` build unchanged). The canonical true-no_std
invocation is now:

```
cargo build -p lib-q-zkp --no-default-features --features alloc,zkp
```

This **compiles clean** (only 4 pre-existing dead-code warnings for unused `*_col` helpers in
`poseidon2_gadget.rs`, present in the std build too). Note `--no-default-features` with *no* `alloc`
can never compile — the crate's core public types (`ZkpProof::data: Vec<u8>`, `ProofMetadata`) require
`alloc`; "no_std" here means *no_std + alloc*, the embedded/wasm sense. Arm B's own lower layers were
already no_std-clean (`lib-q-stark-baby-bear`, `lib-q-poseidon::poseidon2_baby_bear`, the gadget).

## Step 3 — in-circuit Poseidon2-BabyBear AIR gadget (DONE, tested)

`lib-q-zkp/src/air/poseidon2_gadget.rs`: a 285-column single-permutation `Poseidon2Air` (`BaseAir`
width 285 + `Air::eval` over BabyBear, `AB::F = BabyBear`), max constraint degree 7. `generate_poseidon2_row`
replays the value-level `permute_with_trace`. **7 tests green** — `gadget_output_matches_value_level`
(32 inputs: in-circuit digest == `permute`), `constraints_hold_on_valid_trace`
(`check_constraints` accepts 8 honest permutations), and 5 `#[should_panic]` corruption cases (input /
begin-sbox / begin-post / partial-post-sbox / end-sbox) — the under-constrained-column hunt: every
stored column class is pinned. Built on the value-level constants exposed `pub` from
`poseidon2_baby_bear`. Tier RED (computes Poseidon2 correctly + fully constrained ≠ parameters sound).

### F8 — `domain` derivation: build spec says K12, Arm A uses its own Poseidon hash; Arm B follows Arm A.
The build spec's step 5 says `domain = first cells of K12("libq.zkfri.membership.v0")`. But the
**Arm A reference** (`unlinkable_membership.rs`) actually bakes `domain = first cells of
poseidon256_wide_hash(bytes_to_poseidon_field(separator))` — its OWN in-circuit hash of the string,
not K12. Arm B mirrors Arm A (uses `poseidon2_wide_hash_bb` of the separator) for structural
parallelism and to avoid a `lib-q-k12` dependency. **This is purely an off-circuit constant
derivation** — the circuit bakes `DOMAIN_ELEMS` constant cells regardless of how they were computed,
so neither soundness nor the (disjoint, tag-0x01-vs-0x02) wire variants are affected. The separator
STRING is unchanged. **Decision for the cryptographer:** keep the in-family Poseidon derivation
(parallel to Arm A) or switch BOTH arms to a K12-derived constant for cross-family domain
separation — a trivial off-circuit change. Flagged so the paper states the actual derivation, not
the spec's aspirational one.

## Step 5 — unlinkable membership AIR (DONE, tested)

`lib-q-zkp/src/air/unlinkable_membership_baby_bear.rs`: `UnlinkableMembershipBbAir` (1643 cols/row;
public `[root(9)‖ctx(4)‖N(9)]` = 22). Statement `∃(L,t,path): L=H(t) ∧ MerklePath(L→root) ∧
N=H(domain‖t‖ctx)`, revealing only `(root,ctx,N)`. Same-`t` binding is structural (leaf + nullifier
blocks read the same `t` columns). Leaf/nullifier sponges run on every row (max degree stays 7);
row 0 carries the real witness, rows 1.. hash a zero preimage, bindings gated to row 0.
`SECRET_T_ELEMS=6` (~185-bit secret — 3 base-field cells would be only ~93). **10 tests green**:
honest roundtrip (depths 1/2/4/8); **unlinkability-across-ctx**; **linkability-within-ctx**; a
circuit-level "same member under two ctx ⇒ both verify with different public N"; and 5 corruption
rejections (public nullifier / ctx / root, wrong sibling, wrong secret `t`). Tier RED.

### F9 — Membership AIR max constraint degree is 14 (→ FRI log_blowup 4), and a step-1 DFT-roots bug the unit tests missed.
Two things surfaced building the real prover (`stark_baby_bear.rs`):
- **Degree 14 / log_blowup 4.** The Merkle direction-select `left = running + dir·(sibling−running)`
  is degree 2; fed into the degree-7 Poseidon2 S-box it yields a **degree-14** constraint, so the
  FRI `log_blowup` must be **4** (blowup 16). A pure-hash AIR (leaf/nullifier, degree-1 inputs) is
  degree 7 → log_blowup 3. **Arm A has the analogous issue** (degree-2 select × x⁵ ⇒ degree 10).
  *Optimization (noted for the measurement):* storing the direction-selected node input in witness
  columns (with a degree-2 selection constraint) drops the membership AIR to degree 7 / log_blowup 3
  and shrinks proofs — the measurement table should either apply this to both arms or report the
  un-optimized degree honestly so the A-vs-B comparison is apples-to-apples.
- **Step-1 bug caught by the prover.** `lib-q-stark-baby-bear`'s `ROOTS_8`/`ROOTS_16` were length
  3/7 (I followed a misleading `data_traits` "first 3/7" comment); the radix-2 DFT `forward_pass`
  asserts `roots.len() == input.len()/2`, requiring **4/8**. The 30 field unit tests passed anyway
  (they don't exercise the size-16 DFT block); only the end-to-end prover hit it. Fixed + cross-checked
  vs canonical Plonky3 in `gen_constants.py`. **Lesson for the paper: unit-green ≠ exercised** — the
  integration prover is what validated the DFT path.

## Step 6 — BabyBear STARK prover/verifier (transparent DONE; ZK next)

`lib-q-zkp/src/stark_baby_bear.rs`: `BbConfig = StarkConfig<TwoAdicFriPcs<BabyBear, RecursiveDft,
MerkleTreeMmcs<…Shake256…>, ExtensionMmcs>, BinomialExtensionField<BabyBear,4>,
Shake256Challenger32<BabyBear>>`. The challenger is the prime-field `SerializingChallenger` directly
(BabyBear is `PrimeField32`) — no `ComplexFieldChallenger` wrapper (Arm A needs one because its Val
is a complex field). `prove_membership_bb`/`verify_membership_bb` **work end-to-end**: a depth-4
roundtrip proves, verifies, and rejects a tampered nullifier (~4.7s debug). FRI: `log_blowup=4`,
`num_queries=100`, `proof_of_work_bits=16`. Tier RED — a working STARK is not a *sound* one.

## Open scope (honest)

Steps 2–6 are the bulk: a value-level Poseidon2 + an in-circuit Poseidon2 AIR gadget (degree-7
constraints) + ~5k lines of wide-sponge/Merkle/membership AIR + a BabyBear FRI prover/verifier +
the measurement harness. Each must KAT-validate against a reference before the next builds on it.
The base field (step 1) is the foundation and is now solid; the **critical path next** is sourcing
+ validating the Poseidon2 BabyBear constants (F1), since steps 2–6 all sit on them.
