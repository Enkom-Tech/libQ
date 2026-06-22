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
| 2 | BabyBear Poseidon2 value-level permutation + KAT vs reference | **BUILT + KAT-GREEN** (3 reference vectors; wasm + no_std clean) — see Finding F6 on validation level |
| 3 | Poseidon2 in-circuit gadget (AIR) + property test | DESIGN LOCKED (membership-arm-b-poseidon2-gadget-design.md); impl + tests next |
| 4 | wide sponge/hash/merkle/merkle_path over BabyBear (t16/r7/c9/w9) | NOT STARTED |
| 5 | `unlinkable_membership` AIR over BabyBear | NOT STARTED |
| 6 | prover/verifier (BabyBear `TwoAdicFriPcs` config), transparent + ZK | NOT STARTED |
| — | dual-arm measurement table | NOT STARTED |
| — | Arm B obligation packet | NOT STARTED |
| — | red-team / known-weaknesses list | accumulating in this doc |

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

### F6 — Poseidon2 value-level KAT is cross-implementation, NOT a third-party binary KAT. **(open item)**
The deployed Poseidon2-BabyBear constants live in Plonky3's `baby-bear/src/poseidon2.rs`. The
in-file test vector there uses **RNG-generated** constants (`new_from_rng_128(Xoroshiro128Plus(1))`),
not the deployed Grain-LFSR constants Arm B needs — so it cannot directly anchor our permutation.
The intended gold-standard anchor (compile upstream `default_babybear_poseidon2_16()` and diff one
output) was **blocked by the sandbox** (executing an external git dependency is disallowed; the repo
expects vendored crates). Current validation, in lieu of that:
- **Constants**: parsed mechanically from the upstream source file by `gen_poseidon2_ref.py`
  (source → parser → emitted Rust literals); no hand-retyping of the 141 field constants.
- **Linear layers**: each is algebraically cross-checked against its *documented matrix form* in
  the generator (external `M_E` block-circulant from `M4=[[2,3,1,1],…]`; internal `1+diag(V)`),
  so the layer formulas are validated, not just copied.
- **Permutation**: the Rust impl (`lib-q-poseidon/src/poseidon2_baby_bear.rs`) reproduces output
  vectors from an **independent Python re-implementation** of the same algorithm (3 KATs green).

This is honest but weaker than an upstream-binary KAT: a *shared* misreading of the round structure
could pass both. **Open item:** obtain a deployed-constant KAT vector from an authoritative third
party (published vector, or upstream binary if the sandbox is later allowed) before the wire freezes.

## Step 2 — value-level Poseidon2-BabyBear (DONE, KAT-green; see F6 for caveat)

`lib-q-poseidon/src/poseidon2_baby_bear.rs`: the deployed Plonky3/SP1 width-16 instance
(`R_F=8=4+4`, `R_P=13`, S-box `x^7`). Constants Grain-LFSR (`field_type=1, alpha=7, n=31, t=16`).
4 tests green (3 KAT + a diffusion smoke), `wasm32` + `--no-default-features` clean. Generator:
`lib-q-poseidon/tools/gen_poseidon2_ref.py`.

## Open scope (honest)

Steps 2–6 are the bulk: a value-level Poseidon2 + an in-circuit Poseidon2 AIR gadget (degree-7
constraints) + ~5k lines of wide-sponge/Merkle/membership AIR + a BabyBear FRI prover/verifier +
the measurement harness. Each must KAT-validate against a reference before the next builds on it.
The base field (step 1) is the foundation and is now solid; the **critical path next** is sourcing
+ validating the Poseidon2 BabyBear constants (F1), since steps 2–6 all sit on them.
