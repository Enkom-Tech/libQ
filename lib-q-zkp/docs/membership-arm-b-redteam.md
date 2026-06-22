# Red-Team / Embarrassment-Avoidance Pass — Membership STARK (Arm A & Arm B)

**Posture:** hostile IACR-reviewer reading, both arms. Goal: surface anything that would be *wrong*
or *embarrassing* in the paper before it ships. Tier for both arms remains **RED**. Where something
is fragile, it is said plainly. This pass is adversarial reading + the evidence already built (KATs,
corruption tests, measurements); it is **not** a substitute for the human cryptographer obligations
(`membership-arm-b-obligation-packet.md`, ADR-113 freeze review).

---

## 1. AIR soundness — under-constrained-column audit (Arm B)

A STARK is only as sound as its constraints: every committed column a malicious prover can choose
must be pinned by a constraint, or it can encode a false statement. For **every stored column class**
in Arm B there is a `#[should_panic]` corruption test proving a tampered value is rejected by
`check_constraints`:

| AIR | Stored columns | Corruption tests (all `#[should_panic]`, green) |
|-----|----------------|-------------------------------------------------|
| `poseidon2_gadget` | inputs, per-round sbox, post, partial post_sbox | input / begin-sbox / begin-post / partial-post-sbox / end-sbox (5) |
| `wide_sponge_baby_bear` | preimage, permutation intermediates, digest | digest / intermediate / preimage (3) |
| `wide_merkle_path_baby_bear` | running, sibling, dir, node intermediates | wrong-sibling / wrong-direction / wrong-intermediate / wrong-root (4) |
| `unlinkable_membership_baby_bear` | t, ctx, leaf/null/merkle intermediates, public root/ctx/N | public-null / public-ctx / public-root / sibling / secret-t (5) |

Plus a positive direction: in-circuit gadget output `==` value-level `permute` over 32 random inputs;
sponge digest `==` clean reference over all input lengths; Merkle roundtrip over depths 1–8. **This is
strong evidence the circuit logic is fully constrained — but it is testing, not proof.** The honest
gaps a reviewer should still press on:

- **Boolean `dir` only forces `dir ∈ {0,1}` via `assert_bool`.** Correct, and the wrong-direction test
  confirms flipping it breaks the hash — but note the AIR does **not** bind the trace height to the
  verifier's claimed depth (same as Arm A's documented metadata caveat). Soundness still holds because
  the verifier folds against its **own trusted root**; a height relabel only re-expresses "fold `H(t)`
  to the real root." Flag for completeness, not a break.
- **Ungated leaf/nullifier rows.** Rows 1.. hash a zero preimage (to keep the sponge constraints at the
  S-box degree on every row); only the row-0 bindings give `t`/`ctx`/`N` meaning. The corruption tests
  cover row-0 tampering; a reviewer should confirm the rows-1.. zero-preimage columns are referenced by
  no binding (they are — read only from `current_slice`, bound by nothing).
- **No negative test currently proves a *cross-permutation* aliasing is impossible** beyond the
  per-class corruption — e.g. that two different permutations' intermediates cannot be swapped. The
  column offsets are disjoint by construction (`constrain_permutation` advances by
  `POSEIDON2_PERM_INTERM_COLS = 269` with no overlap), but an explicit aliasing test would harden this.

## 2. Capacity / digest arithmetic — independent recompute

`p = 2³¹−2²⁷+1 = 2013265921`, `log₂p = 30.9069`. Recomputed from scratch:
- Capacity collision: `9 · 30.9069 / 2 = 139.08 bits ≥ 128` ✓
- Digest entropy: `9 · 30.9069 = 278.16 bits ≥ 256` ✓; output collision `139 ≥ 128` ✓
- A naïve **capacity-5** base-field sponge would give `5·30.9/2 = 77.3 bits` — **insufficient**; the
  paper must not claim 128-bit security for any capacity-5-over-base-field variant. Arm B's capacity-9
  is the fix and the reason its row is wider than a minimal hash.
- **Injective encoding / canonical decode (carry-over hazard).** The ADR-113 review flagged that Arm
  A's byte→field decode used a *reducing* `from_int` (non-injective) rather than `from_canonical_checked`
  in `merkle_root_from_bytes`/`ctx_from_bytes`. **Arm B's membership AIR operates on field elements
  directly** (the public statement is field cells, serialized canonical LE per cell), so the in-circuit
  side has no decode hazard — but the *envelope/FFI layer* that turns wire bytes into the 22 public
  cells (tag `0x02`) is **not yet written**, and when it is, it MUST use a canonical-checked decode
  (reject ≥ p) so the 36/16/36-byte statement fields are injective. **Open item — do not repeat Arm A's
  non-canonical decode in Arm B's envelope.**

## 3. Nullifier — unlinkability & linkability (circuit level)

Tested at the circuit level (`unlinkable_membership_baby_bear.rs`):
- **Unlinkability across ctx:** same `t`, different `ctx` ⇒ different `N` (`unlinkability_across_ctx`),
  and a full circuit proof under two `ctx` values verifies with two *different* public `N`
  (`circuit_nullifier_binds_to_ctx`). So a member can re-prove under a fresh context without the
  verifier linking the two.
- **Linkability within ctx:** same `(t, ctx)` ⇒ identical `N` (`linkability_within_ctx`), so
  double-use under one context collides on `N` (Sybil/double-spend detection).
- **Reviewer caveat:** unlinkability here is the *functional* statement (different ctx ⇒ different
  nullifier value). The *cryptographic* unlinkability (an adversary cannot correlate two nullifiers of
  the same `t` better than guessing) reduces to the pseudorandomness of `H(domain‖t‖·)` — i.e. to
  obligations (i)/(ii)/(vi). Functional ≠ cryptographic; the paper must not overstate.

## 4. FRI conjectured-soundness — sanity for BOTH arms

Both arms: `num_queries = 100`, `proof_of_work_bits = 16`. Conjectured FRI soundness ≈
`num_queries · log₂(blowup) + pow_bits` bits against the query phase, **bounded above by the challenge
field size** for the out-of-domain / DEEP sampling.

- **Arm A — the 62-bit challenge field is the real concern.** Arm A sets `Challenge = ConfigVal =
  Complex⟨Mersenne31⟩` — value field **and** challenge field are the **same ≈ 62-bit** field
  (`stark.rs:75`). Out-of-domain quotient sampling and DEEP-ALI soundness are then capped near **62
  bits**, regardless of query count. For a *deployment* targeting 128-bit soundness this is **marginal
  to inadequate** — the standard Mersenne31 STARK uses a *degree-3 extension over the complex* (≈186
  bits) for challenges, not the bare complex field. **A reviewer would push on this hard. State it
  plainly in the paper: Arm A's challenge field as configured is ~62 bits.**
- **Arm B — better by construction.** `Challenge = BinomialExtensionField⟨BabyBear,4⟩ ≈ 124 bits`,
  distinct from the 31-bit value field. 124 bits is the standard, deployed BabyBear challenge field
  (SP1/Plonky3) and is adequate for ~100–124-bit conjectured soundness. **This is a genuine Arm-B
  advantage** and follows necessarily from BabyBear being too small to self-serve as the challenge
  field. (If 128 is the hard target, a degree-5 extension ≈155 bits is the lever.)
- **Both arms:** `log_blowup` differs (Arm A 2, Arm B 4 as-built / 3 optimized). FRI query soundness
  `~100·log₂(blowup)` is comfortably > 128 in all cases; the binding constraint is the **challenge
  field**, not the query count. **Whether `num_queries=100, pow=16` is deployment-grade depends on the
  target bit-level and the (conjectured, not proven) FRI soundness bound — a cryptographer call.**

## 5. Arm A — the off-envelope Poseidon-over-GF(p²) concern, stated plainly

Arm A's in-circuit hash is **Poseidon-1 (HADES) over `Complex⟨Mersenne31⟩` = GF(p²)**. The standard
Poseidon security analysis (round counts, MDS, algebraic-degree bounds) is stated over a **prime
field**; an **extension-field state is off that envelope**. The code itself says so —
`lib-q-poseidon/src/lib.rs:18–23`: *"the round counts and sponge parameters … have NOT been
independently verified for the `Complex<Mersenne31>` extension field GF(p²) … Do NOT rely on a specific
bit-security level (e.g. 128-bit or 256-bit) … until they have been regenerated and analyzed for
GF(p²)."* This is Arm A's **O1** and the single biggest reason Arm A is RED. **Arm B exists precisely to
avoid this**: a textbook prime field + a deployed Poseidon2 instance. If Arm A's GF(p²) round-count
analysis goes badly under review, Arm B is the fallback with no such hazard.

## 6. Lessons / honesty items already on record

- **F6 — no upstream-binary KAT for the deployed Poseidon2 constants.** The value-level permutation is
  validated against an *independent Python re-implementation* of the same transcribed algorithm +
  matrix-checked linear layers, **not** against a third-party compiled Plonky3 binary (sandbox-blocked).
  A shared misreading could pass both. **Get a deployed-constant KAT vector from an authoritative third
  party before the wire freezes.**
- **F9 — the prover caught a step-1 bug the unit tests missed.** `ROOTS_8`/`ROOTS_16` were truncated
  (3/7 vs the required 4/8 = `input/2`); 30 field unit tests passed, but the size-16 DFT block in the
  real prover panicked. **Unit-green ≠ exercised.** Now fixed + cross-checked vs canonical Plonky3.
- **Arm B membership is degree 14 / `log_blowup 4` as built** (Merkle dir-select degree-2 × x⁷) — an
  implementation choice (the gadget folds ARC where Arm A stores it), not a fundamental property.
  Optimized (store the selected node input) it is degree 7 / `log_blowup 3`. The paper's A-vs-B blowup
  row should attribute the *fundamental* gap to `x⁷` vs `x⁵` (3 vs 2), not to this artifact. The ~17×
  smaller-proof headline is field/width-driven and unaffected.
- **Poseidon2 was deliberately removed from `lib-q-stark-monty31` as "non-NIST hash" (F3).** The paper
  must frame Poseidon2 as an **in-circuit STARK hash for the membership relation**, not a NIST-track
  general primitive — consistent with Arm A using an in-circuit Poseidon.

---

## 7. Known weaknesses / open questions (the list)

1. **(cryptographer)** Poseidon2 round counts `R_F=8/R_P=13` at the **128-bit** target for
   `(BabyBear, α=7, t=16)` — confirm vs ePrint 2023/323; confirm the deployed count's target bit-level.
2. **(cryptographer)** Internal-diagonal / external-MDS width-16 no-subspace-trail check — re-run or cite.
3. **(cryptographer)** Formal **ZK simulator** for the membership AIR with the hiding PCS (incl. the
   ungated zero-preimage rows). Mechanism present; argument not written.
4. **(deployment)** **Arm A's 62-bit challenge field** — almost certainly inadequate for a 128-bit
   deployment as configured; needs a larger challenge extension. (Arm B's 124-bit is fine; 155 if 128 is hard.)
5. **(deployment)** Is `num_queries=100, pow=16` deployment-grade for the target bit-level? Conjectured
   FRI soundness, not proven.
6. **(engineering) — DONE.** Arm B statement-bytes codec + FFI verify entry implemented in
   `stark_baby_bear.rs` (`membership_statement_bytes_bb` / `membership_statement_from_bytes_bb` /
   `verify_membership_bb_bytes`): `root(36)‖ctx(16)‖N(36)` = 88 bytes, each cell canonical LE `u32`,
   decode **canonical-checked** (rejects any limb ≥ p ⇒ injective; no `from_int` reduction). Tests
   cover roundtrip, non-canonical rejection (`==p` and `0xFFFFFFFF`), wrong-length, verify-from-bytes
   roundtrip + tamper + malformed-no-panic. The 1-byte instantiation tag (`0x02` vs Arm A `0x01`)
   remains the consuming envelope's responsibility (the downgrade guard).
7. **(validation) — DONE.** Deployed-constant Poseidon2 KAT from an authoritative third party (F6)
   obtained: our `kat_file_random_input` is byte-identical to Plonky3's published production-constant
   vector (`test_default_babybear_poseidon2_width_16`, the `default_babybear_poseidon2_16()` output),
   and our Rust `permute` reproduces it — Rust == independent Python ref == Plonky3 published output.
   The premise of the old item (Plonky3 only ships an RNG-instance vector) was false. No longer a
   freeze blocker.
8. **(domain)** F8 — confirm in-family Poseidon-derived `domain` vs a K12-derived constant; pick one for
   both arms.
9. **(perf, optional)** Reduce Arm B membership to degree 7 (store the direction-selected node input)
   for a fair `log_blowup` row and ~halved proofs.
10. **(scope) — DONE.** `lib-q-zkp` true-no_std (`--no-default-features --features alloc,zkp`) now
    builds clean: added the missing `alloc::format` / `alloc::string::ToString` imports to
    `ip/recovery_policy*` and dequalified two `String::from` sites in `air/mod.rs` (F7 resolved). The
    membership FFI verify path is now true-no_std-buildable; no behavior change (53 lib tests green,
    std + wasm32 builds unchanged).

**Bottom line:** no circuit-soundness break was found in Arm B's AIRs (every stored column is pinned and
corruption-tested); the open items are the genuine cryptographic obligations + a handful of
engineering/validation hardening tasks. Arm B's distinguishing, defensible win is that its soundness
gate has **no off-envelope field hazard** — and, measured, its proofs are **~17× smaller** than Arm A's.
Both arms remain **tier RED** pending the human cryptographer.
