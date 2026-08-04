# Cryptographer sign-off register (repo-wide RED items)

> **RED — every entry below awaits human cryptographer sign-off.** No item here carries a "secure"
> claim. Constructions are built and self-reviewed (estimators run, adversarial self-review, KATs) but
> **none is proven or signed.** This register is the single index of what a two-human cryptographic
> review must discharge before any of these can be called secure, wire-frozen, or wired downstream.
> Self-review has repeatedly caught real defects in these constructions; that does not substitute for
> sign-off.

Three independent sign-off gates are open. Each has its own detail docs; this file states the
**blocking claim**, the **status**, and the **concrete open item** per gate, with load-bearing numbers.

| # | Gate | Crate(s) | Detail docs | State |
|---|------|----------|-------------|-------|
| A | Anon-cred one-out-of-many membership | `lib-q-lattice-zkp` | `lib-q-lattice-zkp/docs/anon-cred-oom-signoff-brief.md` (+ 7 companions) | design + test-only oracles |
| B | Membership AIR soundness/ZK (Arm A + Arm B) | `lib-q-zkp` | `lib-q-zkp/docs/membership-adr113-freeze-gate-review.md`, `…-arm-b-obligation-packet.md`, `…-arm-{a,b}-soundness-params.md` | built + wire-frozen v0 |
| C | Threshold-KEM CCA closure + its ZK encryption proof | `lib-q-threshold-kem-lattice`, `lib-q-zk-encryption-proof` | those crates' `README.md` / `src/lib.rs` + `dev/conformance/…` design docs | KEM shipped (KAT v1); proof partial |

---

## Gate A — Anon-cred one-out-of-many membership (`lib-q-lattice-zkp`)

**Blocking claim.** A log-size lattice one-out-of-many membership proof (Groth–Kohlweiss selector fold
over `R_q = Z_q[X]/(X²⁵⁶+1)`, `q = 8380417`, on the shipped ABDLOP substrate) is knowledge-sound,
binding, and HVZK-unlinkable at parameters fitting a 160 KiB presentation budget.

**Status.** Full protocol equations + extractor + simulator drafted; six of seven residuals
**argued-conditional**, each with ≥1 real defect found and fixed during self-review. Artifacts are
**test-only oracles + design docs**, consumer-agnostic, held on the never-merged branch
`spike/anon-cred-oom-red` (never on `main` — see "What signed off requires" below).

**The single reviewable packet:** `anon-cred-oom-signoff-brief.md` — it gathers the six results and
their open lists. Do not review the sub-docs cold; start there. The load-bearing open items it
consolidates:
- **Three distinct estimator runs still owed (do not merge):** (1) binding M-SIS at the *final*
  `β_SIS` (set by the mandatory `Π_norm` + the RO-drawn `‖c̄‖_op` p99.99≈34 tail, NOT the honest
  `≈3.5e5`); (2) small-secret **decision-LWR** for the nullifier at sample ceiling `κ_nf·N·#realms`;
  (3) **M-LWE on the credential matrix `A_c`** hiding the fold objects (distinct from the 326-bit
  proof-system Ext-M-LWE).
- **Assumption I1** (issuance yields exact short openings) — load-bearing for single-difference binding.
- **Proofs:** §6 one-first-order-layer completeness; the `(k+1)`-Vandermonde binding + forking
  accounting; `Δ_reject` as a *proven* Rényi/statistical bound; LNP22 `Πquad/Πlin/Πsim` composition.
- **Protocol additions to confirm (already edited in):** `Π_norm` on `(r_ℓ,m_ℓ,a_j)`; `(V-link) +W_γ`;
  `z_γ` uniform-mask; `Ĉ` round-1 + `(V-tie)`; `nf := HighBits` via `Decompose` with `α|(q−1)`.
- **Phrasing:** per-realm privacy (unlinkability across realms / among distinct creds in a realm).

---

## Gate B — Membership AIR soundness + ZK (`lib-q-zkp`, Arms A & B)

**Blocking claim.** Two STARK/FRI membership proofs for the frozen statement
`libq.zkfri.membership.v0` (`MerkleVerify(root,L=H(t),path) ∧ N=H(domain‖t‖ctx)`, revealing only
`(root, ctx, N)`) are 128-bit sound and zero-knowledge. Both arms are RED; Arm B does **not** inherit
Arm A's obligations.

**Status.** Circuits built, wire v0 frozen; commitment-layer bit-counts computed; hash algebraic-
security and the ZK simulators are **argued or implemented-but-unwritten**, not proven.

**Soundness parameters to cite (PCS/commitment-layer only — assume AIR sound+complete, which is RED):**
- **Shared binding term:** SHAKE256 Merkle commitment → 128-bit collision (Cat-2); `num_queries=96`,
  `PoW=20`. Reproduce via `lib-q-zkp/tools/fri_soundness.py`.
- **Arm A:** value field `Complex<Mersenne31>` = GF(p²), p=2³¹−1; challenge field GF(p⁶) (≈186 b);
  `log_blowup=3`; AIR degree 5 (`x⁵`). Overall **128** (Johnson provable 164 / capacity-conj
  308c·298pq / SHAKE 128).
- **Arm B:** BabyBear p=2³¹−2²⁷+1; challenge field `F_{p⁵}` (≈155 b); `log_blowup=4`; AIR degree 7
  (`x⁷`); Poseidon2 t=16, R_F=8, R_P=13, sponge rate 7 / capacity 9 / digest 9. Overall **128**
  (Johnson provable 212 / capacity-conj 404c·394pq / sponge-collision 139 / SHAKE 128).
- PQ model = mainstream QROM (FS preserves RBR soundness; Grover halves only the PoW grinding 20→10;
  SHAKE256 Cat-2, BHT collisions not counted). Max-conservative model rejected (documented).

**Open items the human owes:**

*Arm A (obligations O1–O4):*
- **O1 [blocking] — Poseidon-256 round security over GF(p²):** prove 8 full + 60 partial, `x⁵`,
  width 7 resist Gröbner/interpolation/higher-order-diff at ≥128 bits **over the extension field**
  (off the standard prime-field envelope). *Argued* (§7 derivation; subfield-invariance closed via
  generic nonzero-imaginary round constants). Owes: confirm the constant-genericity subfield defense +
  its base-field-only Cauchy-MDS dependency; accept residual re future cryptanalysis.
- **O2 — capacity-5 truncated-sponge collision/2nd-preimage ≥128:** *argued* (155-bit), conditional on
  O1 (sponge-indifferentiability premise = O1's PRP).
- **O3 — domain-separation adequacy** (baked 2-cell domain, `domain‖t‖ctx` ordering, no leaf↔nullifier
  cross-collision): *argued*, conditional on O1/O2. Owes: confirm global domain-string uniqueness.
- **O4 [blocking residual] — formal ZK simulator:** PPT simulator from `(root,ctx,N)` for the AIR +
  HidingFriPcs/salted-MMCS/Kt128Rng over GF(p²). Mechanism *implemented* (L1 weak-RNG + L2 guessable-
  seed leaks fixed in code); **no formal write-up**. Owes: write the simulator; close the masking-
  degree ≥ `#queries(100)+#OOD+1` vs opening-count budget at `log_blowup≥3`; re-confirm 5-of-7
  truncated openings leak nothing.
- (O5 depth-confusion guard, O6 canonical byte-decode: closed in code, confirm cross-check.)

*Arm B (obligations (i)–(vi)):*
- **(i) [RED] round counts R_F=8, R_P=13 at α=7, t=16 resist attacks at 128:** *argued* (matches
  deployed Plonky3/SP1 verbatim, constant-KAT anchored); count script **not** independently re-run.
  Owes: confirm against ePrint 2023/323 for the 128-bit target; confirm 128-vs-100 intent; `x⁷` forced.
- **(ii) [RED] MDS / internal diagonal over width 16 (no subspace trails):** *argued* (canonical
  values, cross-checked); irreducibility check **not** re-run for width 16. Owes: re-run or cite upstream.
- **(v) domain-separation constant derivation (F8):** off-circuit choice, soundness-neutral,
  **untouched**. Owes: decide in-family Poseidon2 vs K12-derived (string frozen either way).
- **(vi) [RED] ZK simulator** for this AIR (incl. row-0/ungated rows) under Hiding PCS/MMCS/Kt128Rng:
  mechanism *implemented + roundtrip-tested*, **no formal simulator**. Owes: write it; confirm ungated
  leaf/nullifier rows (hashing a zero preimage) leak neither `t` nor `ctx`.
- ((iii) capacity-9 collision ≈139, (iv) 9-cell digest ≈278: GREEN arithmetic, conditional on (i)/(ii);
  confirm (iv)'s wide-squeeze read is indifferentiability-acceptable.)

---

## Gate C — Threshold-KEM CCA closure + ZK encryption proof

Two crates, one gate: the KEM's remaining CCA boundary and the proof that would close it
assumption-free.

### C1 — `lib-q-threshold-kem-lattice`

**Blocking claim.** No formal threshold IND-CCA theorem: an inside coalition probing with **malformed**
ciphertexts can defeat per-partial flooding by amplification (~63 queries), because the FO⊥
re-encryption check fires only at `combine`. Security is conditional on a chosen-ciphertext **closure**
being in force.

**Status.** PROVISIONAL / unsigned. Core KEM built + hardened (branchless codec, structural guards,
zeroization, NTT accumulation, KAT-frozen v1 wire; adversarially self-reviewed 2026-07-10). Estimator-
gated, no human sign-off, no CCA theorem.

**Load-bearing numbers.** Ring `R_q=Z_q[X]/(X¹⁰²⁴+1)`, `q≈2⁴⁸`, MU=6, KAPPA=9. Dec-key hiding
(recover `r` from `t0=B0·r`): **M-LWE 169-bit quantum core-SVP, β=636**. Ciphertext hiding: distinct
M-LWE, n=6144, uniform error, easiest swept point **≈2⁹⁷¹ rop**. Noise worst-case `≈2⁴⁴` vs `q/4≈2⁴⁶`
⇒ FO decryption-failure **δ=0**. Flooding `2⁴⁰` per partial; enc-error bound `2²⁰`.

**Open item.** Sign off on the closure. Two offered: (i) *deployable* — authenticated encapsulator +
enforceable `DecapBudget` (`untrusted()` capped below the ~63-query probe; `authenticated()` = 2²⁰
budget) + DKG key rotation; (ii) *assumption-free* — the ZK proof in C2. Sign-off must confirm a
norm-only well-formedness proof is genuinely insufficient (the `f=δ·unit_k`, `‖f‖=1`
direction-not-magnitude argument) and that the deployed closure is sound.

### C2 — `lib-q-zk-encryption-proof`

**Blocking claim.** A ZK-STARK PoK-of-`µ` for `R_enc` (knowledge of `µ` with
`(e,f,g)=Expand(SHAKE256(seed‖pk_digest‖µ))`, `p=B0ᵀe+f`, `v=⟨t0,e⟩+g+encode(µ)`) is sound **and**
zero-knowledge — forcing the ciphertext noise pseudorandom so the C1 probe cannot be aimed. Explicitly
**RED/unsigned, not production-ready.**

**Status — built vs remaining.** BUILT + self-reviewed-sound + fuzzed (all still RED, self-review
only): `ShakeSpongeAir` (R1), `Ternary`/`BoundedSamplerAir` (R2), the non-native `Z_q` toolkit
(`ModReduce`/`HornerFold`/`RelationCheck`/`EncodeMuFold`, R3; 36k-tamper fuzz, zero survivors), LogUp
join-1 + `XofStreamTableAir` + `SqueezeByteAir`. REMAINING/RED: sponge must **Send** its rate limbs so
sampler bytes are bound in-proof (byte-provenance — the critical open item); `LatticeCheckAir`
composition wiring (boundary openings feeding folds into `RelationCheck`, both LogUp joins, shared FS
`ζ`, µ↔sponge transitive binding, offset disjointness); `prove_batch` assembly; Hiding-FRI **not
proven to hide** `µ`/`(e,f,g)`; no ZK proof, no soundness proof.

**Load-bearing numbers.** `R_enc` sufficiency: grinding `µ` to steer `f` infeasible at **≈2⁻¹¹⁰⁰⁰
/draw**. Fold (Schwartz–Zippel) soundness ≤ `(2N−2)/q ≈ 2⁻³⁷` per point; **m=4** points ⇒ `≤2⁻¹⁴⁸`.
This proof's own STARK config: Mersenne31, GF(p²) value field, `log_blowup=2`, `num_queries=64`,
`pow=16` ⇒ ≈128 *conjectured* (positional-binding collision `≈2⁻⁶²` over GF(p²)). Target ring `q=2⁴⁸−2¹⁴+1`,
N=1024; `Z_q` MAC gadget 14-bit limbs × 4 (corrected from an unsound 16-bit/3-limb draft); `ζ`
rejection-sampled (bare mod-q biases ≈2⁻³⁴). Scale ≈5M constraints, inside the 2²⁴-row ceiling.

**Open items (design reviewer items 1–6).** (1) confirm randomized-trace + hiding-PCS actually hide
`µ` and all `(e,f,g)` (sponge first-block bytes 70..102 = `µ` must be blinded); (2) fold-soundness
composes with STARK + LogUp, no challenge reuse between fold `γ/ζ` and LogUp `α,β`; (3) the explicit
monotone `stream_pos` transition constraint (load-bearing beyond the lookup) prevents reorder around
rejections; (4) fixed height `H` + µ-independent LogUp balance hide the rejection count,
`Pr[draws>H]<2⁻¹²⁸`; (5) state the *provable* STARK bound in any claim, not the conjectured 128;
(6) non-native quotient/remainder range bounds tight, 7-limb accumulator never overflows.

---

## What "signed off" requires (all gates)

For each gate, two independent human cryptographers must: accept the stated assumptions, confirm the
estimator instances at the **deployed** parameters (not the draft numbers), and check the soundness/ZK
proofs actually exist and compose. Until then every gate stays RED — test-only where noted, wire-frozen
but unsigned where noted, and **not** to be advertised as secure. Gate A additionally must not be
**merged to `main`** or wired downstream until signed.

This previously read "must not be committed". That was reworded, not relaxed: leaving ~3,800 lines
of drafted protocol on a single machine's working tree is itself a risk (unbacked, and it blocks
clean gating in `lib-q-lattice-zkp`), and it is not what protects `main` from unsigned crypto —
*not merging* is. The work is therefore preserved on the never-merged branch
`spike/anon-cred-oom-red`. The no-reachability property is structural, not a promise: every Gate A
module carries an inner `#![cfg(test)]` **and** is declared `#[cfg(test)] mod` (private, not `pub`)
in `sigma/mod.rs`, so no shipped build and no downstream crate can name them. Merging that branch,
or making any of those modules `pub`, is the thing the gate forbids.

---

## CORRECTION (appended 2026-08-04, release/0.0.10 @ 2f0d43c, by post-hoc triage of `spike/anon-cred-oom-red`)

This file was recovered verbatim (byte-for-byte, `git show spike/anon-cred-oom-red:docs/crypto-signoff-register.md`)
from the never-merged spike branch, where it was the only copy in the repo (absent from `main`,
`release/0.0.10`, and `wip/pvtn-v1-construction7` before this recovery). The body above is
unedited. This note records what was checked for staleness against `release/0.0.10` and what a
reader should know before following its links from *this* tree.

**Gate A doc/module paths do not resolve in this tree — by design, not by rot.** The register's
Gate A row and detail-packet reference (`lib-q-lattice-zkp/docs/anon-cred-oom-signoff-brief.md`
+ companions) are branch-relative to `spike/anon-cred-oom-red`. OBSERVED:
`git ls-tree release/0.0.10 -- lib-q-lattice-zkp/docs/` returns exactly one file,
`pvtn-v2-unlinkable-membership.md` — none of the nine `anon-cred-oom-*.md` docs (`-binding`,
`-bounding`, `-hvzk`, `-invariant`, `-nullifier`, `-obligations`, `-protocol`, `-signoff-brief`,
`-spike`) are present. Correspondingly `git show release/0.0.10:lib-q-lattice-zkp/src/sigma/mod.rs`
has no `binary_range`, `nullifier_consistency`, or `one_out_of_many` module declarations — those
three source files simply don't exist on `release/0.0.10` (`git ls-tree spike/anon-cred-oom-red --
lib-q-lattice-zkp/src/sigma/` has 12 files where `release/0.0.10` has 9). This is the intended
state per the closing section above ("preserved on the never-merged branch") and per this
release's triage of the same branch (see the commit-by-commit classification: only `facfc87`, the
spike commit itself, was withheld — everything recoverable from the other nine commits already
landed by other routes). It is flagged here only so a reader on `release/0.0.10` who clicks these
links knows to look on `spike/anon-cred-oom-red`, not to conclude the docs were lost.

**Minor: Gate C2's "README.md / src/lib.rs" reference.** `lib-q-zk-encryption-proof/README.md`
does not exist on `release/0.0.10` (`git cat-file -e` fails: "does not exist in
'release/0.0.10'") — OBSERVED it also does not exist on `spike/anon-cred-oom-red` at the commit
this file was read from, so this is not new rot, just a standing overstatement in the original
text; `src/lib.rs` (which does exist on both) carries the design docs for that crate.

**Checked and found NOT stale (no correction needed):**
- All three other crates the register names — `lib-q-lattice-zkp`, `lib-q-zkp`,
  `lib-q-threshold-kem-lattice`, `lib-q-zk-encryption-proof` — exist on `release/0.0.10`
  (`git ls-tree -d release/0.0.10 -- <crate>` non-empty for each).
- All nine Gate B detail docs (`membership-adr113-freeze-gate-review.md`,
  `membership-arm-a-soundness-params.md`, `membership-arm-b-babybear-build-spec.md`,
  `membership-arm-b-build-status.md`, `membership-arm-b-measurement.md`,
  `membership-arm-b-obligation-packet.md`, `membership-arm-b-poseidon2-gadget-design.md`,
  `membership-arm-b-redteam.md`, `membership-arm-b-soundness-params.md`,
  `membership-wire-v0-FROZEN.md`) and `lib-q-zkp/tools/fri_soundness.py` resolve on
  `release/0.0.10`.
- Gate C's `dev/conformance/integration/lib-q-threshold-kem-lattice/*` design docs resolve
  identically on both `release/0.0.10` and `spike/anon-cred-oom-red`.
- The register does **not** name any of the four crates deleted this release cycle
  (`lib-q-threshold-sig`, `lib-q-double-kem`, `lib-q-threshold-kem` [distinct from
  `lib-q-threshold-kem-lattice`, which it does name and which is still present], `lib-q-fhe`) —
  `git ls-tree -d release/0.0.10 -- <name>` is empty for all four, and none of the four strings
  appear in the register body above. No dangling reference to a deleted crate exists in this file.

**Not checked in this pass (SUSPECTED-accurate, not verified):** the numeric claims themselves
(β_SIS, the M-LWE/M-LWR bit estimates, MU/KAPPA/ring parameters, the STARK soundness bit-counts) —
this correction only re-verified that named files, crates, and modules still exist and resolve to
the described structure, not that the underlying security-parameter arithmetic is still current.
Re-running the cited estimator scripts / `fri_soundness.py` against `release/0.0.10`'s actual
constants was out of scope for this recovery pass.
