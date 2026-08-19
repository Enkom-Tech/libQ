# Compressed Post-Quantum Silent OT from Isogenies (ePrint 2026/1444) — radar disposition

Status: **radar / out of scope — not adopted (tracked).** This note dispositions IACR
ePrint 2026/1444 for the `iacr-radar` import (board card `ENK-481`). It is a triage record,
not a finding against any shipped primitive: the paper builds a primitive family (silent
oblivious transfer via pseudorandom correlation functions) that `lib-q` does **not**
implement and, today, has no surface to plug into.

- **Paper:** "Compressed Post-Quantum Silent OT from Isogenies."
  <https://eprint.iacr.org/2026/1444>
- **Authors:** Pouria Fallahpour, Arthur Herlédan Le Merdy, Mahshid Riahinia.
- **Category:** cryptographic protocols (secure computation — oblivious transfer / PCF).
- **Keywords (from ePrint):** Oblivious Transfer, Post-Quantum, Isogeny-Based, Group
  Actions, Quantum Random Oracle, Constrained Pseudorandom Functions.
- **Radar classifier verdict:** `medium (conf 0.85) — Post-Quantum OT`.

## Disposition: post-quantum, but no in-tree surface and a non-standardized assumption

Unlike `ENK-459` (which was a *quantum-security* false positive), this paper's
classification is **correct**: the construction is genuinely post-quantum — it is built on
an isogeny **group action** and comes with a **QROM** security proof. So it is **not**
rejected on threat-model grounds. It is dispositioned out of scope for three independent,
structural reasons:

1. **`lib-q` ships no oblivious transfer, PCF, VOLE, or secure-computation layer.** The
   workspace is KEMs (`lib-q-ml-kem`, `lib-q-hqc`, `lib-q-cb-kem`), signatures
   (`lib-q-ml-dsa`, `lib-q-fn-dsa`, `lib-q-slh-dsa`, `lib-q-mayo`, `lib-q-ring-sig`,
   `lib-q-threshold-raccoon`), AEAD/hash/symmetric, ZKPs (`lib-q-stark`/`lib-q-plonky`,
   `lib-q-lattice-zkp`), DKG and threshold KEM. There is **no two-party correlation
   generation, no OT, and no MPC protocol**. The only `VOLE`/`MPC` strings in the tree name
   the **VOLE-in-the-Head** (FAEST) and **MPC-in-the-Head** (Picnic) *proof* paradigms in
   [`lib-q-sig/docs/FAEST_EVALUATION.md`](../../lib-q-sig/docs/FAEST_EVALUATION.md) and the
   reserved registry entry in `lib-q-core/src/algorithm_registry.rs` — not correlation
   generation. There is nothing here for this PCF to non-interactively feed.

2. **`lib-q` has no isogeny / group-action arithmetic.** The library's asymmetric hardness
   comes from module lattices (ML-KEM/ML-DSA/FN-DSA), codes (HQC, Classic McEliece),
   hash-based signatures (SLH-DSA), and multivariate quadratics (MAYO). There is **no
   CSIDH/SIDH, no class-group / effective-group-action layer** anywhere in the workspace.
   The paper's PCF, its CPRF core, and its assumption all sit on top of a cryptographic
   group action that `lib-q` would have to introduce from scratch.

3. **Security rests on a newly-introduced, non-standardized assumption.** The construction's
   hardness is the **parallelization problem with auxiliary inputs**, which the authors
   *introduce* in this paper as an extension of the group-action parallelization problem
   (the isogeny analogue of computational Diffie–Hellman). It is analyzed by the authors but
   is not part of any standardization process. `lib-q`'s security posture centers on
   NIST-standardized or NIST-selected primitives plus a small set of well-vetted alternatives
   (see [`docs/security.md`](../security.md)); adopting a fresh group-action assumption would
   front-run external review.

Reasons (1) and (2) alone are dispositive today: even setting the assumption aside, the
construction is a green-field addition (new backend + new protocol layer), not an
improvement, attack, or interop target for anything `lib-q` currently ships. Recorded here so
the card closes on a documented rationale rather than being silently dropped, matching how the
other `iacr-radar` cards (`ENK-457`, `ENK-458`, `ENK-459`, `ENK-469`, `ENK-472`, `ENK-541`)
were folded into the tree.

## What the paper actually contains (from the abstract)

- **Compact post-quantum PCF for OT.** A pseudorandom correlation function (PCF, Boyle et
  al., FOCS 2020) whose two short keys let each party *locally* generate large numbers of
  random OT-correlated pairs — `(r_0, r_1)` for the sender and `(b, r_b)` for the receiver —
  non-interactively ("silent" OT).
- **Key sizes ≈ 100 kB, invariant in the target OT count.** The authors report keys roughly
  seven times smaller than the most compact state-of-the-art post-quantum alternatives, and
  approaching pre-quantum PCF compactness (they cite ≈ 30 kB pre-quantum). Prior post-quantum
  PCFs rely on lattices or LPN-style assumptions and produce much larger keys that also grow
  with the target count.
- **Estimated throughput ≈ 7 OTs/second**, with an implementation provided by the authors.
- **First QROM security proof of a post-quantum PCF** (their claim).
- **Core primitive: a compact constrained PRF (CPRF) for inner-product-membership
  predicates**, built on the isogeny group action.
- **New assumption: the parallelization problem with auxiliary inputs**, with an extended
  analysis in the paper.

## Nearest in-tree neighbor (for future reference)

The closest existing crate is [`lib-q-prf`](../../lib-q-prf/) (Legendre / Gold power-residue
PRFs over `F_p`). It is a *plain* PRF, **not** a constrained PRF, and it is **not** oblivious:
[`lib-q-prf/DESIGN.md`](../../lib-q-prf/DESIGN.md) already records that "Gold / power-residue
OPRF literature (e.g. VOLE-based two-party evaluation) is relevant for **oblivious**
evaluation, not implemented here." That note is the honest boundary; this paper's CPRF sits
well past it (different algebraic setting — isogeny group action, not `F_p` — and a
constrained/membership predicate rather than a bare PRF).

## What adoption would require (if ever reprioritized)

Not buildable from `lib-q` today. A concrete adoption would need, in dependency order:

1. an **effective / cryptographic group-action backend** (CSIDH-class isogeny arithmetic),
   with constant-time and side-channel posture matching the rest of the workspace;
2. the **CPRF for inner-product-membership predicates** on top of that action;
3. the **PCF / silent-OT correlation layer**, plus the QROM analysis and KAT/interop
   vectors `lib-q` requires of shipped primitives;
4. **independent cryptanalytic review** of the *parallelization problem with auxiliary
   inputs* before it could back anything shipped.

None of these exist in the tree, so this is a multi-crate green-field effort, not an
incremental change. It is left tracked, not scheduled.

## Verified vs inferred

**Verified by inspection of `lib-q` at commit `c616c5c`:**

- No isogeny / group-action / CSIDH / SIDH arithmetic anywhere (repository-wide
  case-insensitive search for `isogen|csidh|sidh|group action` returned zero content
  matches).
- No oblivious transfer / PCF / silent-OT / secure-computation primitive; the only
  `VOLE`/`MPC` occurrences are the FAEST and Picnic *proof-system* references cited above.
- `Cargo.toml` workspace members contain no OT/PCF/MPC/isogeny crate.
- `ROADMAP.md` and `README.md` contain no OT / MPC / isogeny line item.
- `lib-q-prf` is a Legendre/Gold PRF over `F_p`, not a CPRF and not oblivious (per its own
  README/DESIGN).

**Taken from the paper's ePrint page (abstract + metadata), not independently reproduced:**

- Key size ≈ 100 kB, invariance in the OT count, the ~7× compactness comparison, the ≈ 7
  OTs/second throughput estimate, the "first QROM proof of a post-quantum PCF" claim, the
  CPRF-for-inner-product-membership core, and the *parallelization problem with auxiliary
  inputs* assumption. These are the authors' stated results; this triage did not run their
  implementation or check their proofs.
