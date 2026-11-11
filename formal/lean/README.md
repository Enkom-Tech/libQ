# Lean proofs for the libQ Saturnin sign-offs

Formal-verification support for libQ PR #76's Gate D / Gate E sign-offs
(`docs/crypto-signoff-register.md`), scoped exactly to what is classically mechanisable today.
Every claim below states plainly whether it is **proved**, **assumed** (named `axiom`), or
**estimated** (flagged as such in the source) — nothing here should be read as "sorry, but
informal".

## What is proved (`lake build`, no `sorry`, no custom axioms)

| File | Content |
|---|---|
| `SaturninCTX/Encoding.lean` | The CTX byte encoding `label ‖ key ‖ nonce ‖ baseTag ‖ ad` (`lib-q-saturnin/src/commit.rs`) is injective in `(key, nonce, baseTag, ad)`. |
| `SaturninCTX/Binding.lean` | **Gate D's direct binding argument**: two successful openings of the same `core ‖ T'` under distinct `(key, nonce, ad)` force an `H`-collision. No tidiness assumption. |
| `SaturninCTX/PositiveControl.lean` | **Acceptance-criterion positive control**: drop `key` from the hash input and the *same* proof technique instead proves a live break — two distinct keys open the same ciphertext with no `H`-collision at all. |
| `SaturninCTX/Hierarchy.lean` | Bellare-Hoang (ePrint 2022/268) Appendix A, all four relations among `CMT-ℓ`/`CMTD-ℓ` for `ℓ ∈ {1,3,4}`, plus the "leftward arrows are trivial" facts — including the exact chain the card names: "CMTD-3/4 to CMT-3/4 by correctness, then CMT-1" (`cmt1_secure_of_cmtd4_secure`). |
| `SaturninCTX/QcbTidiness.lean` | **Concrete, checked non-tidiness witness** for `SaturninQcb`'s raw Algorithm-1 (pre-CTX). Corrects a false claim `commit.rs` made ("SaturninQcb is also tidy in Bellare-Hoang's sense") — now fixed there too, with a pointer back here. |
| `SaturninCTX/GateEBound.lean` | The generic `c·q³/2ⁿ` quantum-query bound shape this proof family produces, and the explicit crossover (`q ≈ 2^43` at Saturnin's 128-bit post-quantum target) at which a bound of that shape stops being meaningful — the "stated limit" the register was missing. Flagged throughout as an *estimate of the generic shape*, not a re-derivation of Saturnin's or 2025/387's actual (unpublished) constants. |

Run `#print axioms <theorem name>` on any of the above and the only axioms reported are Lean's own
kernel axioms (`propext`, `Classical.choice`, `Quot.sound`) — never `sorryAx`, never a custom
`axiom` declared in this development. Checked for every theorem in these six files as part of
this card.

## What is stated as an explicit conditional skeleton (`SaturninCTX/GateEComposition.lean`)

Gate E's `IND-qCCA[LoR]` claim for `SaturninAead` (CTR-Cascade, domains 1-5, padded terminal
block, EtM over `(N, A, C)`) is derived from **four axioms**:

* `Thm3`, `Thm4_EtM` — Lang, Leuther, Lucks, *Generic Composition: From Classical to Quantum
  Security*, ePrint 2025/387 / PQCrypto 2026, Theorem 3 and (half of) Theorem 4.
* `CascadeCore_INDqCPA` — nonce-respecting `IND-qCPA[LoR]` of the Cascade core (the
  classically-unsurprising half; not itself a disputed register item).
* `SAT_JQPRF` — the register's name for "the Saturnin LWC spec's §4.3.3 Song-Yun-derived qPRF
  claim for the Cascade MAC actually discharges 2025/387's hypothesis". **This is the open,
  unratified obligation Gate E's sign-off is conditional on** (`docs/crypto-signoff-register.md`,
  Gate E: "Ratify or refute the citation swap. ... nobody has ratified it").

Corollary 1 (`Cor1_EtM`) is *derived* from `Thm3` + `Thm4_EtM`, not re-axiomatised, matching
2025/387's own proof structure. `gate_e_cascade_INDqCCA` is the final, one-line derivation. This
mechanises the *logic* PR #76 signed off on conditionally — it does not, and cannot, prove
`SAT_JQPRF` itself: that needs a QROM/compressed-oracle argument for Saturnin's specific cascade
MAC, exactly the "not feasible yet" work below.

## Not feasible yet: survey of quantum game-based proof frameworks

Discharging `SAT_JQPRF` (or the crate's own **Q-1** obligation — CTX's nAE-preservation proof is
classical-ROM, `SaturninQcb` exists specifically for Q2 superposition-query security) needs a
framework that can reason about **superposition-query oracles**, not just classical ones. Surveyed
2026-09-25:

* **Lean / VCVio** (ePrint 2026/899) — the closest existing Lean cryptography framework, with
  machine-checked forking-lemma and Schnorr EUF-CMA proofs. It is explicitly **classical-oracle
  only**; its own authors note it does not model quantum superposition access. No Lean library
  for compressed/superposition oracles exists as of this survey (a separate `Lean-QIT` effort
  formalises finite-dimensional quantum information theory, not cryptographic games).
* **EasyCrypt** — mainline EasyCrypt is classical-oracle only, like VCVio. The genuinely relevant
  tool is **`qrhl-tool`** (Unruh, POPL 2019), a *separate* prover built around quantum relational
  Hoare logic (qRHL) specifically for superposition-query games; it has real precedent for this
  exact class of result (QROM proofs, the post-quantum Fujisaki-Okamoto security proof). Also
  relevant: **EasyPQC** (ePrint 2021/1253), an extension of EasyCrypt itself, but scoped to
  proofs where a *quantum-computing* adversary makes *classical* queries against a
  quantum-hard assumption (PRF-based MAC, FDH, GPV08 IBE) — not the full Q2
  superposition-query model Gate E's obligations need.
* **CryptHOL / Isabelle** — CryptHOL (game-based proofs in Isabelle/HOL) is classical-oracle
  only. Isabelle separately has a quantum-computing library (matrices, circuits; no-cloning,
  teleportation, Deutsch-Jozsa) with no integration into CryptHOL's cryptographic game logic.
* **SSProve** (Rocq/Coq) — state-separating proofs, classical-oracle only; no quantum extension
  exists as of this survey.

**Verdict: `qrhl-tool` is the only one of the four with genuine, published precedent for exactly
this class of superposition-query security argument**, and is the natural starting point if the
operator wants to pursue `SAT_JQPRF`/Q-1 further. But "closest" is not "ready": no existing
development (in `qrhl-tool` or anywhere else surveyed) covers either Song-Yun's cascade-construction
qPRF argument or 2025/387's EatM/EtM/EaM composition theorem, and building either from scratch is a
multi-month formalisation project on top of a research-grade tool — a research programme, not a
card-sized task, exactly as the parent issue anticipates.

## Reproducing

```sh
curl https://elan.lean-lang.org/elan-init.sh -sSf | sh -s -- -y --default-toolchain none
cd formal/lean
~/.elan/bin/lake build          # builds everything; fails on any error, including a stray `sorry`
grep -rn '\bsorry\b' SaturninCTX/ SaturninCTX.lean   # expect no output
```

`lean-toolchain` pins the exact Lean 4 release (`leanprover/lean4:v4.34.1`); `elan` reads it
automatically. No `mathlib` or other external Lean dependency — every proof here is over core
Lean 4 (`List`, `Nat`, `Prod`, propositional logic) by design, so there is nothing else to fetch.

CI: `.github/workflows/formal-lean.yml` runs exactly the two commands above on every push/PR that
touches `formal/lean/**`.
