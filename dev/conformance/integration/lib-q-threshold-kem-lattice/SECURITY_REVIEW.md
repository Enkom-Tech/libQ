# Security Review — `lib-q-threshold-kem-lattice` + `lib-q-zk-encryption-proof`

**Date:** 2026-07-14
**Reviewers:** in-house adversarial review (no external cryptographer available). Five independent
expert lenses (KEM correctness/FO-CCA, threshold security, concrete lattice parameters, ZK/STARK
soundness, implementation hygiene), with the load-bearing finding re-verified against source by hand.
**Object:** the two crates on branch `wip/tkem-lattice-abandoned`, both self-marked
`RED/unsigned — research add-on, not reviewed, not production-ready`.

> **Verdict: RED stays.** The dual-Regev/GPV KEM underneath is sound and its numbers check out. The
> zero-knowledge *gate* that is the entire reason these crates exist is **vacuous as wired** — it
> verifies for *any* ciphertext, including the exact malformed inputs it was built to reject. The RED
> marker is therefore correct; the defect is that `gate.rs`'s docstrings and the end-to-end test
> present the gate as a finished closure.

---

## 1. The decisive finding (Critical — verified in source)

**C1/C2 — The gated proof proves a vacuously-satisfiable statement.**

`lib-q-zk-encryption-proof::prove::prove_relation_layer` / `verify_relation_layer` (`prove.rs:234–351`)
are the only production-callable proof path, and the one `gate.rs` and the end-to-end test use.
Reading `assemble_relation_prover` (`prove.rs:131–177`) and `prove_relation_layer` (`prove.rs:234–293`)
confirms the assembled batch contains **only** the R3 linear-relation AIRs:

- `HornerFold` / `EncodeMuFold` folds (one per witness term) and one `RelationCheck` instance,
- joined **only** by `FOLD_E_BUS` (join 3, fold → relation).

There is **no `ShakeSpongeAir`**, **no `TernarySamplerAir`/`BoundedSamplerAir`**, and **no joins 1 & 2**
anywhere in that path. The witness `(e, f, g)` enters purely as prover-chosen Horner-fold values
(`prove.rs:245, 265–288`). Nothing constrains:

- `e` to be ternary (no ternary sampler),
- `f, g` to be bounded (no bounded sampler),
- `(e, f, g)` to equal `XOF(pk‖μ)` (no sponge AIR, no joins 1 & 2).

`RelationCheck` enforces only the linear identity `Σ aⱼ wⱼ + c ≡ 0 (mod q)` at the Fiat–Shamir point ζ,
and the R3a/R3b quotients (`r3a_quotient_poly` / `r3b_quotient_poly`) are prover-supplied to make the
numerator divisible.

**Consequence:** for *any* `(p, v)` a prover picks any `e`, sets `f := p − B0ᵀe` and
`g := v − ⟨t0, e⟩ − encode(μ)`, computes the quotients (which then exist by construction), and produces
a **fully verifying** proof. This is precisely the `f = δ·unitₖ` spike ciphertext the design's own
`THRESHOLD_SECURITY.md` §4.2 proves a linear/norm-only check cannot stop. The gate
(`gate.rs::gated_partial_decap_masked`) admits it and emits the masked partial — **the gate delivers
zero cryptographic advantage over the structural well-formedness check it was meant to supersede.**
Knowledge-soundness is empty: an extractor recovers *a* μ, but unrelated to any encrypted message.

The XOF-binding ("byte-provenance") layer — sponge + both samplers + joins 1 & 2 — exists **only as
`#[cfg(test)]` vertical slices in `compose.rs`**, at toy FRI parameters (2 queries, 1 PoW bit,
explicitly "not production-sound"), covering a single ternary element and never chaining the bounded
sampler for `f, g`. Production integration is an open task (`compose.rs` task #26). **No
production-callable proof binds the witness to the ciphertext's actual FO expansion.**

The crate's `lib.rs` RED marker is honest. The problem is that `gate.rs`'s module docs (lines ~1–27)
claim the gate makes "every ciphertext that reaches the share a genuine encryption," and the test
`gated_decap_end_to_end_real_proof` presents the relation-only proof as the "assumption-free
malformed-ciphertext closure wired end-to-end." Both overclaim. (Corrected in this pass — see §5.)

---

## 2. Blockers to lifting RED

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| C1 | Critical | Gated proof is vacuous — verifies any ciphertext incl. the insider spike | **Verified in `prove.rs`**; 2 lenses concur |
| C2 | Critical | `(e,f,g)` never bound to `XOF(pk‖μ)` / ternary / bounded in any production-param proof | Verified (same path) |
| C3 | Critical | Secret μ + FO witness copied into non-zeroizing `Vec`s (`prove.rs:245,265,279,280,287`) | Verified in source |
| H1 | High | FO⊥ re-encryption uses variable-time rejection sampling on attacker-influenced input → decap-latency timing oracle on the share; flooding/budget do not cover timing | Cited (`kem.rs:269–304, 454–474`) |
| H2 | High | No threshold IND-CCA — the ~63-query malformed-ct insider probe is only operationally mitigated (budget/rotation), not cryptographically closed (this is what C1 was meant to fix) | Corroborated; disclosed in docs |
| H3 | High | Key-instance bit-security number is imported from a sibling-repo estimator run; only `ciphertext_estimate.py` is in-tree — not reproducible here | Cited |
| H4 | High | Gate exercised only at toy FRI params; nothing at 128-bit; FS challenge ζ omits `pk_digest`/`t0` (`relation_assembly.rs:80–100`) | Cited |

### Mediums / Lows (hardening, non-blocking individually)
- **M1** No upper bound on decapper-set size vs the noise budget it depends on: `combine` /
  `validate_share_subset` never reject `subset.len() > PROFILE_MAX_PARTIES_V1` (=16). >16 flooded
  partials can push total noise past q/4 → correctness/DoS. Cap lives only in the sibling
  `lib-q-dkg`. *(Fixed in this pass.)*
- **M2** Sensitive aggregate `rp = ⟨r,p⟩` (exact share image on the reference path) not zeroized in
  `combine()` (`lib.rs:339–358`). *(Fixed in this pass.)*
- **M3** `PartialDecap` derives `Debug`; the unmasked-path `value` leaks a share image if logged.
  *(Fixed in this pass — redacting Debug.)*
- **L1** `ring_inner` / `encapsulate_derand_with_digest` / `fo_expand_witness` guard shapes with
  release-compiled-out `debug_assert!` → silent truncation/mis-index in release.
  *(Fixed in this pass — `assert!`.)*
- **L2** `ct_eq` constant-time posture is by-construction only (no `black_box`/verification harness).
- **L3** `DecapBudget` is an in-memory counter; no persistence — resets to zero per process unless the
  deployment persists it (acknowledged operational boundary).

---

## 3. What is sound (independently confirmed)

- **Decryption correctness / δ=0.** Two lenses independently re-derived the noise budget: worst-case
  per-coefficient ∞-norm ≈ `2^44.01` (`⟨r,f⟩ ≤ 9·1024·16·2^20 = 2^37.2`, plus `16·FLOOD(2^40) = 2^44`)
  vs `q/4 ≈ 2^46` — a ~3.9× margin. This is a true worst-case inequality (not a tail bound) and is
  conservative (‖r‖∞=16 needs all 16 dealers' signs aligned). δ=0 is justified.
- **Concrete PQ security.** Independent core-SVP hand-estimate: key-hiding instance is normal-form
  MLWE with secret dim n = (KAPPA−MU)·N = 3072, ternary secret+error, q=2^48 → log₂δ≈0.00275,
  β≈620–680, **≈160–175-bit quantum** — corroborating the claimed 169-bit. The large q=2^48 is
  dangerous in isolation (α≈2^−48) but rescued by the module dimension. Ciphertext-hiding
  (~2^900+) is far above the bar. *(But see H3: the key-instance estimator run is not in-tree.)*
- **FO⊥.** Fully integer-derandomized from μ (no floats), exact all-coefficient re-encryption compare,
  KDF binds `pk_digest` + μ + full ciphertext. Malformed/mauled ciphertexts are rejected, never yield
  a key (confirmed by KATs and `roundtrip.rs`).
- **AIR gadgets.** `ModReduce`/`HornerFold`/`RelationCheck`/`EncodeMuFold`/samplers are carefully
  constrained (field-fit analyses, canonical-remainder traps closed); the negacyclic quotient
  reduction is correct and cross-checked against the real KEM NTT at N=1024. The mutation-census
  fuzzer finds zero survivors — genuine evidence **for the gadgets**, not for the composed proof.
- **Hygiene where it counts.** `forbid(unsafe_code)`; no panics/unwraps on attacker-controlled input;
  all wire-decode paths fail closed with typed errors before touching secrets; KAT freeze is
  integer-only/platform-exact with SHA3-256 pins and an `#[ignore]`-gated generator.
- **Honesty of the docs.** The design docs correctly identify and quantify the insider-probe
  limitation and correctly refute the earlier "norm-only proof suffices" guidance. The RED marker is
  accurate.

---

## 4. What must happen to lift RED (punch-list)

1. **Close C1/C2/H2 — wire the byte-provenance layer** (sponge + both samplers + joins 1 & 2) into
   `prove_relation_layer`/`verify_relation_layer` so `(e,f,g)` are pinned to `XOF(pk‖μ)` and to
   ternary/bounded ranges. **Add a negative test that the `f = δ·unitₖ` spike (malformed but
   structurally valid) FAILS the gate.** This is the real fix and the largest piece of work.
2. **Close H4** — run the composed proof at production FRI parameters with m≥4 challenges; bind
   `pk_digest`/`t0` into the FS transcript ζ.
3. **Close H3** — vendor and reproduce the key-instance estimator config + log in-tree.
4. **Close H1** — constant-time (branchless / fixed-draw) rejection samplers on the FO re-encryption
   path.
5. **Finish C3** — zeroize the returned STARK traces (`ProverRelationLayer.traces`) after
   `prove_batch` consumes them (the local witness copies are handled in this pass; the traces are the
   remaining secret-bearing artifact).
6. **Cryptographer sign-off** on cross-AIR composition and FS/LogUp challenge independence — the
   fuzzer cannot substitute for this.

---

## 5. Fixes applied in this review pass (2026-07-14)

Non-breaking hardening + honesty corrections only; the load-bearing gap (#1 above) is left as scoped
follow-up:

- **`gate.rs`** — docstrings rewritten to stop overclaiming; added a `WARNING` that
  `verify_relation_layer` alone is INSUFFICIENT as a production gate (admits malformed ciphertexts) and
  that a sound gate requires the full XOF-binding closure.
- **`prove.rs`** — the end-to-end test renamed and its comment corrected to state it exercises the gate
  *wiring only*, not a sound closure; local secret witness copies (`e_lifts`, `f_k`, `g_z`,
  `encode_z`, μ) wrapped in `Zeroizing`; `SECURITY:` comment noting returned traces are not yet wiped.
- **`lib.rs` (KEM)** — `combine()` zeroizes the aggregate `rp`; `combine`/`validate_share_subset`
  enforce `≤ PROFILE_MAX_PARTIES_V1`; `PartialDecap` given a redacting `Debug` impl.
- **`kem.rs`** — `debug_assert_eq!` shape guards → `assert_eq!` (hard-fail in release).

These do not change the security posture — they make the crates honest about it and remove the
cheap footguns. **RED remains until the punch-list, especially item 1, is done.**
