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
>
> **Progress update (2026-07-14, later — see §6 & §7):** the byte-provenance layer has since been
> composed into real library API (`encryption_proof.rs`) as a **COMPLETE malformed-ciphertext closure**
> — binding `e` (ternary) + ALL `f_k` + `g` (bounded) across every R3a `p_k` AND R3b, over `m`
> independent Fiat–Shamir challenges, verified at **production FRI params** and wired into the gate.
> Both the classic `f = δ·unitₖ` R3a spike and a tampered `e` are rejected. This **closes C1, C2, H2,
> and H4** (production params + `m`-challenge + pk-bound ζ) and **C3** (trace zeroization). The proof
> is also **zero-knowledge** under the hiding-FRI config (#32, demonstrated).
>
> **UPDATE 2026-07-14 — H1 CLOSED.** The FO encryption samplers are now **constant-time**: fixed byte
> budgets, branch-free rejection, and constant-time compaction of the first `N` accepts (no secret-
> dependent branch, byte-consumption, or memory index). The emitted coefficients are bit-identical to
> the previous rejection sampling (same distribution → §3/§4 analyses unchanged); only the consumption
> boundary is fixed, a `v1 → v2` wire change (KATs regenerated). The byte-provenance proof was
> re-synced to the fixed budget (emission-quota `still`/`emit` columns) and re-verified at production
> params, ZK, and spike-rejection. **RED now stands only for:** external cryptographer sign-off on
> the cross-AIR composition (H1–H4 and the estimator vendoring H3 are all closed).

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
| C1 | Critical | Gated proof is vacuous — verifies any ciphertext incl. the insider spike | **CLOSED (§7)** — full `e`+`f`+`g` / all-R3a+R3b closure; `f=δ·unitₖ` spike rejected |
| C2 | Critical | `(e,f,g)` never bound to `XOF(pk‖μ)` / ternary / bounded in any production-param proof | **CLOSED (§7)** — all three bound at production params over `m` challenges |
| C3 | Critical | Secret μ + FO witness copied into non-zeroizing `Vec`s (`prove.rs:245,265,279,280,287`) | **CLOSED** — `Zeroizing` lifts + `Drop`-wipe of returned traces (`encryption_proof.rs`) |
| H1 | High | FO⊥ re-encryption uses variable-time rejection sampling on attacker-influenced input → decap-latency timing oracle on the share; flooding/budget do not cover timing | **CLOSED** 2026-07-14 — fixed-budget branch-free samplers + constant-time compaction (`kem.rs`); v1→v2 KAT; proof re-synced (emission quota) + re-verified at production params, ZK, spike-rejection |
| H2 | High | No threshold IND-CCA — the ~63-query malformed-ct insider probe is only operationally mitigated (budget/rotation), not cryptographically closed (this is what C1 was meant to fix) | **CLOSED (§7)** — the sound gate now cryptographically rejects the malformed-ct probe |
| H3 | High | Key-instance bit-security number is imported from a sibling-repo estimator run; only `ciphertext_estimate.py` is in-tree — not reproducible here | **CLOSED** 2026-07-14 — `key_estimate.py` (self-contained config, tkem consts) + `key_estimate.log` (authoritative per-attack table, vendored with provenance) + `ciphertext_estimate.log` materialized; both instances reproducible-from-config in-tree, no sibling-repo dependency |
| H4 | High | Gate exercised only at toy FRI params; nothing at 128-bit; FS challenge ζ omits `pk_digest`/`t0` (`relation_assembly.rs:80–100`) | **CLOSED (§7)** — production params (~128-bit) + `m`-challenge (~2⁻⁵²ᵐ) + pk-bound ζ |

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
  (~2^900+) is far above the bar. *(H3 closed: the key-instance estimator config + archived run are
  now in-tree — `key_estimate.py` / `key_estimate.log`.)*
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

1. **Close C1/C2/H2 — wire the byte-provenance layer** (sponge + both samplers + joins 1 & 2) so
   `(e,f,g)` are pinned to `XOF(pk‖μ)` and to ternary/bounded ranges, with a negative test that a
   malformed-but-structurally-valid spike FAILS the gate.
   - **DONE (2026-07-14, §7):** `encryption_proof::assemble_full_provenance_*` composes sponge ⇒
     squeeze ⇒ ternary(`e`) + bounded(`f`) + bounded(`g`) samplers ⇒ all folds ⇒ every R3a `p_k` + R3b
     into ONE production-param batch over `m` Fiat–Shamir challenges. `spike_tampered_f_witness_rejected`
     (the classic `f = δ·unitₖ`) and `spike_tampered_e_witness_rejected` are the negative tests; the
     gate is wired to the sound closure. C1/C2/H2/H4 closed.
2. **Close H4** — run the composed proof at production FRI parameters with m≥4 challenges; bind
   `pk_digest`/`t0` into the FS transcript ζ.
3. **H3 CLOSED** (2026-07-14) — key-instance estimator config + archived run vendored in-tree
   (`key_estimate.py` / `key_estimate.log`); ciphertext run materialized (`ciphertext_estimate.log`).
4. **Close H1** — constant-time (branchless / fixed-draw) rejection samplers on the FO re-encryption
   path.
   - **DONE (2026-07-14):** `kem.rs` samplers draw fixed budgets (`E_TERNARY_ATTEMPTS`,
     `bounded_attempts(n)`), evaluate every attempt branch-free (masking), and constant-time-compact
     the first `N` accepts. Coefficients are bit-identical to the old rejection sampling; the fixed
     consumption boundary is a v1→v2 wire change (KATs regenerated; KEM suite green). The byte-
     provenance proof was re-synced (emission-quota `still`/`emit` columns so the drained tail keeps
     the sponge join balanced) and re-verified at production params + ZK + spike-rejection.
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

---

## 6. Progress pass — `e` byte-provenance composed & gated (2026-07-14, later)

This pass takes punch-list item 1 from "open" to "done for the `e` component," turning the vacuous
gate into a **sound** gate for the `e`-probe class. New module **`encryption_proof.rs`** (real,
non-`#[cfg(test)]` library API):

- **`assemble_e_provenance_prover(t0, μ)`** builds, over a genuine `encapsulate_derand` ciphertext at
  `N = 1024`, a single batch: `ShakeSpongeAir` (over the real FO preimage `DOM ‖ pk_digest ‖ μ`) ⇒
  `SqueezeByteAir` ⇒ `TernarySamplerAir` (`MU·N` coeffs) ⇒ `MU` byte-bound `e_r` Horner folds ⇒ the
  R3b relation, wired by joins 1 (SQUEEZE_LIMB→XOF_STREAM), 2 (COEFF_E) and 3 (FOLD_E). `g`/`encode`/
  quotient folds are fed directly (not yet byte-bound).
- **`assemble_e_provenance_verifier(t0, ct, shape)`** rebuilds every AIR + the sponge's pk-binding
  public values from `pk_digest_of(t0)` (new public accessor in `tkem::kem`) and the relation
  coefficients from `(t0, ct, ζ)` — **never** prover-supplied. So the load-bearing pk obligation is met.

**Verification evidence** (`encryption_proof::tests`):
- `e_provenance_round_trip_test_params` — honest proof prove+verify (green).
- `e_provenance_round_trip_production_params` — same at **production FRI params** (`log_blowup=2`,
  `num_queries=64`, `pow=16` ⇒ ≈128-bit conjectured FRI soundness + 16-bit grinding); green in release
  (~6 s). **Closes H4's production-param gap for this path.**
- `spike_tampered_e_witness_rejected` — tampering an `e_r` fold coefficient (a witness that deviates
  from the XOF-derived `e`) yields **no verifying proof** (join-2 unbalances / Horner constraint
  fails). **This is the non-vacuousness proof: C1/C2 closed for the `e`-probe class.**
- `gate_uses_composed_byte_provenance_closure` — `gated_partial_decap_masked` driven by the composed
  `verify_batch` closure: forwards for the matching ciphertext, refuses (`ProofRejected`) for a
  different one, before the share is read. **The gate is now non-vacuous when handed this closure.**

Docs corrected to match (`gate.rs`, `prove.rs`, `compose.rs`): the "not yet wired" language is
replaced with the accurate "wired for `e`; `f`/`g` pending."

*(This `e`-only pass was superseded within the day by the complete closure — see §7.)*

---

## 7. Completion pass — full `(e,f,g)` closure, `m`-challenge, gated (2026-07-14)

Extends §6 from the `e` component to the **complete malformed-ciphertext closure**, closing C1, C2,
H2, H4, and C3. Same module `encryption_proof.rs`, three tiers:

- `assemble_e_provenance_*` — `e` + R3b (the §6 result; cheapest).
- `assemble_r3a_f_provenance_*` — binds `e` AND `f` (a bounded sampler at the absolute XOF offset after
  `e`) for selected R3a `p_k` columns; the harness for the classic `f = δ·unitₖ` spike.
- **`assemble_full_provenance_*(t0, μ, num_challenges)`** — the production closure: one batch binding
  `e` (ternary) + ALL `KAPPA` `f_k` + `g` (bounded, at XOF offsets `0`, `e_bytes`, `e_bytes+f_bytes`)
  and proving EVERY R3a `p_k` AND R3b, over `m` independent Fiat–Shamir challenges. The `MU` `e_r`
  folds are shared and fan out to all `KAPPA+1` relations (per challenge); the samplers Send each
  coefficient `m×` so the `m` per-challenge fold sets each Receive once and every COEFF bus balances.

**How each blocker is closed:**
- **C1/C2** — every witness component is now pinned: `e ∈ {-1,0,1}` and `f,g ∈ [-B,B]` by the sampler
  AIRs; `(e,f,g) = XOF(DOM ‖ pk_digest ‖ μ)` by joins 1→2 from the sponge (whose preimage is pinned,
  with pk_digest as verifier-built public values); and `p_k = B0ᵀe+f_k`, `v = ⟨t0,e⟩+g+encode(μ)` by
  the R3a/R3b relations (join 3). No free component remains. `spike_tampered_f_witness_rejected` and
  `spike_tampered_e_witness_rejected` confirm a deviating witness cannot verify.
- **H2** — the malformed-ct insider probe is now *cryptographically* rejected by the gate, not merely
  budget/rotation-mitigated (`gate_uses_composed_byte_provenance_closure`).
- **H4** — runs at production FRI params (`log_blowup=2`, `num_queries=64`, `pow=16` ⇒ ≈128-bit
  conjectured FRI + byte-provenance soundness) AND over `m` challenges: each relation is checked at
  `ζ_i = H(pk_digest ‖ ct)`, a malformed ct passing with prob ≤ (deg/|F|)^m ≈ 2⁻⁵²ᵐ (m=3 ⇒ ~156 bits),
  defeating the prover's ability to grind `ct`. ζ now absorbs `pk_digest` (multi-target separation).
- **C3** — the secret coefficient lifts are `Zeroizing`; `EncProvenanceProver` has a `Drop` that wipes
  every returned trace cell (`black_box`-guarded) after `prove_batch` consumes them.

**Verification evidence** (`encryption_proof::tests`, all green in release):
`e_provenance_round_trip_{test,production}_params`, `r3a_f_round_trip_{test,production}_params`,
`spike_tampered_{e,f}_witness_rejected`, `gate_uses_composed_byte_provenance_closure`,
`full_provenance_round_trip` (m=1, complete closure @ production params, ~44 s), and
**`full_provenance_sound_multichallenge` (m=3 @ production params)** — the production-shaped sound
proof. Full crate regression: 92 passed / 0 failed / 4 ignored (the heavy ones run under `--ignored`).

**Zero-knowledge (#32) — DEMONSTRATED.** The same assembly runs unchanged under the hiding-FRI config
(`zk_batch_config`, `is_zk() == 1`): the batch prover blinds every committed matrix and randomizes the
quotient, so the proof reveals nothing about μ beyond the statement — sound AND zero-knowledge
(`e_provenance_zero_knowledge_round_trip`, green). One subtlety: under the hiding PCS the *preprocessed*
sponge position column is committed with blinding, so the verifier reuses the prover's preprocessed
`CommonData` (sound — preprocessed is public and a deterministic function of the AIRs; it still
recomputes ζ + all public values independently from `(t0, ct)`). A deployment may instead commit
preprocessed under a non-hiding sub-commitment (it needs no blinding) to let the verifier rebuild it
independently — a batch-stark ergonomics refinement, not a soundness gap.

**Remaining for full RED-lift (NOT soundness or ZK of this proof):**
1. **H1 CLOSED** (2026-07-14) — fixed-budget branch-free FO samplers + constant-time compaction in
   `kem.rs`; XOF byte consumption co-designed with the byte-provenance offsets; v1→v2 wire KATs
   regenerated; proof re-synced (emission quota) and re-verified at production params.
2. **H3 CLOSED** (2026-07-14) — key-instance estimator config + archived run vendored in-tree
   (`key_estimate.py` / `key_estimate.log`).
3. **Cryptographer sign-off** on the cross-AIR composition and FS/LogUp challenge independence.
   → **Executed 2026-07-14 as the structured process a cryptographer would run (no external human
   available — see §8). The composition is structurally sound; the process found two real issues —
   S1 (challenge field was ~62-bit) and S2 (ZK trusted prover preprocessed) — and BOTH ARE NOW FIXED
   and re-verified green at GF(p⁶). Residual is purely the external human signature. See §8.**

---

## 8. Cryptographer sign-off pass — cross-AIR composition + FS/LogUp challenge independence (2026-07-14)

**What this is.** With no external cryptographer available, we ran the *process* a reviewer would:
decompose the residual item into its four checkable obligations, audit each against source
adversarially (four independent expert lenses), and re-verify every load-bearing claim by hand against
the framework source. **This is an in-house adversarial review, not an external human signature** — it
raises assurance from "unexamined composition" to "examined by a documented, reproducible process," but
the residual item is not *closed*; it is *reduced to two named, actionable findings*.

**Scope.** The batch prover/verifier (`lib-q-plonky-batch-stark`), the LogUp gadget
(`lib-q-plonky-lookup`), the challenger (`lib-q-stark-challenger`), and this crate's bus wiring
(`encryption_proof.rs` / `logup_join.rs` / `compose.rs` / `sampler.rs` / `sponge_air.rs`).

### 8.1 What checks out (independently corroborated, hand-verified)

- **FS transcript ordering — SOUND.** Reconstructed the exact observe/sample sequence on both sides.
  Every challenge is sampled strictly *after* the commitments it must bind: main-trace commit
  (`prover.rs:370`) → LogUp α/β (`:382`) → permutation/aux commit + cumulated sums (`:406-411`) →
  constraint-combine α (`:415`) → quotient commit (`:502`) → OOD ζ (`:517`) → FRI. The **verifier
  replays a byte-identical sequence** (`verifier.rs:215-251`) via the *same* helpers
  (`observe_instance_binding`, `get_perm_challenges`), which structurally forecloses prover/verifier
  drift. Public values + preprocessed ("pk") commitment are absorbed before any challenge. No
  challenge-before-commit; no cross-role challenge reuse.
- **LogUp accumulator + cross-AIR bus balance — SOUND.** Accumulator init (`s[0]=0`,
  `logup.rs:204`), polynomial transition (`:220-232`), and final-row boundary pinning
  `expected_cumulated` to the true per-AIR sum (`:224-225`) are correct. The **cross-AIR bus is
  cryptographically forced to cancel to zero**: the verifier groups per-AIR cumulated sums by the
  *verifier-trusted* bus name (`Kind::Global`, from its own config — not proof-supplied) and rejects
  unless the global sum is exactly zero (`verify_global_final_value`, `logup.rs:280-284`;
  `verifier.rs:525-565`). An unmatched Send/Receive cannot balance.
- **m-challenge fan-out arithmetic — SOUND.** Each coefficient is Sent `m×` and Received once per
  challenge set, with per-challenge fold bases partitioning the position axis
  (`CHALLENGE_SPAN=(KAPPA+1)·R3A_BASE_SPAN`); counted from source — no off-by-one, no silent balance
  against a wrong coefficient. The `m` per-relation points `ζ_i = SHAKE256(DOM_ZETA ‖ pk_digest ‖ ct)`
  are **independent consecutive XOF draws** (`derive_zetas`, `relation_assembly.rs:80-100`), AND-combined
  (one batch; any failing relation fails the proof), so the exponent `m` is real.
- **Verifier-built public values — SOUND.** `pk_digest = pk_digest_of(t0)`, ζ_i, and every relation
  coefficient `(a,c)` are rebuilt by the verifier from `(t0, ct)`; never prover-supplied.
- **Sampler ranges — SOUND in composition.** `e ∈ {-1,0,1}` and `f,g ∈ [-B,B]` are pinned by the
  sampler AIRs (boolean-gated lifts; the bounded `lift<Q` obligation is discharged by the composed
  fold's `w<q` borrow check, present in every shipped `assemble_*`). Multiplicity columns are
  boolean-gated expressions, not free columns — the standard LogUp "multiplicity range is the caller's
  job" obligation IS met here.

### 8.2 Findings the process surfaced (these are why it is NOT a clean sign-off)

**S1 — High (concrete soundness LEVEL, not a break): the encryption proof runs on the ~62-bit
challenge field.** The demonstrated configs use `DefaultPcs` / `DefaultChallengeMmcs` with
`Challenge = Complex<Mersenne31> = GF(p²) ≈ 2⁶²` (`encryption_proof.rs:1254-1261`;
`lib-q-zkp/src/stark.rs:81-88`). All *Layer-B* STARK-internal challenges (LogUp α/β, constraint-combine
α, OOD ζ, FRI folding/batching) are therefore ~62-bit draws, capping the composed proof's own soundness
**well below the "≈128-bit" claimed in §7** (that headline is FRI *query-phase* only; it does not bound
the algebraic-combination terms over GF(p²)). The Layer-A `m`-challenge does **not** rescue this — it
amplifies only the ciphertext-grinding/relation term (→ ~2⁻¹⁴⁸), a *different* error than the
single-instance STARK soundness. **The same repo already fixes this for the sibling membership STARK:**
`ConfigChallenge = BinomialExtensionField<ConfigVal, 3> = GF(p⁶) ≈ 186-bit`, "upgraded from using the
value field itself" (`stark.rs:66-72`, `MembershipChallengeMmcs` `:94`). **Fix:** wire the encryption
proof to the GF(p⁶) challenge config (as membership does) before asserting any ≥100-bit soundness. Until
then the honest number is ~62-bit for the STARK's own soundness.
> **S1 RESOLVED (2026-07-14).** `Cfg`/`ZkCfg` and the `test`/`production`/`zk` batch configs were
> rewired from `DefaultPcs`/`GF(p²)` to `MembershipPcs`/`ConfigChallenge = GF(p⁶)` (~186-bit) — same
> value field/DFT/Merkle commitment, larger FRI challenge extension, mirroring the sibling membership
> STARK. Re-verified green at GF(p⁶): full non-ignored suite (92/0), and every heavy production-param
> proof incl. `full_provenance_sound_multichallenge` (m=3) and `full_provenance_round_trip` (m=1)
> (5/0, ~600 s). The composition is sound at the ≥128-bit challenge field; the ~62-bit ceiling is lifted.

**S2 — Medium (conditional ZK-soundness gap): hiding-PCS preprocessed reuse.** The ZK path passes the
prover's *blinded* preprocessed commitment (`prover_data.common`) to `verify_batch` with no independent
rebuild (`encryption_proof.rs:1503-1514`). Preprocessed carries the sponge round-constants / position
column that pin `e = XOF(pk‖μ)`; a doctored preprocessed could make the sponge AIR accept a witness that
is not the true XOF output. Sound **only** under the deployment obligation, already named in-source
(`:52-54`), to commit preprocessed under a *non-hiding* sub-commitment and rebuild+compare on the
verifier (preprocessed carries no witness secret, so it needs no blinding). The current ZK round-trip
test takes the trusting shortcut → it demonstrates *completeness*, not *soundness*, of preprocessed
handling. **Fix:** production ZK gate MUST NOT trust prover preprocessed.
> **S2 RESOLVED (2026-07-14).** `e_provenance_zero_knowledge_round_trip` no longer passes
> `prover_data.common` to `verify_batch`; the verifier now **rebuilds** the preprocessed independently
> from its own (public) AIRs via `build_preprocessed(&zk_batch_config(), &verifier.airs)` and verifies
> against that — exactly the sound non-ZK pattern. This is sound (the verifier binds preprocessed to the
> canonical AIR set, never to a prover claim) and loses no ZK: preprocessed is public/secret-free, so a
> fresh config restarting the hiding-MMCS RNG at its fixed seed reproduces the commitment bit-identically
> while only the witness-bearing main/aux/quotient matrices keep their blinding. Re-verified green at
> GF(p⁶). The doctored-preprocessed attack is foreclosed. (A deployment building its own gate must follow
> the same discipline — never trust a prover-supplied preprocessed commitment.)

### 8.3 Hardening notes (non-blocking)

- **HN1** `FOLD_E` disjoint-base disjointness is a *caller convention*, not a constraint
  (`logup_join.rs:93-98`) — met by every shipped `assemble_*`, but a future caller reusing the helpers
  with overlapping bases could cross-satisfy Sends/Receives. Add a typed base allocator or an assertion.
- **HN2** The bounded sampler's canonical `lift<Q` soundness is contingent on the composed fold's `w<q`
  check; a *standalone* bounded proof (no fold) is under-constrained. Document/assert the fold is
  present.
- **HN3** Reconcile the two per-challenge soundness figures in comments: `encryption_proof.rs:44` cites
  `deg/|F| ≈ 2⁻⁵²` (over GF(p²)); `relation_assembly.rs:70` cites `(2N−2)/q ≈ 2⁻³⁷` (base field). The
  `2⁻³⁷` base-field figure is the correct conservative one; the headline should be read against it.

### 8.4 Verdict of this pass

The cross-AIR composition and FS/LogUp challenge independence are **structurally sound** — no ordering
break, no bus-balance escape, no vacuous-composition or challenge-reuse defect, corroborated by four
independent lenses and by-hand source verification. The two findings this pass surfaced — **S1**
(challenge field was ~62-bit) and **S2** (ZK trusted the prover's preprocessed) — **are both now FIXED
and re-verified green at GF(p⁶)** (see the RESOLVED notes in §8.2): the composed proof runs at the
~186-bit challenge field at production params (incl. m=3), and the ZK verifier rebuilds preprocessed
rather than trusting it. Hardening notes HN1–HN3 remain open (non-blocking).

**RED still stays — but the residual is now purely the terminal gate: an external human cryptographer's
signature.** This pass ran the *process* one would run (four adversarial lenses + by-hand source
verification), found two real issues, and closed them; that raises assurance from "unexamined
composition" to "examined by a documented, reproducible process, findings fixed." It does **not**
manufacture the accountability of an independent expert signature. An in-house process reduces — it does
not replace — external sign-off.
