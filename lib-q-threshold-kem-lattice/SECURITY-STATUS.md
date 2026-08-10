# Security status — what a downstream may rely on

This file exists so a consumer can cite a **crate-local, published** answer instead of a chat
message. It answers the questions board card `t_faa048e0` asked of libQ. It is deliberately short
and deliberately negative where the honest answer is negative.

The deep treatment lives in the repository at
`dev/conformance/integration/lib-q-threshold-kem-lattice/` (`THRESHOLD_SECURITY.md`,
`SECURITY_ANALYSIS.md`, `SECURITY_REVIEW.md`, `LIBQ_API.md`). Those files are **not shipped in the
published crate** — this one is. Section numbers below refer to `THRESHOLD_SECURITY.md`.

---

## 1. Overall position: PROVISIONAL

**There is no formal threshold IND-CCA theorem for this construction, and this crate does not claim
one.** It is not product-grade by the standard card `t_faa048e0` asks about, and it should not be
described as such downstream.

Precisely what is missing: a threshold IND-CCA theorem **in the bare model**. The threshold
partial-decapsulation oracle is strictly stronger than an FO⊥ decryption oracle, and the
malformed-ciphertext probe of §4 is a real gap in that model, not an artifact of a loose proof.

What *is* claimed, as an argued-not-proven statement (§7): threshold IND-CCA holds in the ROM at the
§2/§3 hardness **conditional on a closure being in force** — either closure A (a ZK proof of
knowledge of `μ`, assumption-free, unbuilt) or closures B+C together (authenticated encapsulator
plus an enforced decapsulation budget with key rotation). Sign-off on that conditional statement is
the primary open item for a human cryptographer.

Two results underneath it are on firmer ground and are estimator-gated rather than argued:
decapsulation-key hiding (BKZ β = 636 ⇒ 169-bit quantum core-SVP) and ciphertext IND-CPA hiding
(≈2^971 rop at the easiest swept point). Robustness — a corrupt coalition can cause denial of
service but cannot make an incorrect shared secret be accepted — follows unconditionally from FO⊥.

## 2. Does `partial_decap_masked` leak a party's share?

This is the specific question `t_faa048e0` was filed for, because the withdrawn `lib-q-threshold-kem`
had `partial_decap` return the party's raw Shamir share. **The answer here is not a flat no.**

**It is not the same defect.** Nothing in this crate hands over a share, or a reconstructible
encoding of one, as its normal output. A masked partial is
`λ_i·⟨rand(i), p⟩ + m_i + flood_i`, where `m_i` is a ciphertext-bound additive zero-share (uniform
over `R_q` to anyone outside the pair that holds the seed, and summing to exactly zero across the
subset) and `flood_i` is fresh uniform noise bounded by `2^40`.

**Honest ciphertexts — no practical leak, but the argument is heuristic.** With `p` honestly
generated, the coalition-stripped view of an honest party is an LWE instance in the 9216 unknown
coefficients of that party's `rand(i)`, at modulus `q ≈ 2^48` with `2^40` noise (§3). Its parameters
dominate the §2 instance that *was* estimator-gated, so any feasible query count is safe. **Status:
heuristic-by-domination — no dedicated estimator run exists for the dimension-9216 instance.**

**Malformed ciphertexts — yes, it leaks, and this is condition X.** The above rests on the queried
`f` being pseudorandom and full-rank across queries. A coalition that chooses the ciphertext need not
oblige: the spike `p = δ·unit_k` reduces the partial to `λ_i·δ·rand(i)_k + flood_i`, and since the
`2^40` flood sits `2^8` below the modulus, **each probe leaks the top ≈7 bits of every coefficient of
one share coordinate**. Sweeping `δ` over ≈7 values × `KAPPA = 9` coordinates ⇒ **≈63 malformed
partials recover the party's entire share** (§4.1). FO⊥ rejects the *output*, but it fires at
`combine`, after the partials have been broadcast.

Note the norm ball does not save you: the spike with `δ = 1` has `‖f‖∞ = 1`, well inside it. A
well-formedness proof that certifies only "error is short" **does not close this** — §4.2 gives two
independent exact-arithmetic reasons, and it is the correction that supersedes earlier guidance in
`SECURITY_ANALYSIS.md` §4 and `LIBQ_API.md` §7.3.

**So: a masked partial does not reveal the share to a passive party or under honest ciphertexts, and
does reveal it under ≈63 adversarially malformed ones.** Deploying this safely means preventing that
input, which is what §3 below is about.

**Separately: `partial_decap` (unmasked) leaks by construction and by design.** Its own rustdoc says
so — "individually **not** private (leaks a linear image of the share)". It exists as a reference for
a trusted combiner. A migration that keeps the old call shape and swaps the import lands on this
function, which is the trap the card flagged. Use `threshold::partial_decap_masked_budgeted` for any
distributed path.

## 3. What a deployment MUST do to use this at all

These are not recommendations. Without them the §2 answer is "the share leaks after ≈63 queries".

1. **Authenticated encapsulator (closure B).** Gate `partial_decap*` on an authenticated-origin
   decision, so a corrupt coalition cannot inject a chosen ciphertext. The crate deliberately does
   not embed a signature scheme or PKI — this is a deployment contract, and the caller owns it.
2. **Enforced budget + rotation (closure C).** Thread a `DecapBudget` through every partial and
   reshare the DKG key before it is exhausted. `DecapBudget::authenticated()` = 2^20 assumes (1) is
   in force. `DecapBudget::untrusted()` = 32 is deliberately below the ≈63-query probe length, so
   the probe can never complete on one key. Closure C bounds the exposure window; it does not make
   the partial oracle hard, and it is not a substitute for (1).

Use `partial_decap_masked_budgeted` rather than `partial_decap_masked`: it makes the budget
unskippable rather than doc-only.

## 4. Migrating off the withdrawn `lib-q-threshold-kem`

`lib-q-threshold-kem` was withdrawn because its `partial_decap` returned the party's raw Shamir
share, so `t` partials reconstructed the ML-KEM decapsulation key — escrow, not threshold
decapsulation. ML-KEM decapsulation is non-linear, so no correct partial-decap function exists for a
Shamir-shared `dk`; it was unfixable in place.

This crate is a **different construction, not a port**, and the APIs are not equivalent. Four
differences change a consumer's design, not just its imports:

1. **No per-share verification.** There is no `verify_share` / `ShareVerifier`. Validity is enforced
   inside `combine` by an FO⊥ re-encryption check, so you learn *the set* failed, not *which
   custodian* sent the bad partial. A ceremony that must name a misbehaving custodian needs its own
   accountability layer. (Robustness still holds: a bad partial causes rejection, never a wrong
   accepted key.)
2. **A budget is now part of the protocol.** `DecapBudget` is a per-key counter that must be
   persisted and accounted for, and exhausting it requires resharing. There was no analogue before.
3. **The ceremony gains a round.** `partial_decap*` bakes Lagrange coefficients for a *known*
   decapping subset into the partial, so the participating subset must be agreed before custodians
   can act. The withdrawn API let them act independently.
4. **The masked path needs new material.** `partial_decap_masked` takes `ZeroShareSeeds` and an RNG.
   The pairwise seeds are per-pair state a ceremony must establish and distribute; the old one
   needed neither.

There is no compatibility shim and there should not be one — the operator confirmed (card
`t_faa048e0`, 2026-08-06) that no deployment ever ran the withdrawn construction against real data,
so there is no installed base to stay compatible with and no rotation obligation.

## 5. Not answered here

- Whether the §7 conditional threshold IND-CCA statement is correct. That is the sign-off item.
- The §3 dimension-9216 LWE domination, which has no dedicated estimator run.
- Closure A (the SHAKE-in-STARK PoK of `μ`) is unbuilt; `lib-q-zk-encryption-proof` is the attempt
  and is itself RED.
- Whether `lib-q-threshold-kem` 0.0.6–0.0.9 should be yanked from crates.io. They remain
  installable, and yanking is an operator decision, not a libQ-code one.
