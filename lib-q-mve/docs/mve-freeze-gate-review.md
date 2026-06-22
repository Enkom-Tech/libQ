# mVE Freeze-Gate Review — `lib-q-mve` multi-recipient verifiable rekey

**Crate:** `lib-q-mve` · **Tier status: RED** (no human cryptographer sign-off) ·
**PENDING HUMAN SIGN-OFF everywhere.**

> Engineering analyses of the four mVE obligations (M1–M4), to the standard a human cryptographer
> would review. **NOT** a sign-off; nothing here flips the tier. Generated 2026-06-22.

Implements [`libq-mve-rekey-v0`](../../../libQ-SPEC/spec/security/libq-mve-rekey-v0.md) §4/§7.

## 1. Construction under review

```text
key_commitment = K12(libq.mve.commit.v0 ‖ K ‖ r ‖ epoch_ctx)          # outside circuit, 32 B
per recipient i:  (ss_i, kem_ct_i) = ML-KEM.Encaps(update_pk_i)
                  w_i = K + H_zk(ss_i)                                 # field-additive wrap
proof π (FRI/AIR, hiding PCS, hash_suite_id = 5):
  ∃ (K, {ss_i}):  ∀ i:  w_i = K + H_zk(ss_i)   (single K across all rows)
  and  acc = HashChain(w_0,…,w_{H-1})  bound to the public digest
Verify(key_commitment, {kem_ct_i, w_i}, {update_pk_i}, π):
  recompute acc from the wire wraps; verify π under the ZK FRI params
recipient: ss_i = Decaps(sk_i, kem_ct_i); K = w_i − H_zk(ss_i); check key_commitment (§4.3)
```

- `H_zk` = the truncated Poseidon-256 wide sponge shared with the membership AIR (`hash_suite_id = 5`).
- Proof system: lib-q-zkp `StarkProver`/`StarkVerifier` with the **hiding** PCS (`HidingFriPcs` +
  `Kt128Rng`, fresh OS-CSPRNG blinding seeds per proof). PQ-sound (hash-based), transparent setup.
- `K`, `r`, encaps randomness are RED-zone (libq-mve-rekey §5): never logged / FFI-exported.

## 2. What is proven vs. residual (the honest scope)

The proof **soundly** establishes: there is a **single** `K` such that every wire wrap `w_i`
equals `K + H_zk(ss_i)` for a shared secret `ss_i` the producer knows. A "split" (different `K` to
different recipients) violates the cross-row constant-`K` constraint and admits **no** verifying
proof. This is the core anti-split guarantee (libq-mve-rekey §7 property 1).

It does **NOT** prove `ss_i` is the ML-KEM shared secret of `kem_ct_i` under `update_pk_i` (full
ML-KEM-encaps-in-circuit). See **M1**.

## M1 — KEM-ciphertext binding (the principal residual)

**Claim under review:** robustness ("a malicious producer cannot split the group").

**What holds.** The proof binds, via `H_zk`, that one `K` underlies every wrap. A recipient who
decapsulates `ss_i` from an **honest** `kem_ct_i` recovers exactly that `K` (ML-KEM correctness).
So all honest-ciphertext recipients obtain the **same** key — no split.

**The gap.** The relay verifies the proof but cannot check that `ss_i` (the producer's wrap secret)
matches `Decaps(sk_i, kem_ct_i)` — that needs `sk_i` (which the relay/producer lack) or a proof of
`Encaps(update_pk_i; coins_i) = (ss_i, kem_ct_i)` **in circuit**. ML-KEM-encaps-in-circuit (NTTs,
`Z_q` arithmetic, the FO transform's SHA3/SHAKE) is research-grade and prohibitively expensive in a
Poseidon/FRI AIR — exactly the arithmetization-unfriendliness that motivates the §9 PQ-hash duality.

**Why this is acceptable for the tier's guarantee (not a silent split).** A producer pairing a
valid wrap with a mismatched/garbage `kem_ct_i` makes recipient `i` decapsulate `ss_i' ≠ ss_i`,
unwrap `K'' ≠ K`, and **fail the recipient commitment check** (libq-mve-rekey §4.3) — an
*availability* failure that honest recipients **detect**, which §6/§8 explicitly bound as
acceptable (the relay-less fallback has the same property). The mVE proof upgrades this from
"detected post-hoc" to "single-`K` consistency proven up-front"; the residual is only the
relay's *up-front* ciphertext-binding.

**Adversarial self-check.** *Can a producer split the group with a verifying proof?* To make
recipients `a, b` end with different keys, the wraps must unwrap (under their true `ss`) to
`K_a ≠ K_b`. With honest ciphertexts `ss` is fixed by ML-KEM, so `w_a − H_zk(ss_a) = K_a` and
`w_b − H_zk(ss_b) = K_b`; the proof asserts a single `K` with `w_i = K + H_zk(ss_i)`, forcing
`K_a = K_b = K`. A split therefore requires dishonest ciphertexts → caught by §4.3. No verifying
proof yields a *silent* split.

**Residual for the cryptographer:** decide whether the relay's up-front guarantee must include
KEM-ciphertext binding (then a future `lib-q-mve` revision needs ML-KEM-encaps-in-circuit or a
VOLE-in-the-Head proof of the KEM relation), or whether §4.3 backstop + single-`K` consistency is
the accepted v0 robustness model. **PENDING HUMAN SIGN-OFF — tier stays RED.**

## M2 — Poseidon-256 over GF(p²) (shared with membership O1)

mVE's in-circuit hash is the **same** truncated Poseidon-256 wide sponge as the membership AIR
(`hash_suite_id = 5`, `x⁵`, `t = 7`, `R_F = 8`, `R_P = 60`, over `GF(p²)`). The round-count /
algebraic-degree analysis is therefore **identical** to membership obligation **O1**
([`../../lib-q-zkp/docs/membership-adr113-freeze-gate-review.md`](../../lib-q-zkp/docs/membership-adr113-freeze-gate-review.md)
§7 O1): 8+60 clears the published bounds (USENIX 2021 §5.5 + ePrint 2023/537) by ≈2× at `n = 62`
and still clears the pessimistic `n = 31` subfield case; round constants are generic `GF(p²)`
(nonzero imaginary parts), closing subfield invariance. **No parameter change.**

**Adversarial self-check.** mVE hashes shared secrets and wraps rather than Merkle paths, but the
permutation security is input-independent — the same PRP/round-count argument applies. **PENDING
HUMAN SIGN-OFF — tier stays RED** (the round counts are not human-verified for `GF(p²)`).

## M3 — Zero-knowledge of `(K, r)` (analogue of membership O4)

**Claim under review:** confidentiality — `(key_commitment, {kem_ct_i, w_i}, π)` reveals nothing
about `K` (and `r`) to the relay / any non-recipient (libq-mve-rekey §7 property 2).

**What holds.**
- `K` is **never** a public input. The proof's only public value is `acc` (a Poseidon hash-chain of
  the wire wraps), which the verifier recomputes from data it already has.
- The proof uses the **hiding** PCS (`HidingFriPcs` + `Kt128Rng`): `K` lives in *constant* trace
  columns, whose openings under a **transparent** STARK would leak `K` directly — so a transparent
  proof would be a confidentiality break. The hiding PCS (salted commitments + low-degree
  randomization) prevents that; blinding seeds are fresh OS-CSPRNG per proof (tested: distinct
  proof bytes). `r` is never in the circuit (the commitment is computed outside it).
- The wire wraps `w_i = K + H_zk(ss_i)` hide `K` from non-recipients (the per-recipient mask
  `H_zk(ss_i)` is pseudorandom and secret; `w_i − w_j = H_zk(ss_i) − H_zk(ss_j)` reveals no `K`).

**Residual (same as membership O4).** A formal **simulator** argument for this AIR + hiding PCS, and
the quantitative **masking-degree-vs-opening-count** budget (`log_blowup = 3`, 100 queries + OOD),
must be confirmed — including that the truncated-output sponge openings leak nothing. **PENDING
HUMAN SIGN-OFF — tier stays RED.**

## M4 — Consistency-proof soundness (the anti-split AIR)

**Claim under review:** the AIR soundly enforces "single `K` across all wraps, bound to the wire".

**Argument.**
- **Constant `K`:** `when_transition: next.K == K` chains equality across all rows ⇒ one global `K`.
- **Wrap relation:** `w_i == K + H_zk(ss_i)` every row binds each committed wrap to that `K` and to
  the in-circuit hash of the witnessed `ss_i` (degree-1 binding on the degree-5 sponge output).
- **Public binding:** the `acc` hash-chain `acc_i = H_zk(acc_{i-1} ‖ w_i)`, IV = 0, threaded
  `next.running == parent`, last row `parent == public acc`, binds the committed `w_i` columns to a
  single public digest the relay recomputes from the envelope wraps — so the prover cannot prove
  about one set of wraps and ship another.
- **Padding:** recipient count is padded to a power-of-two height by **repeating the last
  recipient** (exact copies that satisfy every constraint); the verifier knows `n` and the
  repeat-last rule, so it recomputes `acc` over the identical padded sequence. No key-dependent
  padding, no gated rows.

Soundness rests on M2 (Poseidon collision/preimage for the wrap-binding and `acc` chain) and STARK
soundness (production FRI params). The degree-5 `x⁵` S-box is the max constraint degree (ungated, as
in the membership AIR), so the quotient blowup is not overflowed.

**Adversarial self-check.** *Free `ss_i`?* `ss_i` is a witness, but it is **hashed in-circuit**, so
`w_i` is bound to `(K, H_zk(ss_i))` through `H_zk`; a cheater cannot retarget `w_i` to a different
`K'` without a hash collision/preimage (M2). *Swap wraps after proving?* The `acc` binding fails.
*Collide `acc` over a different wrap sequence?* Requires a Poseidon collision (M2). **PENDING HUMAN
SIGN-OFF — tier stays RED.**

## Obligation status summary (engineering view — NOT a sign-off)

| Obl. | Question | Engineering finding | Residual for human cryptographer |
|------|----------|---------------------|----------------------------------|
| M1 | Robustness / anti-split | Single-`K` consistency proven; honest-ciphertext recipients can't be split | KEM-ciphertext binding (`ss_i↔kem_ct_i↔pk_i`) NOT in-circuit; §4.3 backstop. Accept v0 model or require KEM-in-circuit? |
| M2 | Poseidon-256 over GF(p²) | Same hash as membership O1; 8+60 clears bounds; constants generic | = membership O1 (round counts not human-verified) |
| M3 | ZK-of-`(K,r)` | Hiding PCS wired (K not public; fresh OS blinding; transparent would leak K) | Formal simulator + masking-degree budget (= membership O4) |
| M4 | Consistency-proof soundness | Constant-`K` + wrap binding + `acc` public binding; repeat-last padding | Confirm AIR soundness + `acc` collision-resistance (rests on M2) |

**None of the above flips the tier. `lib-q-mve` is RED and remains RED until a human cryptographer
signs off M1–M4. An automated pass is not a sign-off.**
