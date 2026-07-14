# Proof of Correct Encryption for `lib-q-threshold-kem-lattice`

**Status:** RED / unsigned design. No cryptographer has reviewed this. It specifies the
assumption-free closure of the malformed-ciphertext insider probe (the last open boundary in
`THRESHOLD_SECURITY.md`). Nothing here changes the frozen v1 wire; the proof system is an
*additive*, optional gate on the partial-decapsulation path.

Date: 2026-07-10. Crate under construction: **`lib-q-zk-encryption-proof`**.

---

## 1. What must be proved, and why nothing weaker works

`THRESHOLD_SECURITY.md` §4 establishes (rigorously, 3 independent analyses + adjudication) that a
**ciphertext well-formedness proof is insufficient**: the adversary is the encryptor, attacks with
its actual `(e, f)`, and the degenerate spike `f = δ·unit_k` with `δ = 1` has `‖f‖ = 1` — inside
any norm ball — yet still collapses `⟨rand_h, p⟩` to a single-coordinate extraction. Bounding the
*magnitude* of `f` does not bound its *direction*.

The minimal sufficient statement is **proof of correct encryption**: knowledge of the message `μ`
such that the entire noise vector is the deterministic pseudorandom expansion of `μ`. That forces
`f` to be pseudorandom, so the adversary cannot aim the spike, and the single-coordinate extraction
is gone.

Formally, the partial-decapsulation verifier must be convinced of the relation `R_enc` below before
emitting any masked partial. All quantities except `μ` are public (the verifier holds the DKG group
key `t0` and the ciphertext `(p, v)` it is being asked to help decapsulate).

```
Public inputs (bound into the proof):
    pk_digest ∈ {0,1}^256          -- SHAKE-256 digest of t0 (verifier recomputes it)
    p ∈ R_q^KAPPA   (KAPPA = 9)    -- ciphertext vector part
    v ∈ R_q                        -- ciphertext scalar part
    (t0 ∈ R_q^MU, B0 ∈ R_q^{MU×KAPPA} are public/derivable constants)

Witness (secret):
    μ ∈ {0,1}^256

Relation R_enc(pk_digest, p, v ; μ) holds iff:
    (R1)  (e, f, g) = Expand( SHAKE256( DOM_FO_SEED ‖ pk_digest ‖ μ ) )
    (R2)  the coefficients of e are the exact ternary rejection-sampling of the XOF stream,
          and the coefficients of f (KAPPA polys) and g are the exact bounded rejection-sampling
    (R3a) p = B0ᵀ · e + f            in R_q^KAPPA
    (R3b) v = ⟨t0, e⟩ + g + encode(μ) in R_q
```

`DOM_FO_SEED = b"lib-q-threshold-kem-lattice/fo-seed/v1"` (38 bytes). Constants: `N = 1024`,
`q = 281474976694273 ≈ 2^48`, `MU = 6`, `KAPPA = 9`, `ENC_ERROR_BOUND = 2^20`,
`MESSAGE_BITS = 256`, `encode(μ)[i] = (q/2)·μ_i` for `i < 256`, else 0. Draw order (wire-frozen by
the KATs): `e[0..MU]` ternary, then `f[0..KAPPA]` bounded (interleaved into `p`), then `g` bounded.
See `kem.rs` lines 269–378 for the byte-exact reference.

Proving `R_enc` closes the boundary with **no deployment assumption**: it does not rely on
authenticating the encryptor or on a decap budget (those remain the *cheap* deployable closure in
`THRESHOLD_SECURITY.md`; this is the *assumption-free* alternative).

---

## 2. Why this is hard, and the three sub-problems

`R_enc` chains a hash expansion (R1), a rejection-sampling decode (R2), and lattice arithmetic
modulo `q ≈ 2^48` (R3). The proving stack (`lib-q-zkp`, `lib-q-plonky-*`) is a Plonky3-style STARK
over **Mersenne31** (`p = 2^31 − 1`) with value field `Complex<Mersenne31> = GF(p²)`. Two frictions:

1. **Hash size.** The XOF must be squeezed until enough bytes exist for `e` (~8.2 KB after
   rejection), `f` (KAPPA·N·8 ≈ 73.7 KB) and `g` (~8.2 KB): ≈ 90 KB, i.e. ≈ **662 Keccak-f
   permutations** (136 B/squeeze). At 24 rows/permutation that is ≈ 15.9 K trace rows for the hash
   alone — heavy but well inside the prover's `2^24`-row ceiling.

2. **Field bridge.** `q ≈ 2^48` is not the STARK field. Naively emulating R_q multiplication
   (an in-circuit NTT mod `q`, ~54 ring products of degree-1024 polynomials) is `~10^7–10^8`
   constraints and is the reason this was originally scoped as "weeks, field-bridge hard."

The design **avoids the in-circuit NTT entirely** (§4). The three sub-problems map to three AIRs,
composed in one `batch-stark` proof and linked by LogUp:

| AIR | Proves | Field | Scale |
|-----|--------|-------|-------|
| `ShakeSpongeAir` | R1: the exact SHAKE-256 expansion, byte-for-byte | Mersenne31 (16-bit limbs) | ~662 perms × 24 rows |
| `SamplerAir` | R2: XOF bytes → ternary/bounded coefficients (rejection-exact) | Mersenne31 | ~N·(MU+KAPPA+1) rows |
| `LatticeCheckAir` | R3: `p = B0ᵀe+f`, `v = ⟨t0,e⟩+g+encode(μ)` via random Z_q folding | non-native Z_q on Mersenne31 limbs | O((MU+KAPPA+1)·N) MACs |

The witness values (`e, f, g` coefficients; the raw XOF bytes) are shared **across** AIRs; the LogUp
lookups enforce that the byte the sampler consumed at stream-position `i` equals the byte the sponge
squeezed at position `i`, and that the coefficients the sampler produced equal the coefficients the
lattice check folds. See §5.

---

## 3. Sub-problem R1 — `ShakeSpongeAir` (buildable now; the concrete core)

The in-repo `lib-q-plonky-keccak-air` already proves the Keccak-f[1600] **permutation** (2633
columns, 24 rows/perm, verified against `KeccakF` reference). Its `RATE_BITS = 1088 = 136 bytes` is
**exactly** SHAKE-256's rate. What it does *not* prove is the sponge around the permutation:
padding, the rate XOR between the previous output and the next absorbed block, the squeeze
extraction, and cross-permutation chaining. `ShakeSpongeAir` adds precisely that.

### 3.1 Layout

The sponge trace is the Keccak permutation trace (reused verbatim from `generate_trace_rows`) plus a
thin set of **sponge-boundary columns** on the first/last round-row of each permutation block:

- `block_kind ∈ {ABSORB, SQUEEZE}` (selector; our encap input is a single 102-byte absorb that fits
  one 136-byte block, followed by all-squeeze blocks).
- `absorbed_byte[0..136]` and `squeezed_byte[0..136]` on the boundary rows, tied to the permutation
  `preimage`/`a_prime_prime_prime` rate lanes via the existing `input_limb`/`output_limb` maps
  (bytes ↔ 16-bit limbs: 2 bytes/limb, little-endian, matching `rq`/`u64` LE conventions).
- A `stream_pos` counter naming the absolute squeeze-byte index, exported for the LogUp link to the
  sampler.

### 3.2 Constraints added on top of `KeccakAir`

1. **Padding (absorb block).** SHAKE-256 pad10*1 with domain suffix: the first absorbed block is
   `DOM_FO_SEED ‖ pk_digest ‖ μ` (102 bytes) followed by `0x1F` at byte 102, zeros, and `0x80` at
   byte 135 (single-block case: the `0x1F` and `0x80` land in the same block). These are boundary
   constraints on `absorbed_byte[102] = 0x1F`, `absorbed_byte[135] |= 0x80`, `absorbed_byte[103..135] = 0`.
   The first 102 bytes are the public label ‖ public `pk_digest` ‖ witness `μ`.
2. **Absorb = permutation input.** On the first block, `a(y,x,·)` (permutation input) equals the
   padded bytes on the rate lanes and 0 on the capacity lanes.
3. **Rate feed-forward (chaining).** For squeeze block `t+1`, the permutation input equals the
   permutation output of block `t` (state carried; no new absorb after the single input block). This
   is a boundary constraint linking `output_limb` of block `t`'s final round-row to `preimage`/`a`
   of block `t+1`'s first round-row.
4. **Squeeze extraction.** `squeezed_byte[j]` on block `t` equals the LE bytes of the rate lanes of
   that block's permutation output; `stream_pos` increments by 136 per squeeze block.

Every one of these is degree ≤ 2 and touches only boundary rows, so the sponge wrapper adds a small
constant number of constraints on top of the (already-audited) permutation AIR.

### 3.3 Validation for R1 (the KAT this design commits to)

`ShakeSpongeAir::generate_trace(label ‖ pk_digest ‖ μ, out_len)` must produce a trace whose
`squeezed_byte` columns, read in `stream_pos` order, equal `lib_q_sha3::Shake256` XOF output on the
same input, for `out_len` covering the full encap draw. This is a direct, self-contained test (no
prover needed for the correctness half) and is the first landed, validated artifact of this build.

### 3.4 Implementation status — `ShakeSpongeAir` (BUILT + reviewed SOUND + fuzzed + PROVABLE + input partition)

`src/sponge_air.rs::ShakeSpongeAir` (width `NUM_KECCAK_COLS = 2633`, no added columns) delegates to
`KeccakAir::eval` and adds exactly the two boundary-constraint groups of §3.2, specialised to the
frozen encap shape (single 102-byte absorb + squeeze-only — no in-circuit XOR-absorb):
- **(A)** `when_first_row`: block-0 `preimage` carries the SHAKE `pad10*1` tail on the rate (limb
  51 = `0x1F`, limbs 52..=66 = 0, limb 67 = `0x8000` — the byte↔limb mapping is exact for a 102-byte
  block) and 0 on all 8 capacity lanes. Rate limbs 0..=50 (`label ‖ pk_digest ‖ μ`) are now
  **partitioned** (see the input-partition paragraph below): label → constant, pk_digest → public
  values, μ → free witness.
- **(B)** `when_transition().when(step_flags[23])`: `next.preimage = local.a_prime_prime_prime`
  across all 25 lanes (full-state squeeze carry), threading the sponge state; combined with
  `KeccakAir`'s `first_step: preimage == a` this closes the chain with no gap (incl. the special
  lane-(0,0) `a_prime_prime_prime_0_0_limbs` columns).

**Validation approach.** `generate_trace_rows` pads to a power-of-two height with zero-input
permutations, and `24·k` is never a power of two, so the constraint logic is validated by
`check_constraints` on the **truncated** (exactly `24·k`-row) trace — every `step_flags[23]` boundary
there is a real inter-block boundary, and the final one is excluded by `is_transition`. Tests:
honest single-absorb/multi-squeeze trace accepted; a wrong-length (50-byte) input rejected (pad lands
off-position → (A) fails); and — isolating (B) — two permutations with a correctly-padded block 0 but
an unrelated block-1 input are **accepted by `KeccakAir` alone yet rejected by `ShakeSpongeAir`**,
proving the chaining constraint bites.

**Independent adversarial review (2026-07-11, sonnet) = SOUND** on the constraint logic: exact
byte↔limb pad mapping (A); (A) forces a valid single-102-byte-block absorb (capacity 0); **(B)'s
gating reduces entirely to `KeccakAir`'s round-flag integrity** — `step_flags[23]` is 1 only on
round-23 rows (pinned at row 0 + rotated every transition), so (B) fires at exactly the `k−1` real
boundaries and never elsewhere; gapless full-state carry (all 25 lanes, incl. lane (0,0)); truncation
faithfully tests the logic. **Fuzzed:** 5×60 single-cell tampers on a 2-perm trace — the only
survivors are the benign `export` bit (KeccakAir's LogUp hook, free on final-step rows, unused here;
allowlisted, not a finding). **34 lib tests green, clippy `-D`, fmt.**

**Prove/verify path landed — continuation padding instead of a boundary selector (2026-07-11).** The
earlier residual "prove-time boundary selector" is *resolved without a selector or preprocessed
column*: `generate_provable_sponge_trace` builds a power-of-two-height trace (`H = next_pow2(24·k)`)
by **squeezing extra, ignored continuation permutations** — it generates `⌊H/24⌋+1` real sponge
continuation input states (`sponge_permutation_states`) and truncates to `H` rows, so the final
(partial) chunk is backed by a real continuation input and *every* permutation boundary in the trace
is a genuine sponge step. Constraint (B) then holds **uniformly** (no last-real → padding boundary
exists), the AIR is unchanged (so the SOUND review above still applies verbatim), and
`StarkProver`/`StarkVerifier` prove & verify the pad + chaining constraints end-to-end (a corrupted
pad byte fails to verify). Soundness note: a malicious prover must satisfy (A)+(B)+`KeccakAir` on all
`⌊H/24⌋` permutations, forcing a correct SHAKE sponge; the extra continuation blocks are constrained
to be correct too but their output is ignored, so they add no soundness surface. `H` is public (the
committed trace degree, fixed by the public `out_len`).

**Input partition landed (2026-07-11).** Constraint group (A) now tiles the 102-byte message prefix
(51 rate limbs, byte↔limb mapping exact and compile-time-guarded by four `const _: () = assert!(…)`):
- **label** (limbs 0..=18, bytes 0..37) pinned to the frozen `DOM_FO_SEED` constant (duplicated from
  the crate-private tkem constant — cannot import without a dep cycle; guarded by the
  `dom_fo_seed_layout_is_frozen` CI test);
- **pk_digest** (limbs 19..=34, bytes 38..69) pinned to the 16 public values `sponge_public_values(pk)`
  (LE 16-bit limbs) — binds the proof to *one* public key;
- **μ** (limbs 35..=50, bytes 70..101) left a **free witness** (the ZK secret).

Because the pinned columns *are* the permutation input `preimage` that `KeccakAir` threads through the
round function (via `first_step: preimage==a` + preimage-constancy), the squeezed output is a
deterministic function of exactly `(label, pk_digest, μ)`; μ is not an under-constraint hole (KeccakAir
forces it to be consistently carried, not free-per-row). `num_public_values = 16`.

**Independent adversarial review (2026-07-11, sonnet) = SOUND-with-obligations.** Byte mapping exact
and non-overlapping (guards enforce the tiling); pk-binding load-bearing; first-row-only not evadable
(the absorb is always block 0, rows 0..23, input fixed at row 0); μ consistently threaded; public-value
count correct. Tests added: honest encap-preimage accepted under matching public values; **a proof for
`pk_A` rejected under `pk_B` public values** (the ciphertext-binding property); tampered label rejected;
μ-as-free-witness (two messages, same pk, both accept). **38 lib tests green (release), clippy `-D`,
fmt.** (Debug-build note: `StarkProver::prove` runs `check_constraints` internally, so tamper tests
must treat a prove-time panic as rejection — these are release-mode tests, consistent with the crate.)

**Residual = composition (documented, correctly scoped):** (1) **verifier pk-wiring obligation
(load-bearing)** — the verifier must build the public values itself as `sponge_public_values(&ct.pk_digest)`
and NOT accept prover-supplied ones, else the binding is vacuous; (2) the **LogUp squeeze join** (join 1)
exposing the output rate bytes to the sampler. Note the AIR does not itself forbid a multi-block absorb
— that is structural (the fixed public perm-count for the 102-byte shape makes it impossible for the
concrete instantiation), not an in-AIR constraint.

---

## 4. Sub-problem R3 — `LatticeCheckAir` and the field bridge (the design crux)

**Observation that kills the in-circuit NTT:** given the public `(B0, t0, p, v)`, relations R3a/R3b
are **`Z_q`-linear (affine) in the witness** `(e, f, g)` and in `encode(μ)`. `B0ᵀe` is a public
matrix times a witness vector; `⟨t0,e⟩` is a public constant convolved with witness `e`; `f, g` add
linearly; `encode(μ)` is linear in the bits of `μ`. There is no witness×witness product. So R3 need
not be *computed* in-circuit — it need only be *checked*, and a linear relation is checked by a
**random linear combination**, one scalar equation over `Z_q`.

### 4.1 The fold (divisibility at random points — the sound, realizable form)

> **Correction (2026-07-10, during R3 build).** An earlier draft of this section folded the
> *coefficient vectors* against a uniform `γ ∈ Z_q^N` and claimed the circuit needs only
> `MU+KAPPA+2 ≈ 17` inner products with `1/q` soundness. That is **not soundly realizable**: the
> convolution `B0ᵀe` folded by an *unstructured* `γ` does not collapse to the per-`e_r` scalars
> `E_r = ⟨γ,e_r⟩` — reconstructing the slot equations needs per-slot public fold vectors
> `c^{(k,r)}_b = Σ_i γ_i M^{(k,r)}_{i,b}` (`M` = the negacyclic matrix of `B0_{r,k}`). Those depend
> on the Fiat-Shamir `γ`, so they cannot be preprocessed; supplying them is `~KAPPA·MU·N ≈ 55 K` Z_q
> public inputs (equivalently, an in-circuit NTT). A geometric `γ_i = ζ^i` collapses the convolution
> *only at 2N-th roots of unity* (`ζ^N = −1`), of which there are `2N`, giving Schwartz–Zippel error
> `≈ 1/2` — useless. The sound form below evaluates at random points in **all of `Z_q`** and pays for
> the negacyclic reduction with *witnessed quotient polynomials*.

Verify each ring identity as a **polynomial divisibility** in `Z_q[X]`. R3a slot `k` is equivalent to
the existence of a quotient `H_k` (deg ≤ `N−2`, prover-supplied witness) with

```
Σ_r B0_{r,k}(X)·e_r(X) + f_k(X) − p_k(X)  =  (X^N + 1) · H_k(X)          (R3a_k)
Σ_r  t0_r(X)·e_r(X) + g(X) + encode(μ)(X) − v(X)  =  (X^N + 1) · H'(X)   (R3b)
```

The left sides use the **unreduced** products (deg ≤ `2N−2`); `(X^N+1)H` carries the negacyclic
reduction. Draw `m` independent challenges `ζ^(1..m) ∈ Z_q` from the FS transcript, each
**rejection-sampled** (squeeze 6 bytes, retry if `≥ q`; a bare `mod q` on a 48-bit draw biases by
`(2^48−q)/2^48 ≈ 2^-34`, which would leak into soundness — rejection costs ≈ one retry per `2^16`
draws). For each `ζ = ζ^(l)` the circuit checks the **scalar `Z_q`** equations

```
slot k:  Σ_r B0_{r,k}(ζ)·E_r + F_k − p_k(ζ) − (ζ^N+1)·HK_k = 0
scalar:  Σ_r  t0_r(ζ)·E_r + G + ENC − v(ζ) − (ζ^N+1)·HP = 0
```

where `E_r = e_r(ζ)`, `F_k = f_k(ζ)`, `G = g(ζ)`, `ENC = encode(μ)(ζ)`, `HK_k = H_k(ζ)`, `HP = H'(ζ)`
are **witness Horner-folds** the circuit computes, and `B0_{r,k}(ζ), t0_r(ζ), p_k(ζ), v(ζ), (ζ^N+1)`
are **public scalars** the verifier evaluates itself. The witness side per point is
`e_r (MU) + f_k (KAPPA) + g + enc + H_k (KAPPA) + H' = 2·KAPPA + MU + 3 ≈ 27` length-`N` folds — not
17; the earlier figure omitted the quotient folds and the `m` repetition. Ternary `e` folds add no
multiply (coeffs ∈ {−1,0,1}); `f, g` are ≤ 21-bit; only the quotients are full `Z_q`. Dominant cost
`≈ m · (N Horner mults)` per fold `≈ few · 10^4` non-native `Z_q` mults — still `~10^2–10^3×` under
the in-circuit NTT, so the bridge stands.

### 4.2 Soundness of the fold

If a ring relation is **false**, no valid quotient exists, so for *any* prover-supplied `H` the
polynomial `LHS − (X^N+1)H` is **nonzero of degree ≤ 2N−2**: writing
`Σ_r B0_{r,k}e_r + f_k − p_k = D_k + (X^N+1)H_k^{true}` with defect `D_k = p_k − f_k − (B0ᵀe)_k ≠ 0`
(deg < N), the checked polynomial is `D_k + (X^N+1)(H_k − H_k^{true})`; its degree-≥N part
`(X^N+1)ΔH` cannot be cancelled by the degree-<N `D_k` unless `ΔH = 0`, in which case it equals
`D_k ≠ 0`. By Schwartz–Zippel it vanishes at a uniform `ζ ∈ Z_q` with probability `≤ (2N−2)/q ≈
2^-37`. Over `m` **independent** points the error is `≤ ((2N−2)/q)^m`; `m = 4` gives `≤ 2^-148`,
clearing 128 bits. Crucially `e, f, g` are pinned by R1+R2 (LogUp join 2), so the prover's only
freedom is the auxiliary quotient witnesses `H_k, H'` — and because the *same* witness polynomials
are folded at *every* `ζ^(l)` (one commitment, evaluated at all points), the prover cannot choose
`H(ζ^(l))` independently per point. (A single evaluation in a degree-`d` extension `GF(q^d)` reaches
`≤ (2N−2)/q^d` in one instance, trading `m` scalar points for in-circuit `GF(q^d)` MACs — deferred.)

This soundness stacks *below* the STARK's own soundness (the AIR constraints prove the folds and the
mod-`q` reductions were computed correctly). The fold's `2^-148` is the probability a prover with a
**false** R3 passes; the STARK's `~2^99–2^116` provable / `~2^128+` conjectured soundness (per the
BabyBear/Poseidon note and `membership_config`) is the probability a prover cheats the arithmetic.
The proof's overall soundness is `min` of these — the honest paper claim is the **provable** STARK
figure, not 128 (see the Arm-B soundness memo).

### 4.3 Non-native `Z_q` MAC gadget

`q = 281474976694273 = 2^48 − 2^14 + 1` (a Solinas-like prime; `2^48 ≡ 2^14 − 1 (mod q)` gives a
fast fold, though the AIR uses the generic witnessed-quotient reduction below for simplicity/
soundness).

> **Correction (2026-07-10, during R3 build).** An earlier draft used **three 16-bit limbs**. That
> is unsound over Mersenne31: a limb product `a_i·b_j` reaches `(2^16−1)^2 ≈ 2^32 > p = 2^31−1`, so
> the field product wraps and field-equality no longer implies integer-equality. The limb size `L`
> must keep a whole group sum in-field: with `n = ⌈48/L⌉` limbs the middle group has up to `n`
> partials, so `n·2^{2L} < 2^31`. **`L = 14`, `n = 4`** is the clean fit — partials `< 2^28`, middle
> group `4·2^28 = 2^30 (+carry) < 2^31`. So a `Z_q` element is **four 14-bit Mersenne31 limbs**
> (56-bit capacity; the top limb holds `48 − 42 = 6` bits).

**Key simplification — the fold is public-linear.** In `acc ← acc·ζ + w_i` the challenge `ζ` is a
*public* Fiat-Shamir scalar, so `acc·ζ` is a **public-coefficient-linear** function of `acc`'s limbs
(`ζ`'s limbs are public constants; each partial `acc_i·ζ_j` is witness×public `< 2^28 < p`). There is
**no witness×witness product** anywhere in the fold — the only nonlinearity is the witnessed mod-`q`
reduction. So the atomic gadget is: compute the (public-linear) `acc·ζ + w_i < 2^96`, **witness** a
quotient `κ < 2^48` and remainder `r < q`, assert the integer identity `acc·ζ + w_i = κ·q + r` by a
14-bit-limb carry chain (all terms public-linear in the witnesses, both sides `< p` per limb group),
and range-check `κ` (bit decomposition) and `r < q` (borrow-chain comparison against the public
constant `q`, as in the bounded sampler's `r ≤ Z`). Constraints per Horner step ≈ 40–60 (the carry
chain over ~7 limb positions + two range checks). The corrected fold does
`≈ 27 folds/point × m points × N` Horner steps `≈ 27·4·1024 ≈ 110 K` steps → `≈ 5 M` constraints —
larger than the earlier `600 K` estimate (which used the wrong 17-IP count and `m=1`), still well
inside the `2^24`-row prover ceiling; ternary-`e` folds skip the multiply (coeffs ∈ {−1,0,1}), and
the per-point `ζ`-power chain is shared across all folds at that point.

### 4.3a Implementation status — `ModReduceAir` (BUILT + reviewed SOUND)

`src/zq.rs::ModReduceAir` (width `MODREDUCE_WIDTH = 372`) is the **atomic reduction primitive** the
whole fold rests on: per row it proves `V = κ·q + r`, `0 ≤ r < q`, `0 ≤ κ < 2^48`, for a witnessed
`V < 2^96`. Built with the corrected **12-bit limbs** (§4.3): `κ·q` is a public-linear schoolbook
(`q`'s limbs are constants), verified against `V` by an unsigned base-`2^12` carry chain with
`carry_8 = 0` (no top carry-out column ⇒ `κ·q + r < 2^96`); `κ` is 4×12-bit range-checked (⇒ `κ <
2^48` structurally); `r < q` is a 4-limb borrow subtraction against `q − 1` with the final borrow
forced to 0. Range checks by bit decomposition (self-contained; no LogUp).

**Independent adversarial under-constraint review (2026-07-10, sonnet) = SOUND** on all five claims:
field-fit (worst LHS `≈ 5.0·10^7`, worst RHS `= 2^27 − 1`, both `≪ p = 2^31 − 1` — 16–42× margin, so
field-eq ⇔ integer-eq with no wrap; 15-bit carries fit honest peak `≈ 12283` yet cannot wrap),
`carry_8 = 0`/`κ < 2^48`, canonical `r < q` (telescoping borrow argument; a forged negative digit
can't fit 12 boolean bits), complete range checks (all κ/r/V/carry columns Horner-linked + bits
boolean), and padding (no transition constraints; pad rows are real `V = 0` reductions). No holes.
Validated: prove/verify over values spanning `0 … 2^95` incl. `κ` near the `2^48` ceiling, tampered-`r`
rejected, non-canonical `r ≥ q` rejected. 15 lib tests green, clippy `-D`, fmt.

### 4.3b Implementation status — `HornerFoldAir` (BUILT + reviewed SOUND)

`src/zq.rs::HornerFoldAir` (width `HORNER_WIDTH = 393`) is the **fold layer**: chained rows compute
`E = Σ_i c_i·ζ^i (mod q)` by Horner steps `acc ← (acc·ζ + w) mod q` (`next.acc = this.r`,
`first.acc = 0`, coefficients fed high-order-first). `ζ`'s four 12-bit limbs are public. Key trick: a
**single fused signed carry chain** verifies `acc·ζ + w = κ·q + r` without materializing the product —
per-limb `net_g = L_g + w_g − R_g − r_g` with `c_0 = c_8 = 0` hardcoded telescopes to
`Σ_g net_g·2^{12g} = 0`. Signed carries stored offset by `2^17`, 18-bit range-checked (~200 columns
narrower than the two-chain-with-explicit-`V` alternative).

**Independent adversarial review (2026-07-10, sonnet) = SOUND on the fold's internal arithmetic:**
telescoping exactness (both boundary carries are literal constants, not free witnesses), field-fit
(worst term `< 2^30`, `< p = 2^31−1` with ~2× margin, so no wrap), carry range-check completeness,
Horner chaining (every row's `acc` pinned; last-row `r` fixed by its own fused identity + `r < q`),
and `r < q`. The review flagged **three composition obligations** (boundary bindings the fold cannot
self-supply — now recorded in the module doc and here):
- **Expose `E`.** The last-row `r` is `E` but is *not* a public value; the relation-check AIR must
  read it (boundary opening / shared column) or a prover could fold a *different* polynomial.
- **Bind coefficients.** `w` is only locally `< 2^48`; its tie to the real sampler coefficients (and
  `w < q`) comes from LogUp **join 2**.
- **Canonical `ζ`.** The public `ζ` limbs must be `< 2^12` (met by `horner_public_values`); a
  non-canonical limb could breach the field-fit bound.
Validated: fold of 16 coefficients matches the reference `Σ c_i ζ^i mod q`, prove/verify, tampered
result rejected. 17 lib tests green, clippy `-D`, fmt.

### 4.3c Implementation status — `RelationCheckAir` (BUILT + reviewed SOUND)

`src/zq.rs::RelationCheckAir { num_terms: L }` proves the canonical scalar equation
`Σ_{j<L} a_j·w_j + c ≡ 0 (mod q)` — the shape every folded relation (§4.1) reduces to: `a_j` public
(`B0_{r,k}(ζ)`, `ζ^N+1`, …), `w_j` the witness fold outputs (`E_r, F_k, HK_k`), `c` public
(`p_k(ζ)`, …). Negative terms are pre-folded into the coefficients as `q − x` (so `a_j, c ∈ [0,q)`,
`LHS ≥ 0`, and `LHS ≡ 0 (mod q) ⇔ LHS = κ·q`). Verified by the **same fused signed carry chain** as
the fold, telescoping `LHS − κ·q = 0` over 8 limb positions (`κ` 5×12-bit, remainder 0). Public coeffs
enter as public values; the relation is checked in every (replicated) row.

**Independent adversarial review (2026-07-10, sonnet) = SOUND on all soundness claims**, including
the critical `κ·q` top-limb capture (`κ_4·Q_3` at g=7 is included — no silent truncation), telescoping
exactness at any magnitude (signed carries absorb `LHS > 2^96`; `c_8 = 0` *is* the divisibility
statement), `κ` uniqueness, and the `q−x` encoding faithfulness. Field-fit holds to `L ≤ 31`; a
defensive `L ≤ 15` guard (`REL_MAX_TERMS`, the tighter *completeness* bound where honest carries
`4L·2^12` still fit the `2^18` offset) was added. External deps (by design): `w < q` and the tie of
`w` to real fold outputs come from LogUp **join 2**; `a_j, c < q` are verifier obligations. Validated:
`L=8` relation proves/verifies, tampered witness rejected, false relation unprovable. 20 lib tests
green, clippy `-D`, fmt.

**R3 non-native arithmetic toolkit is now COMPLETE** — `ModReduceAir` (§4.3a) + `HornerFoldAir`
(§4.3b) + `RelationCheckAir` (this section), all reviewed SOUND. What remains for R3 is **composition
wiring only** (no new arithmetic): boundary openings to feed the folds' `E` into `RelationCheckAir`
(obligation 1); LogUp joins 1 & 2; the `encode(μ)` fold + boolean-`μ` binding (§4.4); the sponge
constraint-eval; `prove_batch`; hiding-FRI ZK; the tkem gate.

### 4.3d Mechanical under-constraint fuzzer (`src/fuzz.rs`) — assurance without a cryptographer

Because no human cryptographer is available to sign off, the R3 arithmetic core's soundness is
hardened *mechanically* by a fuzzer that turns the crate's fast constraint evaluator
(`lib_q_stark::check_constraints`, wrapped in `catch_unwind`) into a boolean accept/reject oracle and
hunts for a **satisfying-but-tampered trace** — the operational definition of an under-constraint hole.

**What it does (per arithmetic AIR — `ModReduceAir`, `HornerFoldAir`, `RelationCheckAir`):**
- **Completeness sweep** — builds `N = 40` random valid instances; each must be *accepted* (a rejected
  valid trace fails the test). Catches over-constraint / trace-gen drift.
- **Single-cell mutation census** — for each valid instance, `M = 300` random single-cell flips to a
  random `M31` value; each must be *rejected*. `survivors.is_empty()` is a hard assertion: these three
  AIRs are dense (every column is live on every row, no `active`-gating), so *any* survivor is a cell
  the constraints fail to pin — a genuine finding. `40·300·3 = 36,000` trials; **zero survivors.**
- **Negative-control canary (mandatory).** A deliberately broken `CanaryAir` (col 0 pinned to 1, col 1
  left unconstrained) is run through the *same* census; the test asserts survivors *exist* and land
  *only* in col 1. This proves the harness genuinely detects an unconstrained column — it forecloses
  the "harness always reports clean" failure mode that would make the whole fuzzer worthless.

**Result (2026-07-11):** all four fuzz tests pass; **no survivors in any of the three arithmetic
AIRs** at 12,000 trials each; canary finds survivors only in its unconstrained column. So the R3
core's `reviewed SOUND (RED)` verdicts are now backed by 36k random single-cell tampers that all
bounced, on a canary-validated oracle. Deterministic (SplitMix64, fixed seeds) ⇒ reproducible.

**Coverage boundary (stated honestly — this is a *floor*, not a proof):**
- **1-cell only.** Does NOT catch coordinated *2-cell* attacks (e.g. the non-canonical `(κ−1, r+q)`
  shift, which flips two cells in concert). Those stay covered by the hand-written targeted reject
  tests (`modreduce_rejects_noncanonical_remainder`, `…_tampered_*`). The 2-cell / all-subset search
  is the SMT (Picus/Ecne-style) or Lean escalation, if a deployment target demands machine-checked
  soundness.
- **Real-part mutations only.** Mutates to `M31` real values, not `GF(p²)` elements with a nonzero
  imaginary part. Argued benign (bit constraints `b(1−b)=0` admit only `b=0,1` over `M31[i]`, so
  imaginary parts are transitively pinned to zero), but not *tested* — a dedicated imaginary-injection
  pass is the next hardening step.
- **Three arithmetic AIRs only.** The two samplers (`TernarySamplerAir`, `BoundedSamplerAir`) have
  `active`-gated columns (benign free cells on inactive rows), so a blanket `survivors.is_empty()`
  would false-positive; they need active-row classification (a census-report allowlist) — deferred.
  The sponge has no constraint-eval yet (only trace-gen), so it is not yet fuzzable.

**Standing discipline:** every new constraint-eval-complete AIR (the sponge, the composed
`encode(μ)` fold, the batch composition) gets fuzzed as it lands — build-then-fuzz is the
security rhythm for this crate absent a cryptographer.

### 4.4 Binding `μ` in R3b (do not let `encode(μ)` be a free ring element)

R3b is `v = ⟨t0,e⟩ + g + encode(μ)`. There is a trap: if `encode(μ)` is committed as an
*unconstrained* witness ring element, the prover can set it to `v − ⟨t0,e⟩ − g` and R3b passes
**vacuously**. Two constraints close this, and together they bind the `μ` used in R3b to the `μ`
absorbed by the sponge:

1. **Valid-encoding constraint (`LatticeCheckAir`).** The `μ`-bit columns `μ_0..μ_255` are each
   constrained boolean (`μ_i(μ_i−1)=0`), and `encode(μ)` is *derived*, not free:
   `encode(μ)_i = ⌊q/2⌋·μ_i` for `i < 256`, `= 0` for `i ≥ 256` (the tkem `encode_msg` uses integer
   `⌊q/2⌋ = 2^47 − 2^13`, since `q` is odd — *not* a rational `q/2`). So `encode(μ)` ranges only over
   the `2^256` valid encodings, not all of `R_q`.
2. **Transitive binding to the sponge's `μ` (no third join needed).** `e` and `g` are pinned by R1+R2
   to the SHAKE expansion of the sponge's `μ` and propagated to `LatticeCheckAir` by LogUp join 2
   (§5.1). Given pinned `(e,g)` and public `v`, the fold forces `encode(μ_lc) = v − ⟨t0,e⟩ − g`.
   Because `encode` is **injective** (`q/2 ≠ 0`, and `q` is prime so `q/2` is a well-defined nonzero
   residue; distinct bit-strings give distinct coefficient vectors), the valid encoding equal to that
   forced value is *unique*. For an honest ciphertext `(p,v)=Enc(μ)` that unique value is
   `encode(μ)`, so `μ_lc = μ` (the sponge's message). No separate LogUp join on the `μ` bytes is
   required — the binding flows through `(e,g)` plus injectivity. (A third join on the 32 `μ` bytes is
   a valid belt-and-suspenders alternative; it is heavier and unnecessary given constraint 1.)

#### 4.4a Implementation status — `EncodeMuFoldAir` (BUILT + reviewed SOUND + fuzzed)

`src/zq.rs::EncodeMuFoldAir` realizes constraint 1 as a *standalone, fuzzable* AIR: it computes
`E_encode = encode(μ)(ζ) = Σ_{i<256} ⌊q/2⌋·μ_i·ζ^i (mod q)` by **delegating to the fuzzer-validated
`HornerFoldAir`** (256-term Horner, height 256 = 2^8, no padding) and appending one boolean `μ_bit`
column per row plus the *derivation* constraint `w_j = HALFQ_j·μ_bit` (`HALFQ = ⌊q/2⌋ = 2^47−2^13`,
limbs `[0,4094,4095,2047]`). Because `HALFQ` is a public constant and `μ_bit ∈ {0,1}`, each row's
coefficient `w` is provably the select `0 / ⌊q/2⌋` — the free-ring-element vacuity trap is closed
*inside this AIR*, and `w < q` is **structural** (no join-2 coefficient bound needed here, unlike the
generic fold). Width `HORNER_WIDTH + 1 = 394`; public values = ζ's four 12-bit limbs (shared
`encode_mu_public_values` = `horner_public_values`).

**Independent adversarial under-constraint review (2026-07-11, sonnet) = SOUND** on the crux (the four
ties + boolean-`μ` pin every row's `w` to exactly `{0, HALFQ}` — no satisfying trace encodes an
invalid coefficient), delegation correctness (the delegated `eval` reads only cols 0..393; the μ-bit
at 393 alters no fold constraint; public-value indexing aligns), field-fit with `w=HALFQ` (κ ≤ q−2 <
2^48, 4-limb bound holds), and row-ordering/bit-extraction (matches the KEM `(mu[i/8]>>(i%8))&1` and
the reference). **Mechanical fuzz (build-then-fuzz discipline, §4.3d):** 16 instances × 200 single-cell
tampers = 3,200 trials on the dense 256×394 trace → **zero survivors**; completeness holds. Validated:
`E` matches an independent high-order Horner reference over the KAT message `μ=(0..31)`, prove/verify
succeeds, a flipped μ-bit (without matching `w`) is rejected by the derivation tie. **28 lib tests
green** (incl. the 4-AIR fuzzer), clippy `-D`, fmt.

**Residual = composition only** (the review's load-bearing items, mirrored in the module doc): (1)
expose last-row `r = E_encode` to R3b's `RelationCheckAir` (boundary opening — the load-bearing one);
(2) canonical ζ limbs (met by the shared constructor); (3) μ↔sponge binding via the transitive
`(e,g)` + injectivity argument above (no third join); (4) **same ζ across all fold AIRs** (e/g/encode
must evaluate at one Fiat-Shamir challenge, else §4.1 is checked at mixed points). A standalone
`EncodeMuFoldAir` proof attests only "*some* binary μ′ folds to `encode(μ′)(ζ)` with the result in the
last-row `r`" — *which* μ′, and that `r` is consumed, are the composition's job.

---

## 5. Sub-problem R2 — `SamplerAir` and the LogUp links

R2 proves each coefficient was correctly derived from the XOF byte stream by the exact wire-frozen
sampler. Two decode rules:

- **Ternary `e`:** read 1 byte, `two = byte & 3`; if `two < 3` emit `two − 1 ∈ {−1,0,1}` (stored
  `.rem_euclid(q)`), else reject and read the next byte. The AIR carries `(byte, two, accepted,
  coeff, stream_pos)` per attempt; constraints: `two` is `byte mod 4` (bit-decompose low 2 bits),
  `accepted = [two ≠ 3]`, `coeff = two − 1` on accept. Rejections are rare but must be represented
  (they consume a stream position without emitting a coefficient) — the `stream_pos`/`coeff_idx`
  counters diverge on reject, which is exactly what the LogUp position-tag captures.
- **Bounded `f, g`:** read 8 bytes LE as `r`; if `r < zone = u64::MAX − (u64::MAX mod span)`,
  `span = 2·2^20 + 1`, emit `(r mod span) − 2^20`, else reject. The AIR witnesses the 8 bytes, the
  `u64` recomposition, the comparison `r < zone` (range check), and the `r mod span` reduction
  (quotient + remainder, range-checked). This is the heaviest sampler row (a 64-bit mod).

### 5.1 The two LogUp joins

1. **Sponge → Sampler (bytes).** Global LogUp on tuples `(stream_pos, byte_value)`: every byte the
   sponge squeezes is looked up by exactly one sampler row, keyed by absolute position. **LogUp
   multiset equality does not by itself enforce ordering** — a prover could otherwise present the
   sampler consuming positions out of order (feeding a different byte into a rejection slot). The
   ordering is enforced by an **explicit `SamplerAir` transition constraint**, not by the lookup:
   `stream_pos[0] = 0` and `stream_pos[row+1] = stream_pos[row] + bytes_consumed[row]` (where
   `bytes_consumed ∈ {1, 8}` for ternary/bounded rows, or `0` for a dummy tail row). The position tag
   plus this monotone counter together make the join an *ordered* lookup; neither suffices alone.
2. **Sampler → LatticeCheck (coefficients).** Global LogUp on tuples `(role, coeff_idx, coeff_value)`
   where `role ∈ {e_r, f_k, g}`: the coefficients the sampler *emitted* equal the coefficients the
   lattice check *folded*. This binds the same `(e,f,g)` across R2 and R3 without re-deriving them.

Both use the existing `LogUpGadget` (`Kind::Global`, degree-manageable) and its
`generate_permutation` prover path. The cumulative-sum-zero check across the batch closes the join.

### 5.1a Implementation status — ternary sampler (BUILT + reviewed)

`src/sampler.rs::TernarySamplerAir` implements R2 for `e` in native `Mersenne31` (ternary coeffs are
`{-1,0,1}`; the `mod q` lift is deferred to R3). Width 14: `active, stream_pos, coeff_idx, byte,
bit[0..8], accepted, coeff_val`; one public value `num_coeffs`. Constraints: byte = Horner sum of 8
boolean bits (pins `byte ∈ [0,256)` and fixes `bit0,bit1` = the low two bits); `accepted =
active·(1 − bit0·bit1)` (forces the exact accept-iff-`two<3` rule — no skip/forge); `coeff_val`
forced to `two−1` on accept, `0` otherwise; `stream_pos += active`, `coeff_idx += accepted` with
`stream_pos[0]=coeff_idx[0]=0` and last-row `coeff_idx+accepted = num_coeffs`; `active` non-increasing
(padding after real rows). An **independent adversarial under-constraint review returned SOUND** on
all intra-trace relations (bit/byte, accept/reject, coeff value, counters/ordering, padding all fully
pinned); the only unbound relations are the two *intended* LogUp joins (§5.1). Validated: trace
matches `xof_ternary_poly` on 1024 coeffs, STARK prove/verify roundtrip, tampered-coeff rejected.

### 5.1b Implementation status — LogUp join 1 (mechanism + Receive side; `src/logup_join.rs`)

Join 1 (sponge → sampler bytes) is realised as a **positional cross-table LogUp** on tuples
`(position, byte)` over the shared bus `libq.enc.xof-stream.v0` (`Kind::Global`). Both sides fold the
2-tuple by the LogUp challenge `β` to `α − (pos + byte·β)`, so a Send cancels a Receive only when
*both* the position and the byte match; positional binding holds with collision probability `≈ 2⁻⁶²`
over the value field `GF(p²)`, `p = 2³¹−1`.

- **Receive side (the real samplers, BUILT):** `sampler.rs::ternary_receive_lookup` sends one tuple
  `(stream_pos, byte)` per row (mult `active`); `bounded_receive_lookup` sends eight tuples
  `(stream_pos + k, r_byte_k)`, `k=0..8` (mult `active`). Both use `Direction::Receive`. `LookupAir` is
  implemented on both sampler AIRs so the batch prover can pull them via `get_lookups`.
- **Send side (byte-stream SOURCE):** `logup_join.rs::XofStreamTableAir` — a positional byte table that
  Sends `(pos, byte)` (mult `active`) with `pos` a monotone 0-based counter. This **stands in for the
  sponge's squeezed output** until the sponge Send side is built (see obligations).
- **Validation:** `lib_q_plonky_lookup::debug_util::check_lookups` (the multiset-balance analogue of
  `check_constraints`, which sums `Kind::Global` tuples across instances and asserts net-zero). Six
  tests: honest ternary and bounded streams balance the source; a tampered source byte, a missing
  source byte, a shifted position, and the bounded 8-byte case all unbalance and are rejected.
- **Independent adversarial review (2026-07-11, sonnet) = SOUND-with-obligations.** Tuple columns and
  offsets exact (no off-by-one for either sampler); multiplicity gating correct given the sampler AIR's
  `active ∈ {0,1}`; positional binding sound over `GF(p²)`; length surplus/deficit caught by the
  global balance. **44 lib tests green (release), clippy `-D`, fmt.**

**Obligations OUTSIDE this join (documented; required for the composite argument):** (1) **sampler AIR
co-enforcement** — the lookup multiplicity is the raw `active` column; `active ∈ {0,1}` is an AIR
constraint, so the batch proof must verify the sampler AIRs *and* their lookups jointly. (2) **sponge
Send side** — `XofStreamTableAir`'s byte values are free; until the Keccak squeeze output binds them
(limb→byte decomposition on `export` rows + a squeeze-block index → `(pos, byte)` tuples), the join
proves positional order, not byte provenance. (3) **global offsets** — each sampler's `stream_pos` is
local (from 0); on one bus the several sub-draws (`e`, each `f`, `g`) must be shifted by their absolute
byte offset in the XOF, else the composition is unsatisfiable even for an honest prover (not a forgery
vector, but ill-formed). (4) **batch verifier** must run the per-bus `verify_global_final_value` on the
exact bus name. (5) **`num_coeffs`** public values must be pinned to the true lattice dimensions.

### 5.1c Implementation status — join 1 sponge SEND side (byte decomposition; `src/squeeze_byte.rs`)

The samplers consume *bytes* but the SHAKE squeeze output is produced as 16-bit *limbs* (4 per rate
lane, 17 lanes = 68 limbs = 136 bytes/squeeze permutation). `SqueezeByteAir` (width 21) is the
byte-provenance half of the sponge Send side: **one row per rate limb**, decomposing it into a low/high
byte pair and Sending them positionally.
- **Byte decomposition + range (load-bearing):** `lo = Horner(lo_bits)`, `hi = Horner(hi_bits)` over 8
  boolean bits each ⇒ `lo, hi ∈ [0,256)` (the unique canonical 8-bit decomposition). This is the byte
  range check the **bounded sampler delegates** (§5.2) — every byte reaching the bus is `< 256`.
- **Position axis:** `bytepos` = absolute position of the low byte, a monotone counter (`0` at row 0,
  `+2` per active row). Global limb index `g` sits at `bytepos = 2g = perm·136 + 2·limb_in_perm`, so
  this single counter *is* the key the sponge's future limb-Send will use — no separate `perm`/`limb`
  columns. Byte order matches `sponge::read_output_rate` / reference SHAKE (lane-major, LE per lane).
- **Sends** `(bytepos, lo)` gated by `active` and `(bytepos+1, hi)` gated by `has_hi` on
  `libq.enc.xof-stream.v0`. `has_hi` clears on an odd-length tail so the table Sends exactly the
  consumed byte count (a produced-but-unconsumed tail hi is decomposed/range-checked but not Sent).
- **Validation:** a KAT that the reconstructed bytes equal reference SHAKE-256 (incl. a 273-byte odd
  tail); `check_constraints` on the AIR; `check_lookups` balancing both the ternary and bounded sampler
  Receive sides; and a tampered-but-canonically-recoded byte (AIR still accepts) that unbalances the
  join. **49 lib tests green (release), clippy `-D`, fmt.**
- **Independent adversarial review (2026-07-11, sonnet) = SOUND-with-obligations:** canonical
  decomposition unique; range load-bearing holds; `bytepos` strictly monotone (no off-by-one/collision,
  bytes can't be swapped positions); active-gating sound; a suppressed hi-Send (`has_hi=0` on a consumed
  byte) is caught by the join balance, not a local constraint.

**Remaining for full byte provenance (the critical open item):** the **sponge must Send its rate
limbs** — augment `ShakeSpongeAir` with a `perm` counter and, on `export` rows, a Send of
`(perm·136 + 2·limb_flat, a‴_limb)` for each of the 68 rate limbs on a second bus; `SqueezeByteAir` then
**Receives** `(bytepos, lo + 256·hi)` and matches it, so the byte values are no longer prover-chosen.
Until then `SqueezeByteAir`'s bytes are bound to the true squeeze stream only by construction (the
generator), not by an in-proof lookup. Also: per-instance `bytepos` spaces must be disjoint under
multi-instance composition (the global-offset obligation, §5.1b).

### 5.2a Bounded sampler (`f, g`) — BUILT + reviewed SOUND

`src/sampler.rs::BoundedSamplerAir` (width `BOUNDED_WIDTH = 323`) implements R2 for `f, g`. The
bounded rule reads 8 bytes as `r = u64::from_le_bytes`, accepts iff `r < zone`, emits
`coeff = (r mod span) − 2^20`, `span = 2^21+1`. Unlike ternary this needs **64-bit non-native
arithmetic** (`r`, `zone` exceed the `~2^31` field). What was built:

- **Wide-carry byte limbs (the width win vs. the original plan).** Rather than byte-decomposing each
  partial product `P_i = span·Q_i` into 4 sub-bytes (which would add ~170 columns), the division
  identity `Q·span + R = r` is verified by a **byte carry chain that keeps a wide carry** (`< 2^22`)
  and adds the *whole* `Q_k·span < 2^30` at each byte position: `acc_k = carry_k + Q_k·span (+R at
  k=0) = r_k + 256·carry_{k+1}`, `carry_8 = 0`. Every `acc_k < 2^22 + 2^30 + 2^21 < 2^31 < p` and
  every RHS `< 256 + 2^30 < p`, so **field-equality ⇔ integer-equality** — the whole reason this
  fits Mersenne31. `Q_k` (byte, 8 bits) and the 7 carries (22 bits) are all bit-range-checked, so the
  per-byte identities compose to the exact integer division; `carry_8 = 0` (no top carry-out column)
  bounds `r < 2^64`; unique Euclidean division follows.
- **Canonical remainder is load-bearing** (an under-constraint trap): `Q·span+R=r` alone does *not*
  pin `R` (`R'=R+k·span, Q'=Q−k` also works), so `R` is decomposed as a 21-bit low limb + top bit
  with **`top·R_lo = 0`**, forcing `R ∈ [0, 2^21] = [0, span)` exactly. Without this the emitted
  coefficient is free. (A dedicated test, `bounded_sampler_rejects_noncanonical_remainder`, forges
  `R+span` and confirms the range check rejects it.)
- **Acceptance / no-skip** via a byte-wise borrow subtraction `Z − r`, `Z = zone−1`:
  `accepted = active·(1 − bo_8)` where `bo_8` is the final borrow, proving `accepted ⇔ r ≤ Z ⇔
  r < zone`. This blocks both a fake reject on a valid draw (stream-misalignment / coefficient-skip)
  and a fake accept on a rejected draw. Reject rows are fully constrained (gate is `active·rel`,
  active=1 on rejects); padding rows force `accepted=0` via `active·(1−bo_8)`.
- Same `stream_pos`/`coeff_idx`/`active` counters as ternary, but `stream_pos += 8·active` (8 bytes
  per attempt), `active` non-increasing, last-row `coeff_idx+accepted = num_coeffs`.
- **Range checks by bit decomposition** (transparent/self-contained — no lookup infra), which is why
  the standalone `prove/verify` test needs no LogUp. `r`'s byte range (`r_k < 256`) is the one thing
  *not* locally checked — it is supplied by **join 1** to the sponge (design §5.1), exactly as the
  ternary AIR's byte provenance is. A future width optimization is a shared 8-bit range-check table.

**Independent adversarial under-constraint review (2026-07-10, sonnet) = SOUND** on all three
soundness-critical claims (canonical `R`, division/field-fit incl. the `acc_k < p` bound and the
`carry_8=0` enforcement, acceptance/no-skip incl. per-byte borrow uniqueness) and on counter
ordering. Only unbound properties are the intended join-1 targets (`r_k < 256`; `r_k` = the real XOF
byte at `stream_pos+k`; `stream_pos` indexes the sponge). Max constraint degree 2. Validated: trace
matches `xof_bounded_poly` (256 coeffs), STARK prove/verify, tampered-coeff rejected, non-canonical-R
rejected. 11 lib tests green, clippy `-D`, fmt.

### 5.2 `μ`-independent trace geometry (closing the two soft leaks)

The number of ternary rejections is a function of `SHAKE(μ)` (≈ 2048 ± 34 over 6144 draws, a
`~7.6`-bit range). Two ways this leaks even under a hiding PCS, both closed by fixing geometry:

- **Trace height (leak 4a).** If `SamplerAir`'s height equalled the actual bytes drawn, the height —
  public metadata, not hidden by hiding-FRI — would reveal the rejection count. Fix: pad `SamplerAir`
  to a **fixed height `H`** independent of `μ`, chosen so `Pr[actual draws > H] < 2^-128` (a generous
  margin above the `~90 KB` mean; a completeness caveat, not a soundness one — an honest `μ` whose
  expansion overruns `H` is astronomically rare, and the prover simply cannot prove it, it never
  produces a wrong proof). Rows beyond the real draw are `active = 0` dummies.
- **LogUp multiplicity balance (leak 4b).** The sponge squeezes a **fixed** number of full 136-byte
  blocks (sized to cover `H`), so the sponge side of join 1 is a fixed multiset regardless of `μ`.
  Every squeezed byte is looked up exactly once: real sampler rows consume the prefix, `active = 0`
  dummy rows "consume" the unused suffix. Coefficient production also stops at the **fixed** count
  `(MU+KAPPA+1)·N`. Thus both the byte-side and coefficient-side LogUp totals are `μ`-independent
  constants; the cumulative sums the verifier sees carry no information about the rejection count. The
  `active` flags themselves are witness columns, blinded by the hiding PCS.

---

## 6. Composition, public-input binding, and the API

- **Composition:** one `prove_batch` call over `[ShakeSpongeAir, SamplerAir, LatticeCheckAir]` with
  shared LogUp challenges. `μ` never appears as a public value — it enters only as the last 32 bytes
  of the sponge's first absorbed block (witness) and as the source of `encode(μ)` in R3.
- **Public-input binding to *this* ciphertext:** `pk_digest`, and a Merkle/sponge commitment to
  `(p, v)`, are public values observed into the transcript before any challenge. A proof for
  ciphertext `C` therefore cannot be replayed against `C' ≠ C`: the folded public side (`p(·), v(·)`)
  is bound, so the fold in §4.1 only closes for the `(p,v)` in the public inputs.
- **API (`lib-q-zk-encryption-proof`):**
  ```
  pub struct EncProofStatement { pub pk_digest: [u8;32], pub ct: CiphertextPublic }
  pub struct EncProofWitness   { mu: Zeroizing<[u8;32]> }
  pub fn prove(stmt: &EncProofStatement, wit: &EncProofWitness) -> Result<EncProof, EncProofError>
  pub fn verify(stmt: &EncProofStatement, proof: &EncProof) -> Result<(), EncProofError>
  ```
  The tkem partial-decap gate calls `verify(stmt, proof)?` before `partial_decap_masked`, replacing
  the deployment-contract assumption with a cryptographic check for callers who supply a proof.

---

## 7. Cost, and honest status of each part

| Part | Trace scale | Status |
|------|-------------|--------|
| `ShakeSpongeAir` | ~15.9 K rows × 2633 cols | trace gen + KAT **BUILT/validated** (`src/sponge.rs`); constraint-eval (chaining/padding boundary) still to wire |
| `SamplerAir` (ternary `e`) | ~14 K rows × 14 cols | **BUILT + reviewed SOUND** (`src/sampler.rs::TernarySamplerAir`); prove/verify + tamper tests green |
| `SamplerAir` (bounded `f,g`) | ~N rows × 323 cols | **BUILT + reviewed SOUND** (`src/sampler.rs::BoundedSamplerAir`, §5.2a); prove/verify + tamper + non-canonical-R tests green |
| `LatticeCheckAir` | ~600 K constraints | designed (§4); non-native MAC gadget specified, not yet built |
| LogUp joins | 2 global lookups | mechanism exists (`LogUpGadget`); wiring not yet built |
| `prove_batch` composition | one proof | entry point exists; assembly not yet built |

Estimated prover: dominated by ≈ 662 Keccak permutations + ~600 K MAC constraints → seconds-to-low-
minutes single-threaded, MBs of proof. Verifier: milliseconds. **All RED** — no proof of
zero-knowledge, no soundness proof, no cryptographer sign-off. The ZK property in particular
requires the hiding-FRI / randomized-trace path (`HidingFriPcs`, `zk_config`) so the proof leaks
nothing about `μ`; this design uses it but does not prove it hides.

---

## 8. Reviewer open items

An adversarial review (2026-07-10, independent, RED) confirmed **SOUND**: sufficiency of `R_enc`
(grinding `μ` to steer `f` is infeasible by `~2^-11000` per draw), the field-bridge fold (`1/q` per
`γ`, `2^-144` at 3 vectors, coefficient-wise folding correctly sidesteps the `X^N+1` quotient), and
the non-native overflow bounds (§4.3). It drove the fixes now folded in above: γ rejection-sampling
(§4.1), the `μ`-binding argument (§4.4), the explicit monotone `stream_pos` constraint (§5.1), and
the `μ`-independent geometry (§5.2). Remaining items for a *cryptographer* sign-off:

1. **ZK of `μ`:** confirm the randomized-trace + hiding-PCS configuration actually hides `μ` and all
   `(e,f,g)` witness columns; the sponge's first-block bytes 70..102 are `μ` and must be blinded.
2. **Fold soundness composition:** confirm `2^-144` fold error composes correctly with STARK
   soundness and LogUp soundness (no challenge reuse between the fold `γ` and the LogUp `α,β`).
3. **Position-tag lookup:** confirm the ordered lookup — LogUp `(stream_pos, byte)` **plus** the
   explicit `SamplerAir` monotone `stream_pos` transition constraint (§5.1) — prevents a malicious
   prover from reordering the stream around a rejection. (The lookup alone does not; the constraint is
   load-bearing.)
4. **Rejection-count leakage:** confirm the fixed-height `H` and the `μ`-independent LogUp balance
   (§5.2) fully hide the rejection count under the hiding PCS, and that `H` is chosen with
   `Pr[draws > H] < 2^-128`.
5. **Provable vs conjectured soundness:** state the *provable* STARK bound in any paper claim, not
   the conjectured 128 (per the Arm-B soundness memo).
6. **Non-native reduction completeness:** confirm the quotient/remainder range bounds in §4.3 are
   tight (no accepted out-of-range reduction) and that the accumulator never overflows 7 limbs.
