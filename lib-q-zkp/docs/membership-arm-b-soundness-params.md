# Arm B membership-STARK soundness parameters — 128-bit post-quantum

**Status:** the Arm B config is tuned to **128-bit post-quantum** soundness and the bits are computed +
reproducible (`python lib-q-zkp/tools/fri_soundness.py`). Tier RED — this is a *parameter
characterization* of the PCS/commitment layer, not a soundness proof of the AIR. It does **not**
discharge the cryptographer obligations (AIR completeness, Poseidon2 algebraic security).

> **Headline:** the default config delivers **≈128-bit post-quantum** soundness (and ≈128-bit
> classical, both conjectured and proven per BCIKS20 Thm 8.3), binding on the SHAKE256 Merkle commitment
> (256-bit → 128-bit collision, NIST Category 2). Every other term sits comfortably above 128.

## History (why the params changed)

The original config (degree-4 challenge field, `log_blowup 3`, `q=100`, `PoW 16`) delivered only
**≈116-bit conjectured / ≈99-bit provable** — bound by the **124-bit** degree-4 challenge field and
the FRI query phase. The "128-bit" elsewhere in the Arm B docs was only the *Poseidon2 primitive*
(round-count) target; it did not lift the proof-system soundness. This was fixed by enlarging the
challenge field and retuning FRI. The first fix was a quintic (`GF(q^5)`, ≈155 bits); that cleared the
conjectured bound but left the BCIKS proximity-gap field term of the PROVEN (Johnson) bound near
≈119 bits, so Arm B now uses an **octic** extension (`GF(q^8)`, ≈247 bits).

## The 128-bit-PQ config (mirror of `stark_baby_bear.rs`)

| param | value | was |
|-------|-------|-----|
| challenge field | `BinomialExtensionField<BabyBear, 8>` = `F_{p^8}` (≈247 bits) | deg-5 (≈155b); originally deg-4 (≈124b) |
| `log_blowup` | **4** (FRI rate ρ = 1/16) | 3 |
| `num_queries` | **96** | 100 |
| `proof_of_work_bits` | **20** | 16 |
| Merkle commitment | SHAKE256 (256-bit) | unchanged |
| max AIR constraint degree | 7 (x⁷ S-box, degree-7 optimized) | unchanged |

The octic field `F_{p^8} = F_p[x^8 - 11]` is built in `lib-q-stark-baby-bear`
(`BinomialExtensionData<8>`; `W = 11`, the same non-residue as the degree-4 field). Its constants
(`DTH_ROOT = 11^((p-1)/8)`, a generator of order `p^8-1`, `EXT_TWO_ADICITY = 30` and the three
extension two-adic generators) are derived and **self-certified in pure Python** by
`lib-q-stark-baby-bear/tools/gen_octic_constants.py` (an element of full order `p^8-1` in the ring
proves it is a field; `p^8-1` was fully factored with coreutils `factor`) and re-validated in Rust by
the `test_extension_field!` / `test_two_adic_extension_field!` harnesses. The superseded quintic
generator script `gen_quintic_constants.py` is kept for reference.

## Computed bits (`tools/fri_soundness.py`)

| term | classical | post-quantum (mainstream model) |
|------|----------:|--------------------------------:|
| challenge field \|F_{p⁸}\| | 247.3 | — |
| constraint/DEEP Schwartz–Zippel (at the verifier's max domain) | 217.4 | 217.4 (FS preserved in QROM) |
| BCGM Lemma 9.3 `eps_MCA`, alpha batching `d = l − 1` (proven; zk) | 164.5 (164.4) | — |
| BCIKS20 Lemma 8.2 `eps_C` (proven; zk) | 175.6 (175.6) | — |
| BCIKS20 Thm 8.3 query term, `m = 3` (proven) | 190.7 | 180.7 (grinding Grover-halved) |
| `eps_FRI = eps_MCA + eps_C +` query term (proven; zk) | 164.5 (164.4) | — |
| FRI query+PoW — unique-decoding (provable) | 108 | — |
| FRI query+PoW — Johnson, `m → ∞` limit (not a strict bound) | 212 | — |
| FRI query+PoW — capacity (conjectured) | 404 | 394 (grinding Grover-halved) |
| SHAKE256 Merkle collision | 128 | 128 (NIST Cat-2) |
| sponge capacity (9 cells) collision | 139 | 139 |
| **OVERALL** | **128 (conj & proven)** | **128 (binding: SHAKE256)** |

Note on the proven rows: every term is a cited theorem, with one `m = 3` throughout:
`eps_FRI = eps_MCA + eps_C + (sqrt(ρ)(1 + 1/(2m)))^s`.
- **Batching, `eps_MCA`.** libQ's PCS folds all `l` opened (column, point) quotients into one word
  with powers of ONE alpha: the univariate powers generator `(1, x, …, x^d)`, `d = l − 1`. It is
  priced by Bordage–Chiesa–Guan–Manzur, "All Polynomial Generators Preserve Distance with Mutual
  Correlated Agreement" (ePrint 2025/2051, version of May 19, 2026), Lemma 9.3 / Def 9.1, MCA for
  Reed–Solomon codes up to `1 − (1 + 1/2m)√ρ`: `(m+½)^7 d |D|^2 / (3ρ^{3/2}|F|)`. For Arm B,
  `l = 3386` (zk `3534`), measured from real proofs by `tests/soundness_gate_shape_tests.rs`, which
  also checks that every committed matrix has the same LDE height (no `β²` roll-in).
- **FRI on the batched word, `eps_C` and the query term.** BCIKS20 (ePrint 2020/654, version of
  July 3, 2021) Thm 8.3 applied to that one word, `eps_C` from Lemma 8.2 eq (8.5):
  `(m+½)^7 |D|^2 / (2ρ^{3/2}|F|) + (2m+1)(|D|+1) Σ l^(i) / (sqrt(ρ)|F|)`, `l^(i) = 2` per fold.
  The two combine by a union bound over alpha: unless the opened quotients have correlated
  agreement of density `(1 + 1/2m)√ρ`, the batched word reaches that agreement with probability at
  most `eps_MCA` (BCGM Def 3.14), and below it Thm 8.3 applies.
- **Domain.** `|D|` is the largest LDE domain the verifier accepts. `verify_membership_bb` does
  **not** bind the trace height to a depth: a 128-row proof (2 × `MAX_DEPTH`) verifies (same test
  file). So only the FRI verifier's two-adicity check bounds it, giving `|D| ≤ 2^27`.
- **Not used: Manzur, ePrint 2026/2617** (MCA of the powers generator for any linear code). Its
  radius is the generalized Johnson radius `J_{d+2}(δ) = 1 − (1 − δ)^{1/(d+2)}`, which at
  `d = 3385`, `δ = 1 − ρ` is `8.2·10^-4`; 96 queries at that distance give about 0.1 bit. The
  RS-specific BCGM theorem is the one that applies.

The previous round of this change multiplied Lemma 8.2's first term by `l` and added `l` to
`Σ l^(i)` (163.9 bits here; our own composition of BCIKS20's curve theorems with Lemma 8.2, with no
theorem stating it). The cited form above is 0.585 bits tighter.
An earlier version used the Thm 5.1 eq (5.3) line form `(m+½)^7 n^2 / (3ρ^{3/2}|F|)` at
`n = 32 · 16` without `l`, and cited it as "Thm 1.5". That gave 212.2 bits here and ≈119 for
`GF(q^5)`. Under the form above, `GF(q^5)` gives 71.7 and is still rejected. The CI gate is
`tests/security_parameter_tests.rs` (formulas in `tests/soundness_gate/mod.rs`).

### Post-quantum model

The "mainstream / deployed" QROM model — used by Plonky3, ethSTARK, SP1, Risc0:
- The Fiat–Shamir compilation of a **round-by-round-sound** IOP preserves its soundness in the QROM up
  to small polynomial factors, so the IOP terms (challenge field / DEEP / FRI query) keep ≈their
  classical bits — **not** a Grover square-root loss on soundness.
- Grover gives a quadratic speedup on the **grinding** proof-of-work only (`20 → 10` bits quantum;
  a minor additive term on the already-404-bit query phase).
- The Merkle binding rests on **collision resistance**: SHAKE256/256 → 128-bit classical, rated NIST
  **Category 2** (≈128-bit PQ; the BHT quantum-collision speedup needs exponential QRAM and is not
  counted). This is the binding 128-bit term.

A *maximally-conservative* model (Grover-halve even the IOP soundness, count BHT hash collisions)
would instead need a degree-8+ field and 384-bit Merkle digests; that was considered and rejected as
over-conservative versus NIST's SHAKE256 categorization (the chosen model is the deployed one).

## Cost of the upgrade

Negligible. Re-measured proof sizes are within ~0.5% of the old (leaky) config — **transparent
≈0.95–1.04 MB, ZK ≈1.13–1.21 MB** — because proof size is dominated by `num_queries × trace_width`
(queries dropped 100→96, offsetting blowup 3→4; the deg-5 field touches only the small challenge-MMCS
openings). Verify ≈26–33 ms. See `membership-arm-b-measurement.md`.

## Caveats

- Term [2] (DEEP Schwartz–Zippel) is an approximation of the combined ALI/DEEP-OOD soundness; within
  ~1 bit of the |F|/(deg·domain) variant. Either way ≥ ~144, well above the 128 binder.
- These are **PCS-layer** bits. They assume the AIR is sound + complete and that Poseidon2's algebraic
  security holds at its round counts — both still **RED**, pending the human cryptographer.
