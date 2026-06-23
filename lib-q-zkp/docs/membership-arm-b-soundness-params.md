# Arm B membership-STARK soundness parameters — 128-bit post-quantum

**Status:** the Arm B config is tuned to **128-bit post-quantum** soundness and the bits are computed +
reproducible (`python lib-q-zkp/tools/fri_soundness.py`). Tier RED — this is a *parameter
characterization* of the PCS/commitment layer, not a soundness proof of the AIR. It does **not**
discharge the cryptographer obligations (AIR completeness, Poseidon2 algebraic security).

> **Headline:** the default config delivers **≈128-bit post-quantum** soundness (and ≈128-bit
> classical, both conjectured and provable-Johnson), binding on the SHAKE256 Merkle commitment
> (256-bit → 128-bit collision, NIST Category 2). Every other term sits comfortably above 128.

## History (why the params changed)

The original config (degree-4 challenge field, `log_blowup 3`, `q=100`, `PoW 16`) delivered only
**≈116-bit conjectured / ≈99-bit provable** — bound by the **124-bit** degree-4 challenge field and
the FRI query phase. The "128-bit" elsewhere in the Arm B docs was only the *Poseidon2 primitive*
(round-count) target; it did not lift the proof-system soundness. This was fixed by enlarging the
challenge field to a **quintic** extension and retuning FRI.

## The 128-bit-PQ config (mirror of `stark_baby_bear.rs`)

| param | value | was |
|-------|-------|-----|
| challenge field | `BinomialExtensionField<BabyBear, 5>` = `F_{p^5}` (≈155 bits) | deg-4 (≈124b) |
| `log_blowup` | **4** (FRI rate ρ = 1/16) | 3 |
| `num_queries` | **96** | 100 |
| `proof_of_work_bits` | **20** | 16 |
| Merkle commitment | SHAKE256 (256-bit) | unchanged |
| max AIR constraint degree | 7 (x⁷ S-box, degree-7 optimized) | unchanged |

The quintic field `F_{p^5} = F_p[x]/(x^5 - 2)` is built in `lib-q-stark-baby-bear`
(`BinomialExtensionData<5>`); `x^5 - 2` is irreducible (2 is a non-5th-power, `5 | p-1`). Its
constants (`W=2`, `DTH_ROOT`, a multiplicative generator of order `p^5-1`, `EXT_TWO_ADICITY=27`) were
derived **and verified** by `lib-q-stark-baby-bear/tools/gen_quintic_constants.py` under SageMath, and
re-validated in Rust by the `test_extension_field!` harness.

## Computed bits (`tools/fri_soundness.py`)

| term | classical | post-quantum (mainstream model) |
|------|----------:|--------------------------------:|
| challenge field \|F_{p⁵}\| | 154.5 | — |
| constraint/DEEP Schwartz–Zippel | 146.7 | 146.7 (FS preserved in QROM) |
| FRI query+PoW — unique-decoding (provable) | 108 | — |
| FRI query+PoW — Johnson (provable) | 212 | — |
| FRI query+PoW — capacity (conjectured) | 404 | 394 (grinding Grover-halved) |
| SHAKE256 Merkle collision | 128 | 128 (NIST Cat-2) |
| sponge capacity (9 cells) collision | 139 | 139 |
| **OVERALL** | **128 (conj & Johnson)** | **128 (binding: SHAKE256)** |

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
