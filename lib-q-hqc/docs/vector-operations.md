# HQC PKE vector operations

Documentation for the production **u64 polynomial vectors** used in the HQC PKE layer. All symbols below live in [`src/hqc_pke.rs`](../src/hqc_pke.rs) on `HqcPke<P: HqcParams>` unless noted.

This is not a catalog of every `vect_*` name in the crate. Byte-oriented helpers in [`src/internal/vector.rs`](../src/internal/vector.rs) (`vect_add`, `vect_fixed_weight`, …) are separate utilities and are **not** on the KEM/PKE hot path.

For AVX2 multiply and runtime dispatch, see [SIMD architecture](simd-architecture.md). For assurance and KAT strategy, see [SECURITY.md](../SECURITY.md).

## Scope and representation

| Concept | Type / location | Notes |
|--------|-----------------|-------|
| Ring element | `&mut [u64]` length `P::VEC_N_SIZE_64` | Coefficients in \(\mathrm{GF}(2)[x]/(x^N-1)\); little-endian u64 limbs |
| Dense random `h` | `vect_set_random` | Fills `P::VEC_N_SIZE_BYTES` via XOF, then masks the high bits of the last limb |
| Sparse secret `x`, `y` | `vect_sample_fixed_weight1` | Weight `P::OMEGA` (keygen / decryption key) |
| Encryption noise | `vect_sample_fixed_weight2` | Weights `P::OMEGA_R` (`r1`, `r2`) and `P::OMEGA_E` (`e`) |
| Multiply | `vect_mul` | \(\mathrm{GF}(2)[x]/(x^N-1)\); AVX2 Toom when available, else schoolbook |
| Add / truncate | `vect_add`, `vect_truncate` | XOR; truncate to `P::N1N2` bits for concatenated-code payloads |

Parameters are defined per security level in [`src/params_correct.rs`](../src/params_correct.rs) (`Hqc1Params`, `Hqc3Params`, `Hqc5Params`).

## PKE call graph

```text
keygen (seed_dk XOF)
  ├─ vect_sample_fixed_weight1 → y, x     (weight OMEGA)
  └─ vect_set_random (seed_ek XOF) → h
       └─ vect_mul(y, h); vect_add → s

encrypt (theta XOF)
  ├─ vect_sample_fixed_weight2 → r2, e, r1
  ├─ vect_mul / vect_add → u
  ├─ vect_mul / vect_add → tmp; vect_truncate(tmp)
  └─ concatenated encode → v

decrypt
  └─ same multiply/add/truncate pattern on recovered polynomials
```

## XOF byte consumption (`xof_get_bytes`)

Support sampling and `vect_set_random` must advance the SHAKE-256 XOF state exactly like the reference `xof_get_bytes`. The crate centralizes that in `HqcPke::xof_get_bytes`:

- If `output.len()` is a multiple of 8: one `squeeze` of the full buffer.
- Otherwise: squeeze the aligned prefix, squeeze 8 bytes into a temporary buffer, copy only `len % 8` bytes into the tail.

`vect_generate_random_support1` refills its 3·weight byte buffer through `xof_get_bytes`, not a bare `squeeze` of arbitrary length. KAT and intermediate-value tests depend on this.

## Operations

### `vect_write_support_to_vector`

Writes `weight` bit positions from `support[]` into `v[]` using precomputed `index_tab` (word index `pos >> 6`) and `bit_tab` (`1 << (pos & 0x3f)`). Each output word ORs masked contributions from every support entry (`*val |= temp_val`); assignment would be wrong when multiple bits share a limb.

**Timing:** Inner word selection uses the reference constant-time equality idiom (`tmp == 0` via masks). Support values are XOF-derived secrets in the PKE threat model.

### `vect_sample_fixed_weight1` / `vect_generate_random_support1`

**Purpose:** Sample a sparse vector with Hamming weight `weight` for decryption-key polynomials (`x`, `y`).

1. Zero the output buffer.
2. `vect_generate_random_support1`: rejection sampling on 24-bit candidates, then Barrett reduction mod `P::N`, then duplicate rejection.
3. `vect_write_support_to_vector`.

**Rejection threshold:** Accept when `candidate < P::UTILS_REJECTION_THRESHOLD`, where

\[
\texttt{UTILS\_REJECTION\_THRESHOLD} = \lfloor 2^{24} / N \rfloor \cdot N
\]

(not \(2^{24}-1\)). See parameter table below.

**Timing:** Rejection loops and `if support[k] == support[i]` duplicate checks follow the reference and are **not** constant-time; runtime varies with XOF draws and collision count.

### `vect_sample_fixed_weight2` / `vect_generate_random_support2`

**Purpose:** Sample sparse encryption noise (`r1`, `r2`, `e`) without the per-draw rejection loop of method 1.

1. `xof_get_bytes` → `weight` little-endian `u32` values.
2. Map index `i` with `support[i] = i + (rand * (N - i)) >> 32` (64-bit intermediate).
3. Reverse pass resolves collisions with masked updates (reference `vect_generate_random_support2`).

**Timing:** Reference-style masked fixes; still not a uniform-cycle guarantee in the BearSSL sense.

### `barrett_reduce`

Reduces `x` mod `P::N` using precomputed `P::N_MU = \lfloor 2^{32} / N \rfloor`. Final correction uses bit masks (no branch on `r >= N`).

**Timing:** Fixed operation count; suitable for auditing as constant-time at the C/Rust statement level.

### `vect_set_random`

Expands a dense polynomial from the encryption-key XOF:

- Consumes **`P::VEC_N_SIZE_BYTES`** (not `VEC_N_SIZE_64 * 8`); for HQC-128 that is 2209 bytes vs 2216.
- Uses the same aligned / partial-tail `xof_get_bytes` pattern as above.
- Masks the last u64 when `P::N % 64 != 0`.

Used for public polynomial `h` in keygen and when parsing `seed_ek` from a public key.

### `vect_mul`

Product in \(\mathrm{GF}(2)[x]/(x^N-1)\).

| Path | When | Implementation |
|------|------|----------------|
| AVX2 | `feature = "simd-avx2"`, x86_64, runtime `has_avx2()` | [`src/simd/avx2/gf2x.rs`](../src/simd/avx2/gf2x.rs) Toom-based `avx2_vect_mul_mod_xnm1` |
| Portable | otherwise | `schoolbook_vect_mul_mod_xnm1` in `hqc_pke.rs` |

Both paths must agree; see `tests/vect_mul_equivalence.rs` and SIMD tests in [simd-architecture.md](simd-architecture.md).

The schoolbook kernel scans set bits of `a` with `if (ai >> bit) & 1 == 1` (reference-style). That is **data-dependent** in cycle count. AVX2 is optimized for throughput, not documented as constant-time.

`vect_mul` returns `InvalidKey` if `output.len() != P::VEC_N_SIZE_64`.

### `vect_add`

Element-wise XOR over the first `len` limbs. With `simd-avx2` and AVX2 at runtime, delegates to `Avx2::vect_add` on the byte view of the limb slice; otherwise a simple XOR loop with length guards.

### `vect_truncate`

Zeroes and masks limbs so only the low `P::N1N2` bits of a vector remain (concatenated-code width). Used after multiply/add before encoding into the RS/RM payload.

## Parameters (vector-related)

| Parameter | HQC-128 (`Hqc1Params`) | HQC-192 (`Hqc3Params`) | HQC-256 (`Hqc5Params`) |
|-----------|------------------------|------------------------|------------------------|
| `N` | 17669 | 35851 | 57637 |
| `OMEGA` (dk sparse weight) | 66 | 103 | 134 |
| `OMEGA_E` (`e` weight) | 75 | 114 | 149 |
| `OMEGA_R` (`r1`, `r2` weight) | 75 | 115 | 149 |
| `VEC_N_SIZE_64` | 277 | 561 | 901 |
| `VEC_N_SIZE_BYTES` | 2209 | 4482 | 7205 |
| `N1N2` (truncate width, bits) | 17664 | 35840 | 57600 |
| `UTILS_REJECTION_THRESHOLD` | 16767881 | 16742417 | 16772367 |
| `N_MU` | 243079 | 119800 | 74517 |

Bit indexing within a limb: `word = position >> 6`, `bit = position & 0x3f`, `mask = 1u64 << bit`.

Official names in the HQC submission map to `HqcParams` in Rust (`N`, `OMEGA`, …).

## Side-channel and timing posture

Do not describe this module as uniformly constant-time. Use the following classification when reviewing or hardening:

| Component | Posture | Notes |
|-----------|---------|-------|
| `vect_write_support_to_vector` | Reference-style CT word select | Masks for `tmp == 0` |
| `barrett_reduce` | Fixed-latency reduction step | |
| `vect_generate_random_support1` | Variable time | Rejection + branched duplicate check |
| `vect_generate_random_support2` | Variable time | Collision resolution passes |
| `schoolbook_vect_mul_mod_xnm1` | Variable time | Per-set-bit updates |
| AVX2 `vect_mul` | Fast path | Equivalence-tested vs schoolbook, not CT-audited |
| `vect_add` / `vect_truncate` | Public-length operations | Operand values may still be secret |

HQC reference code uses the same patterns for interoperability and KAT alignment. Any hardening fork must re-run KATs and cross-implementation tests.

## Verification map

| Concern | Tests / artifacts |
|---------|-------------------|
| Support write, Barrett, basic multiply | `tests/comprehensive_validation.rs` |
| Schoolbook vs AVX2 multiply | `tests/vect_mul_equivalence.rs`, `src/simd/avx2/gf2x.rs` unit tests |
| `vect_set_random` / XOF alignment | `tests/vect_set_random_analysis.rs`, `tests/kat_intermediate_values_verification.rs` |
| Parameter constants | `tests/compliance_parameter_validation.rs`, `tests/official_specification_verification_test.rs` |
| Full KEM | `tests/kat_test.rs`, `tests/compliance/kat_verification.rs` |
| Cross-parameter behavior | `tests/compliance/cross_implementation.rs` |

Public test hooks on `HqcPke` (`test_vect_mul`, `test_vect_sample_fixed_weight1`, …) exist for component debugging; prefer the integration tests above for regression gates.

## Maintenance checklist

When changing vector code:

1. Preserve `xof_get_bytes` semantics for any path that feeds KATs or reference intermediate values.
2. Keep `|=` accumulation in `vect_write_support_to_vector`.
3. Run multiply equivalence (portable vs AVX2) for all three parameter sets.
4. Re-run KAT or intermediate-value suites if sampling or `vect_set_random` changes.
5. Update this document and [simd-architecture.md](simd-architecture.md) if dispatch or limb layout changes.
6. Record timing-posture changes in [SECURITY.md](../SECURITY.md); do not claim uniform constant-time without evidence.

## References

- [HQC specification](https://pqc-hqc.org/)
- NIST PQC project: [post-quantum cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- Reference C implementation (submission sources for `vector.c`, `gf2x`, `parameters.h`)
- [BearSSL constant-time programming](https://www.bearssl.org/constanttime.html) (background on CT idioms used in support write / Barrett)
