# HQC code/decoder optimizations — radar and rationale

Status: **radar / not adopted.** This note tracks published proposals to change HQC's
error-correcting code or decoder for smaller keys/ciphertexts, and records why
`lib-q-hqc` does **not** implement them. It is a literature note, not a finding against
the crate: the constructions below are optimizations of a future/alternative HQC, not
attacks on the one this crate ships.

`lib-q-hqc` deliberately targets the **NIST HQC specification (2025-08-22)** — the
single-level concatenation of an inner duplicated first-order Reed–Muller code with an
outer Reed–Solomon code, with the fixed wire sizes recorded in
[`SECURITY.md`](../SECURITY.md) and [`../lib-q-types/src/hqc.rs`](../../lib-q-types/src/hqc.rs).
Any change to the code or decoder that alters `n`, the public-key size, or the ciphertext
size is a **breaking, non-interoperable, non-standard wire-format change** and is out of
scope until NIST standardizes it.

## ePrint 2026/656 — "Improved Codes and Decoders for HQC"

- **Authors:** Sebastian Bitzer, Bharath Purtipli, Antonia Wachter-Zeh (TU Munich).
- **Source:** <https://eprint.iacr.org/2026/656>; authors' reproducibility scripts at
  <https://gitlab.com/bharath.purtipli/hqc_gcc>.
- **Class:** code/decoder redesign for smaller sizes. **Not** an attack; does **not**
  falsify any correctness or security claim of the shipped construction.

All figures below were read from the paper PDF and cross-checked against this crate's
parameters; see "Verification" at the end for what was run versus inferred.

### What it proposes

1. **Two-level generalized concatenated code (GCC).** The paper observes that HQC's inner
   duplicated first-order RM code *contains the repetition code as a subcode*, forming a
   partition chain (paper §3, Example 1). This admits a second concatenation level whose
   inner code is the repetition code (minimum distance `n_in`, twice the RM code's), paired
   with an outer binary BCH code. Because the repetition layer has a far smaller inner
   failure probability, its outer code can run at a higher rate; the extra information bits
   let the overall code be shortened while keeping message length `λ` and the `≤ 2^-λ` DFR
   target. For `s = 1` the construction reduces to the single-level concatenation currently
   deployed (paper §3.1, Example 2).
2. **Reliability-based errors-and-erasures outer decoding.** The inner (RM) ML decoder
   yields a reliability measure per outer symbol; low-reliability symbols are declared
   erasures. Since a BMD errors-and-erasures decoder corrects `e` errors and `s` erasures
   whenever `2e + s < d`, this roughly doubles the correction value of a suspected error.
   Two erasure-assignment strategies are analyzed with rigorous (analytical, not
   simulation-extrapolated) DFR upper bounds: **threshold-based** (erase every symbol below
   a fixed reliability threshold `T`) and **partition-based** (erase a fixed count `ε` of
   the least-reliable symbols).

### Quantified gains (paper Table 2 / Example 3, verified)

The paper's **baseline row is exactly the construction this crate ships.** For NIST
category 1 it is an outer RS `[46, 16, 31]` over GF(256) with an inner duplicated RM
`[384, 8, 192]`, ambient length `n = 17669`, hard-decision decoding, DFR `2^-132.9`. That
matches `src/params.rs` for HQC-128 (`N = 17669`, `N1 = 46`, `N2 = 384`, `K = 16`,
`DELTA = 15`).

| NIST | Shipped baseline `n` | Proposed `n` | Reduction |
|------|----------------------|--------------|-----------|
| 1    | 17669                | 16901        | **4.34 %** |
| 3    | 35851                | 34589        | ~3.5 %    |
| 5    | 57637                | 55541        | ~3.6 %    |

For NIST-1 the outer RS length drops `46 → 44` (`n_out`). A single-level RS at that
length would carry only `k_RS · 8 = 15 · 8 = 120` information bits — below `λ = 128`. The
2-level GCC instead splits the inner code's `8`-bit symbols into `7` RS bits + the
repetition bit: level 1 (RS) contributes `15 · 7 = 105` bits and level 2 (a shortened
BCH `[·,25,8]`) contributes `k_C = 25`, totalling `105 + 25 = 130 ≥ 128`. The public key
is `n` bits and the ciphertext is about `n + n_out·n_in` bits, so both shrink by the same
~4.34 %.

### Why `lib-q-hqc` does not adopt it

- **Wire-format break, no interop.** Changing `n`/`n_out` changes the public-key and
  ciphertext byte lengths and the whole KEM transcript (the public key is absorbed into
  `hash_h` during encapsulation). A peer on standard HQC would not interoperate. The crate
  targets the NIST standard precisely so it *does* interoperate.
- **Not standardized.** The proposal is a research construction; NIST's HQC (the Aug-2025
  spec the paper itself cites as reference [1]) fixes the single-level RM-RS concatenation.
  Adopting the GCC/erasure decoder would take the crate off the standard with no
  conformance target to test against.
- **New side-channel surface (author-acknowledged).** The **threshold-based** scheme
  produces a *data-dependent* number of erasures; the paper explicitly warns this count
  depends on the secret key and "may leak information about it," citing the existing line
  of HQC decoder side-channel attacks (paper §4.2, "Practical considerations"). The
  **partition-based** scheme fixes the erasure count `ε` specifically to remove that
  variability. Any future adoption would have to treat erasure assignment as a
  constant-time concern — directly relevant to this crate's side-channel posture
  ([`SECURITY.md`](../SECURITY.md), [`docs/sca-self-certification.md`](../../docs/sca-self-certification.md)).

The correctness and DFR of the shipped construction are unchanged by this paper: its
analysis re-derives the same `2^-132.9` (Model 1) / `2^-145.1` (Model 2) DFR for the
current NIST-1 code, i.e. it corroborates the shipped construction's decryption-failure
margin rather than contradicting it.

### Related proposals mentioned (radar only, not adopted)

- **HARE** (paper ref [10]) — separate HQC adaptation: ciphertext compression, unbalanced
  encryption weights, and a threshold errors-and-erasures RS decoder (the same reliability
  measure as §4.2 here). Also a non-standard wire change.
- **GMD decoding of HQC's RS code** (ref [11]) — the paper notes its DFR bounds rely on
  simulation extrapolation, "which may not yield valid guarantees for DFRs of `2^-λ`."
- **Correlated error models / ciphertext compression** (refs [14–16], "Model 2") —
  alternative error-weight models and orthogonal size reductions; the paper treats them as
  compatible future work.

### What would change this decision

Revisit only if NIST publishes a revised HQC standard adopting a GCC and/or reliability-
based decoder, at which point this crate would follow the standard (new parameters, new
wire sizes, new KATs) rather than this paper directly.

## Verification

- **Ran:** downloaded ePrint 2026/656 PDF and read it in full; extracted Table 2 and
  Example 3 figures. Confirmed the paper's NIST-1 baseline (RS `[46,16,31]`, RM `[384,8,192]`,
  `n = 17669`, DFR `2^-132.9`) equals this crate's HQC-128 parameters by reading
  `src/params.rs`. Confirmed the target spec claim against [`SECURITY.md`](../SECURITY.md)
  ("targets the NIST HQC specification (2025-08-22)"), which the paper cites as its
  reference [1].
- **Inferred (labelled):** the NIST-3/NIST-5 percentage reductions in the table above are
  computed from the paper's `n` values (`1 − 34589/35851 ≈ 3.5 %`, `1 − 55541/57637 ≈ 3.6 %`);
  the paper headlines only the NIST-1 "up to 4.34 %" figure.
- **Not attempted:** re-deriving the paper's DFR bounds or running the authors' scripts —
  out of scope for a radar note, and irrelevant to a construction the crate does not ship.
