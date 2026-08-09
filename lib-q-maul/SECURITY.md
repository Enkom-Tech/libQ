# lib-q-maul — security status: **RED**

**No human cryptographer has reviewed this instantiation. Do not use it for anything.**

`publish = false` in `Cargo.toml`: this crate builds and tests in-tree and does **not** reach
crates.io. That is the mechanical expression of the gate on card `t_5bc0f630`, which requires a
human cryptographer sign-off *before* the crate is wired into any consumer, and which exists
because this repository has just spent a workstream retracting two pre-standard primitives that
did not survive scrutiny (`lib-q-threshold-sig`, unsound; `lib-q-double-kem`, deviated from its
paper).

Status of the underlying construction, separately from this implementation: Maul and the CK-FO
transform are from a peer-reviewed-style ePrint with standard-model and QROM proofs
(ePrint 2025/1755). **The paper is not the thing that is RED.** The RED status is about *this
code* and about the specific instantiation choices listed below, which the paper leaves open.

---

## What was checked, and how

| Claim | Evidence |
|---|---|
| Algorithms match the paper | Each module quotes the figure it implements verbatim: `pke` = Fig. 8, `kem` = Fig. 6, `params` = Tables 5 & 6. Paper at `reference/DAKE/`. |
| Ciphertext size is the paper's | `tests/pq_parameters.rs::sizes_are_pinned_against_table_5_and_against_ml_kem` — 896 / 1440 / 1856, derived from `(k, n, du, dv)`, matching Table 5 exactly. |
| **Both legs contribute secrecy** | `tests/both_legs_contribute.rs` — a full adversary holding `sk_L` + both public keys + every wire byte fails on 4100+ derivations; a deliberately-broken control reproducing the withdrawn crate's defect is broken by that same adversary. |
| **>= 128-bit post-quantum** | `tests/pq_parameters.rs` — Maul768 quantum core-SVP 156 bits (148 on the paper's own lower bound). Basis recorded in that file's module docs. |
| Constant-time secret comparison | `subtle::ConstantTimeEq` on the re-encryption check and on `SharedSecret`; structural exhaustive-position tests, no wall-clock timing. |
| Domain separation | Every hash input length-prefixed, every oracle domain-separated, parameter set bound in. `src/hash.rs` tests. |
| Arithmetic correctness | Exhaustive tests over the full reachable input range for `compress`, `div_2q`, `center`; worst-case accumulator bound proven against the `reduce` precondition. |

---

## Open items a cryptographer must sign off — the actual RED list

### 1. The `D_64` instantiation is a choice this crate made, not one the paper made

Table 5 says `D_64`; §5.3 defines `D_sigma` only as "a Gaussian-like distribution of standard
deviation sigma, encompassing centered binomials, sums of uniforms, and discrete Gaussians". This
crate picks **a sum of 6 differences of 6-bit uniforms**, variance exactly 4095 (`sigma = 63.9922`),
chosen because it needs no rejection sampling and so is constant-time by construction.

That is inside the paper's stated family and matches the variance. But the Hint-MLWE analysis of
§5.4/§5.5 leans on Heuristic 1 ("we assume similar hardness for non-Gaussian distributions of
equal variance"), and §5.5 explicitly warns that Maul's distributions fall **below** the smoothing
parameter where Theorem 4's reduction is tight, so "some degree of security degradation may be
expected". **Whether *this particular* non-Gaussian shape is as good as the one the authors
estimated is not established here.** A reviewer should either accept the equal-variance heuristic
for this shape or specify a different `D`.

### 2. The security figures are re-derived, not re-measured

Every bit-count in `params.rs` and `tests/pq_parameters.rs` is `0.265 * beta` / `0.292 * beta`
applied to the paper's own Table 6 blocksizes. **This crate did not run the leaky-LWE estimator.**
Reproducing Table 6 independently (against `https://github.com/tlegavre/dake_estimator` and
`https://github.com/lducas/leaky-LWE-Estimator`) is an open item. libQ has a working SageMath +
lattice-estimator setup in WSL that has been used for this class of check before.

### 3. No third-party test vectors exist

`tests/vectors/maul_kat.txt` is self-generated and says so in its own header and in
`kats-manifest.toml`. There is no reference implementation of Maul to check against. The vectors
are a wire-format regression pin and **no evidence of interoperability or of correctness against
the designers' intent**.

### 4. Delta (decapsulation failure) is not independently verified

Table 5 claims `2^-196` at Maul768. This crate reproduces the parameters that claim implies but
does not re-derive the failure probability from Lemma 1 with its own `D`. Since the chosen `D` has
variance 4095 rather than exactly 4096, `delta` moves — almost certainly in the safe direction,
but "almost certainly" is not a computation.

### 5. Side channels beyond the ones structurally excluded

The arithmetic is branch-free and division-free on secrets, and there is no secret-dependent
memory index. That is a structural argument, not a measurement. No `lib-q-sca-test` harness, no
`dudect`, no leakage assessment has been run against this crate.

### 6. `MAUL512` does not meet a literal 128-bit post-quantum bar

93 bits quantum core-SVP (89 on the paper's lower bound). It is NIST category 1 in the paper's
framing — the same position ML-KEM-512 occupies at ~107 bits — but a caller who has been told
"128-bit PQ" must not be handed it. `ParamSet::meets_128_bit_quantum_core_svp()` returns `false`
for it and `tests/pq_parameters.rs` asserts that.

### 7. Performance is deliberately bad

Schoolbook ring arithmetic, no NTT, ~15 polynomial products per encapsulation. Optimise **after**
sign-off; an NTT rewrite before review would replace reviewable code with unreviewed code.

---

## Where this does and does not fit

Two findings recorded on card `t_5bc0f630` that any consumer must read before wiring this in:

* **A double-KEM is an AKE shape, not an onion-hop shape.** `Decaps` needs `sk_L` **and** `sk_R`
  together. If two consecutive relay hops' keys were "Maul'd" together, neither hop could
  decapsulate alone — the secrets live on different nodes. And if one node held both, it is one
  hop and there is no saving over an ordinary KEM. The original "PQ-Sphinx MTU relief" motivation
  was a category error independent of any implementation defect.
* **Maul is bigger than a single ML-KEM.** 1440 B against 1088 B at NIST level 3: **+32.4%**. It
  is smaller only against *two parallel* ML-KEMs (2176 B, **-33.8%**). It is a win exactly where
  you genuinely need one key bound to two public keys, i.e. a handshake — which is what DAKE is.
  `tests/both_legs_contribute.rs::size_claim_is_measured_against_both_baselines` asserts both
  comparisons so the favourable one cannot be quoted alone, which is how the withdrawn crate's
  README misled.

## Reporting

Do not file a public issue for a finding in this crate. It is unreviewed by construction; see the
repository-root `SECURITY.md` for the disclosure process.
