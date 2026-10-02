# Security assurance (`lib-q-ml-kem`) — LWE-with-hints posture

Assessment of ePrint [2020/292](https://eprint.iacr.org/2020/292) (Dachman-Soled, Ducas, Gong,
Rossi, "LWE with Side Information: Attacks and Concrete Security Estimation", CRYPTO 2020)
against this crate. See the repository-root [SECURITY.md](../SECURITY.md) for the general
disclosure policy; this file is scoped to the Module-LWE hint-attack framework only.

## What the paper is

Not a break of any specific scheme. It generalizes the primal lattice-reduction attack to absorb
"hints" — side information about the LWE secret and/or error — before a final BKZ run, and
predicts the resulting drop in the concrete block size (and so the bikz security level). The
authors ship a Sage 9.0 toolkit (`leaky-LWE-Estimator`) implementing four hint classes:

- **Perfect hints** — an exact linear equation on the secret (e.g. a fully-recovered coefficient).
- **Modular hints** — a linear relation known modulo an integer or modulo `q`.
- **Approximate hints** — a noisy (Gaussian-distributed) inner product with the secret; this is
  the shape a side-channel trace or a decryption-failure oracle typically yields.
- **Short-vector hints** — a short vector known to lie in, or near, the lattice's dual.

Beyond side channels, the paper explicitly lists "exploiting decryption failures" and "constraints
imposed by certain schemes (LAC, Round5, NTRU)" as other hint sources, and demonstrates an
improved single-trace attack on Frodo (Bos et al., SAC 2018) as an end-to-end example.

ML-KEM (this crate) and ML-DSA (`../lib-q-ml-dsa`) both rest on Module-LWE / Module-SIS, so the
hint framework applies to both in principle: an implementation-level leak of secret or error
information degrades their concrete bikz exactly the way the paper models, independent of any
flaw in the FIPS 203 / FIPS 204 algorithms themselves. The question this file answers is whether
*this crate's shipped implementation* hands an adversary a hint source the framework could use,
and what stands between a real-world attacker and that source.

## Where this crate would leak an approximate hint, and what denies it

The approximate-hint case (§4 of the paper) is the one an implementation controls: a power trace
or timing measurement that correlates with a secret-dependent intermediate value is exactly a
noisy linear hint on that value. `hardened` (feature flag, `Cargo.toml`) is the atomic
countermeasure set on the ML-KEM decapsulation path that exists to deny that measurement:

| Countermeasure | Location |
|---|---|
| First-order additive sharing of `s_hat` in the NTT-domain dot product with `u_hat` | `src/masking.rs:4`, `ntt_vector_dot_masked` |
| Multiplicative masking (`rho * s_hat` against `rho^-1 * u_hat`) before the product | `src/masking.rs:5` |
| Constant-time CBD table lookup, avoiding secret-dependent indexing into `Eta::ONES` | `src/masking.rs:6`, `cbd_table_lookup_ct` |
| Fisher–Yates shuffle of NTT-product accumulation order | `src/masking.rs:7`, `hardened_rng.rs:46-61 shuffle_indices` |
| NTT-domain blinding (`Polynomial::ntt` / `NttPolynomial::ntt_inverse` scaled by random `r`, `r^-1`) | `src/masking.rs:11-14` |
| Row-independent masking on the matrix–vector product (re-encryption path) | `src/masking.rs:9-10`, `ntt_matrix_vector_masked` |
| Constant-time ciphertext equality (byte-wise and coefficient-wise) | `src/masking.rs:158-166,189-200` |

These are first-order countermeasures — `masking.rs:4` states "first-order additive sharing"
explicitly. Whether first-order sharing is sufficient against a specific adversary's approximate-
hint budget under this paper's model (i.e. how many traces / how much noise reduction a real
attacker gets before the residual leakage becomes a useful hint) is target- and adversary-specific
and is **not** established by this crate; it is a claim about the countermeasure's structure, not
a measured bound on the hint's information content.

The masking randomness itself is fail-closed by design, which matters here because a degraded
RNG turns a denied hint back into a perfect one: `hardened_rng.rs:8-11` — "Masking randomness
that silently degrades to a constant defeats the countermeasure entirely (e.g. `r = 1` means no
blinding; a stuck Fisher–Yates means no shuffle) ... the system is in an unrecoverable insecure
state" — `OsRngFill` panics on `getrandom` failure rather than returning a fallback
(`hardened_rng.rs:39-43`).

Outside `hardened`, no additional countermeasure denies the approximate-hint channel; the default
build states "constant-time intent" only (`README.md:16`), which is a narrower claim.

## Decryption failures as a hint source

The paper treats decryption failures as their own hint category, separate from side channels, and
the schemes it demonstrates this against (LAC, Round5) had non-negligible failure rates. ML-KEM's
conjectured decryption-failure probability at the FIPS 203 parameter sets — 2^-139 (ML-KEM-512),
2^-164 (ML-KEM-768), 2^-174 (ML-KEM-1024) [Kyber round-3 submission; reproduced e.g. in
[eprint 2022/212](https://eprint.iacr.org/2022/212.pdf)] — is not tracked anywhere in this crate
(`src/param.rs` carries no `DFR`/failure-probability constant; this file is the first place it is
recorded). At those probabilities a failure-oracle attack needs on the order of 2^130+ decryption
queries against a single key even before any lattice-reduction cost, which is not a realistic
adversary budget. This crate's position is that decryption-failure hints are out of reach for
ML-KEM at the shipped parameter sets, unlike the LAC/Round5 constructions the paper targets —
this is a statement about the published parameter design, not something this crate independently
re-derives.

## The same model applies to ML-DSA

`../lib-q-ml-dsa` carries the analogous masked path with the same fail-closed entropy discipline:
`sample_mask_vector`, `compute_matrix_x_mask`, and `merge_masked_ntt_products` in
`../lib-q-ml-dsa/src/ml_dsa_generic.rs:26,30,43` implement masked mask-vector sampling and masked
NTT products on the signing path, and `SigningError::MaskEntropyUnavailable`
(`../lib-q-ml-dsa/src/ml_dsa_generic.rs:231`) is the same fail-closed-on-RNG-failure policy as
`hardened_rng.rs` here, rather than a silent degrade. ML-DSA's own audit notes
(`../lib-q-ml-dsa/docs/SECURITY_AUDIT.md`) already carry a "Side-Channel Resistance (Hardened
Mode)" section; this file does not duplicate that assessment, it only records that the same hint
framework applies to it for the same structural reason (Module-LWE/Module-SIS secret material,
masked implementation, fail-closed entropy).

## Measuring the leakage this framework's hints assume

`../lib-q-sca-test` is the in-repo tool for the kind of measurement an approximate-hint attacker
would need: "Statistical helpers for TVLA-style and timing-based leakage smoke tests"
(`../lib-q-sca-test/src/lib.rs:1`). Its `dudect` module is explicit about scope: "Wall-clock
timing harness in the spirit of dudect ... This is **not** a substitute for instrumented power
traces or a calibrated dudect build" (`../lib-q-sca-test/src/dudect.rs:1-4`). It is a CI/lab smoke
test for gross timing leaks in `hardened` code paths, not evidence bounding the residual
approximate-hint information content an instrumented power/EM attacker could extract — that gap
is the same one the paper's Frodo single-trace application closes with real trace data, which this
repository does not have or reproduce.

## Verdict

- The paper is a methodology/estimation framework, not a break of ML-KEM or ML-DSA.
- `hardened` is a first-order countermeasure set that structurally denies the approximate-hint
  channel the paper models for side-channel leakage; whether first-order suffices against a given
  adversary's trace budget is not established here and remains an open question for anyone relying
  on `hardened` against a funded attacker.
- ML-KEM's conjectured decryption-failure rate at the shipped FIPS 203 parameter sets puts the
  paper's decryption-failure-hint application out of reach; this is not independently re-derived
  here.
- `lib-q-sca-test` can catch a *regression* in constant-time discipline; it is not calibrated
  power/EM instrumentation and cannot itself confirm the hint channel is closed against a real
  attacker.

Verdict: INFORMATIONAL
