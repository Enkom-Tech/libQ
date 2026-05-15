# Design: federation ring openings vs DualRing-LB

This crate ships a **federation ring-opening** construction and **DualRing-LB** ring openings
([`dualring_lb`](src/dualring_lb.rs)) following Beullens et al. (CCS 2021, ePrint 2021/1213,
Algorithm 3), adapted to the Ajtai opening identification scheme and ML-DSA–style sparse-ball
Fiat–Shamir challenges for the hashed aggregate (see the DualRing-LB section for the deviation from
the paper’s mod-3 challenge space). All paths share the [`lib-q-lattice-zkp`](../lib-q-lattice-zkp/) Ajtai
commitment reference string (CRS).

## Current construction: federation opening proofs

Each issuer publishes an Ajtai commitment image `Com_i = A · (r_i ‖ m_i)` under a
common CRS. To sign a 32-byte message digest `mu` for a ring of `n` members:

1. The signer with index `i*` computes
   `ctx = "lib-q-ring-sig/sign-v1" ‖ federation_digest(ring) ‖ mu`,
   where `federation_digest` is `SHAKE256` over the ordered serialization of all
   `Com_i` values.
2. The signer runs `prove_opening` on its own opening witness for `Com_{i*}` with
   transcript context `ctx`, producing an `OpeningProof = (w, z)` from
   [`lib-q-lattice-zkp::sigma::opening`](../lib-q-lattice-zkp/src/sigma/opening.rs).

Two verification entry points are provided:

| Entry point | Knows signer index? | Cost | Issuer-hiding |
|-------------|---------------------|------|---------------|
| `verify_federation_opening` | Yes (`signer_index` argument) | One `verify_opening` call | Toward verifier: no |
| `verify_federation_opening_scan` | No | Up to `n` `verify_opening` calls | Toward verifier: no (succeeds at exactly one index when keys are distinct) |
| `verify_dualring_lb` | No | One aggregated `verify_dual_ring_opening` (linear in ring size, no per-member `verify_opening` OR) | Single DualRing FS equation; timing does not depend on signer index |

The legacy scan verifier's success index leaks the signer to the verifier, and the loop is
not constant-time. `verify_dualring_lb` runs the **aggregated** DualRing check from CCS 2021
(Algorithm 3) adapted to this Ajtai opening and ML-DSA–style sparse-ball FS challenges.

### Concrete pilot parameters

The `mldsa65_pilot` profile in [`params.rs`](src/params.rs) reuses ML-DSA-65 sigma
constants and is adequate for protocol-level CI smoke tests:

| Field | Value | Source |
|-------|-------|--------|
| `tau` (challenge sparsity) | 39 | FIPS 204 ML-DSA-65 challenge ball |
| `z_inf_bound` (||z||∞ abort) | 20_000_000 | Matches `lib-q-lattice-zkp` opening unit tests |
| `max_prove_attempts` | 512 | Empirical rejection budget for the pilot CRS |

Additional **NIST category–oriented** profiles (`nist_security_category_{1,3,5}`) freeze distinct
`tau`, `z_inf_bound`, and retry budgets for integrators who want separate smoke-test knobs;
they are still **not** production parameters until matched to a Module-SIS hardness margin.

These are **not** production parameters. A deployment must bind issuer Ajtai parameters
(`module_rank`, `randomness_dimension`, ring modulus `q`, ring degree `n_ring`) to the
target NIST security category and re-derive `tau` and the norm bound accordingly.

## DualRing-LB target vs shipped pilot

DualRing-LB attains true ring anonymity (against the verifier) by interleaving a primary
ring of commitments with a dual challenge ring. Witness extraction reduces to
Module-LWE / Module-SIS over the same ring used by ML-DSA-65, so the construction can
share NTT and challenge sampling with [`lib-q-ring`](../lib-q-ring/).

**Shipped today:** [`sign_dualring_lb`](src/dualring_lb.rs) / [`verify_dualring_lb`](src/dualring_lb.rs)
implement DualRing (CCS 2021, Algorithm 3) on the federation opening relation: challenges
`c_1, …, c_n` with `Σ_i c_i = H(ctx ‖ R)` and combined first message
`R = A·y − Σ_{i≠j} c_i · Com_i`, plus one response `z`. Verification is a single aggregated
linear + FS check in [`lib_q_lattice_zkp::verify_dual_ring_opening`](../lib-q-lattice-zkp/src/sigma/opening.rs).

The paper’s Section 7 uses a coefficient-wise mod-3 challenge space; this codebase keeps
[`lib_q_ring::sample_in_ball`](../lib-q-ring/) for the **aggregate** challenge derived from `H(ctx ‖ R)`.
Decoy challenges for `i ≠ j` are independent ball samples; the adjusted `c_j` need not be sparse.

### Target parameter sketches

These are reference points from the literature, not bench-validated for this codebase.

| Security category | Module rank `k` | Ring degree `n` | Modulus `q` | Signature size | Notes |
|-------------------|-----------------|-----------------|-------------|----------------|-------|
| NIST Category 1 | 4 | 256 | ≈ 2^23 | ≈ (constant) + 24·n_ring bytes/member | Beullens et al., Table 4 |
| NIST Category 3 | 5 | 256 | ≈ 2^23 | ≈ (constant) + 24·n_ring bytes/member | Beullens et al., Table 4 |
| NIST Category 5 | 6 | 256 | ≈ 2^23 | ≈ (constant) + 24·n_ring bytes/member | Beullens et al., Table 4 |

The `~24 B/member` term reflects the dual ring's extra commitment per slot. Remaining
engineering toward the paper target:

1. Align challenge-space and norm analysis with Beullens et al., Table 4 / Section 7, if a strict mod-3 `C` is required for a deployment profile.
2. Re-derive transcript hashes and norm bounds directly from Beullens et al., Table 4, for the
   chosen NIST category.

For deployments that require a **bit-for-bit** match to the paper’s Table 4 parameters and mod-3
challenge analysis, re-derive `tau`, norm bounds, and transcript labels accordingly.

## PRF laboratory transcript (`pilot-insecure-prf-transcript`)

The `pilot-insecure-prf-transcript` Cargo feature enables:

- [`dualring_prf`](src/dualring_prf.rs): **canonical** Fiat–Shamir transcript, digest labels, sign /
  verify / **batch verify** entry points for **Legendre** and **Gold** (power-residue) PRF tags over
  safe primes from [`lib-q-prf`](../lib-q-prf/).
- [`pilot_insecure_prf_transcript`](src/pilot_insecure_prf_transcript.rs): legacy `pilot_prf_transcript_*`
  names as type aliases and `#[inline]` wrappers over `dualring_prf`, preserving wire compatibility
  with earlier pilot vectors.

This surface is **not** a ring signature: verification is defined for a **known signer index**, and
the ordered member list carries **raw PRF secret key encodings** so the verifier can recompute PRF
outputs. Any party who sees that list can forge transcripts for any member. The API and Cargo
feature name are intentionally explicit about that threat model.

**Batch verification (`verify_dualring_prf_batch_u256`).** The batch entry point always iterates the
full item list, folds per-item success with `subtle::Choice`, and returns a single aggregate
`Result` (any failure maps to `Rejected`). That avoids **short-circuiting on the first failing
batch index**, which would otherwise create a timing side channel correlated with position. It does
not claim full constant-time equality of work across distinct single-item failure paths.

| Aspect | DualRing-LB (target / default path) | PRF transcript (`dualring_prf` / pilot wrappers) |
| ------ | ------------------------------------- | -------------------------------------------------- |
| FS model | ROM (SHAKE256 as random oracle) | PRF-in-FS style binding for linkage tags (research / lab) |
| Hardness | Module-LWE / Module-SIS in \(R_q\) | PRF / algebraic \(\mathbb{F}_p\) assumptions (see `lib-q-prf`) |
| Anonymity | Full ring anonymity (paper target) | **None** toward anyone who sees the member list (secrets are in the list) |

**Security notes**

- Legendre PRFs over **extension fields** have known weaknesses for degree-1 constructions; `lib-q-prf` evaluates **prime fields \(\mathbb{F}_p\)** only, with that scope documented in [`lib-q-prf/DESIGN.md`](../lib-q-prf/DESIGN.md).
- Gold / power-residue PRFs support oblivious two-party protocols in the literature; this crate wires **direct** evaluation for linkage tags only.

Callers should treat `pilot-insecure-prf-transcript` as **non-shipping** test surface until a
construction exists that exposes only true public material and supports issuer-hiding verification.

## Credential binding

[`credential::CredentialPresentation`](src/credential.rs) attaches a **DualRing-LB–style**
signature to an attribute commitment in two steps:

1. The holder produces `attribute_commitment = Com_attr` and an `OpeningProof` for it
   under a holder-chosen Fiat-Shamir context (`attribute_fs_ctx`).
2. The issuer (a ring member) signs
   `attribute_message_digest(Com_attr) = leaf_hash(write_module_vec(Com_attr))`
   with [`sign_dualring_lb`](src/dualring_lb.rs), yielding [`DualRingLbSignature`](src/dualring_lb.rs).

`verify_credential_presentation`:

- runs `verify_opening` against `Com_attr` and the holder's context,
- recomputes `attribute_message_digest`, and
- delegates to [`verify_dualring_lb`](src/dualring_lb.rs).

The legacy `OpeningProof`-only presentation remains available behind the `federation-opening`
Cargo feature (`CredentialPresentationFederationOpening` + `verify_credential_presentation_federation_opening`).

The 32-byte digest is the only object that crosses the holder-issuer boundary, so the
issuer learns nothing about the holder's witness beyond what the public commitment
reveals.

## Known limitations

- **Challenge space vs CCS 2021 paper.** The reference mod-3 challenge group is not used; the aggregate `c` is a `sample_in_ball` output. Re-derive parameters if you need bit-for-bit paper compatibility.
- **Pilot parameters are not production-frozen.** `mldsa65_pilot` and the `nist_security_category_*`
  helpers are smoke-test profiles; re-derive `tau` and norm bounds for deployment.
- **Legacy scan path.** `verify_federation_opening_scan` is not constant-time across ring
  positions and reveals the signer index on success; keep it behind `federation-opening` for
  compatibility only.
- **PRF transcript batch verify.** `verify_dualring_prf_batch_u256` removes batch-index short-circuit
  timing; single-item `dualring_prf_verify_u256` is not uniform across all rejection reasons.
