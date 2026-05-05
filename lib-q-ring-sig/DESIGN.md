# Design: federation ring openings vs DualRing-LB

This crate ships a **federation ring-opening** construction and a **DualRing-LB–oriented pilot**
([`dualring_lb`](src/dualring_lb.rs)): extended Fiat–Shamir absorption plus constant-time
full-ring verification of the same opening relation as federation signing. A full
**DualRing-LB** scheme in the sense of Beullens, Esgin, Knapp, Sakzad, Steinfeld, and Sun
(CCS 2021, ePrint 2021/1213) would add linked responses across members; that paper target
remains future work. All paths share the [`lib-q-lattice-zkp`](../lib-q-lattice-zkp/) Ajtai
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
| `verify_dualring_lb` | No | `n` `verify_opening` calls (no early return) | Timing-hardened scan; still not the paper’s single-response ring equation |

The scan verifier's success index leaks the signer to the verifier, and the loop is
not constant-time. `verify_dualring_lb` removes **early-exit** timing bias but still runs
one opening check per member. Federation membership is verifiable by external auditors who hold
the ring, but **cryptographic ring anonymity toward the verifier** still requires the CCS 2021
aggregated verification target.

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
reuse the federation opening witness relation with a DualRing-style extended transcript
and constant-time aggregation of per-member `verify_opening` results. This is **not** the
paper’s single aggregated response; treat it as a federation hardening layer until the
full verification equation is implemented.

### Target parameter sketches

These are reference points from the literature, not bench-validated for this codebase.

| Security category | Module rank `k` | Ring degree `n` | Modulus `q` | Signature size | Notes |
|-------------------|-----------------|-----------------|-------------|----------------|-------|
| NIST Category 1 | 4 | 256 | ≈ 2^23 | ≈ (constant) + 24·n_ring bytes/member | Beullens et al., Table 4 |
| NIST Category 3 | 5 | 256 | ≈ 2^23 | ≈ (constant) + 24·n_ring bytes/member | Beullens et al., Table 4 |
| NIST Category 5 | 6 | 256 | ≈ 2^23 | ≈ (constant) + 24·n_ring bytes/member | Beullens et al., Table 4 |

The `~24 B/member` term reflects the dual ring's extra commitment per slot. Remaining
engineering toward the paper target:

1. Replace per-member opening checks with the single linked DualRing-LB verification equation.
2. Re-derive transcript hashes and norm bounds directly from Beullens et al., Table 4, for the
   chosen NIST category.

Until then, callers who require **strong** verifier-side issuer anonymity should treat the
pilot as timing-hardened federation rather than a drop-in anonymous ring signature.

## DualRing-PRF (optional, `dualring-prf`)

The `dualring-prf` Cargo feature enables [`dualring_prf`](src/dualring_prf.rs), a **pilot**
Fiat–Shamir transcript that binds a message digest to **Legendre** and **Gold**
(power-residue) PRF tags over safe primes from [`lib-q-prf`](../lib-q-prf/).

| Aspect | DualRing-LB (target / default path) | DualRing-PRF (`dualring-prf`) |
| ------ | ----------------------------------- | ----------------------------- |
| FS model | ROM (SHAKE256 as random oracle) | QROM-oriented (PRF + FS literature for this class) |
| Hardness | Module-LWE / Module-SIS in \(R_q\) | PRF / DDH-style \(\mathbb{F}_p\) assumptions + safe-prime structure |
| Anonymity | Full ring anonymity (paper target) | **Pilot:** PRF path may require the signer index; not a drop-in anonymous ring signature yet |

**Security notes**

- Legendre PRFs over **extension fields** have known weaknesses for degree-1 constructions; `lib-q-prf` evaluates **prime fields \(\mathbb{F}_p\)** only, with that scope documented in [`lib-q-prf/DESIGN.md`](../lib-q-prf/DESIGN.md).
- Gold / power-residue PRFs support oblivious two-party protocols in the literature; this crate wires **direct** evaluation for linkage tags only.

Callers should treat `dualring-prf` as experimental protocol surface until parameters,
transcript binding, and verifier APIs are aligned with the published DualRing-PRF
construction.

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

- **Opening-based ring verify is not the CCS 2021 aggregated equation.** `verify_dualring_lb`
  still proves the federation opening relation independently per commitment image; it
  removes early-exit timing leaks but does not realize full ring anonymity from the paper.
- **Pilot parameters are not production-frozen.** `mldsa65_pilot` and the `nist_security_category_*`
  helpers are smoke-test profiles; re-derive `tau` and norm bounds for deployment.
- **Legacy scan path.** `verify_federation_opening_scan` is not constant-time across ring
  positions and reveals the signer index on success; keep it behind `federation-opening` for
  compatibility only.
