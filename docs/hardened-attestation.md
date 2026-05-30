# Hardened build attestation

This document describes the `hardened` feature on `lib-q-ml-kem`, `lib-q-ml-dsa`, and `lib-q-lattice-zkp`.

## Scope per crate

### `lib-q-ml-kem` (`hardened` feature)

- Coefficient **masking** during sensitive operations ([`src/masking.rs`](../lib-q-ml-kem/src/masking.rs))
- **Hardened RNG** path for decapsulation randomness ([`src/hardened_rng.rs`](../lib-q-ml-kem/src/hardened_rng.rs))
- **Subtle** constant-time comparisons when the feature is enabled
- Requires `random` + `getrandom`; enable the complete feature set only

### `lib-q-ml-dsa` (`hardened` feature)

- Side-channel-oriented hardening hooks on signing/decoding paths (masking / subtle comparisons)
- Requires `random`, `zeroize`, `subtle`, `getrandom`

### `lib-q-lattice-zkp` (`hardened` feature)

- **Shared ring CT primitives** ([`lib-q-ring`](../lib-q-ring/src/poly.rs)): branch-free `Poly::infinity_norm`, `normalize_mod_q_assign`, `scalar_mul_by_u32_mod_q` (Barrett reduction)
- **First-order witness masking** before `c·wit` ([`MaskedWitness`](../lib-q-lattice-zkp/src/sigma/secrets.rs)): additive shares derived from SHAKE256
- **Structured prover loops**: constant-time norm screen, always run verification per attempt, and **fixed `max_attempts` iteration** with constant-time first-accept transcript selection (no early return on success)
- **Secure mask RNG**: [`hardened::new_secure_rng`](../lib-q-lattice-zkp/src/hardened.rs) via `lib-q-random` (`secure` + `getrandom`)

**Out of scope:** microarchitectural channels (cache/SMT/transient) and independent laboratory certification. Higher-order masking proofs are a planned milestone ([higher-order-masking-milestone.md](higher-order-masking-milestone.md)).

## CI screening (not certification)

Workspace crate [`lib-q-sca-test`](../lib-q-sca-test) provides Welch *t*-test style timing probes (`dudect`-inspired). CI runs **smoke** gates on `hardened` builds:

```bash
cargo test -p lib-q-ml-kem --features hardened,random hardened_dudect_smoke
cargo test -p lib-q-ml-dsa --features hardened,random,mldsa44 --test hardened_dudect_smoke
cargo test -p lib-q-lattice-zkp --features hardened --test hardened_dudect_smoke --test hardened_masked_witness
cargo test -p lib-q-sca-test --features lattice-zkp-hardened lattice_zkp_hardened_prove_dudect_smoke
```

This is a regression hook only. It does **not** constitute independent side-channel evaluation.

## Self-certification

The [side-channel self-certification](sca-self-certification.md) process layers a repeatable, auditable evaluation on top of the smoke gates. [`lib-q-sca-test`](../lib-q-sca-test) runs a fixed-vs-random TVLA battery over the hardened ML-KEM, ML-DSA, and lattice-ZKP paths, derives a per-target verdict against the `|t| < 4.5` gate, and emits a JSON + Markdown evidence package (schema `libq.sca.self-cert.v1`). Externally acquired power/EM/cycle traces feed the same statistical gate through the ingestion hook. Self-certification surfaces defects before an accredited engagement; it is the entry criterion for a laboratory, not a substitute for one.

```bash
cargo test -p lib-q-sca-test --features lattice-zkp-hardened \
    --test self_cert_report self_cert_full_report -- --ignored --nocapture
```

## Release attestation string template

Tagged releases that include attested `hardened` artifacts may publish:

```text
libQ hardened attestation: lib-q-ml-kem=<version> lib-q-ml-dsa=<version> lib-q-lattice-zkp=<version> sca_smoke=pass date=<ISO8601>
```

Downstream products map this string to their own attestation gate identifiers.

## Honest claims

- No crate in this workspace has completed independent side-channel certification unless explicitly stated in a signed release note.
- `hardened` reduces known implementation risks; it does not guarantee resistance on all targets.

## Residual risks (lattice-ZKP)

| Risk | Disposition |
|------|-------------|
| Rejection-attempt timing | Mitigated: hardened provers always run `max_attempts` iterations and merge the first accept via `ct_select_polys` |
| Higher-order DPA on masked shares | First-order masking only; compositional leakage proof tracked in [higher-order-masking-milestone.md](higher-order-masking-milestone.md) |
| NTT / matrix multiply microarchitecture | Fixed-iteration Barrett/Montgomery path; not lab-validated |

## Performance budget (`hardened` lattice-ZKP)

Measured on native debug builds (Windows, May 2026); use as a regression anchor, not a SLA:

| Path | Baseline (no `hardened`) | `hardened` | Delta (approx.) |
|------|--------------------------|------------|-----------------|
| `prove_opening` (token profile) | ~15–25 ms (stops on first accept) | ~`max_attempts` × per-attempt cost | Fixed iteration budget; typical `max_attempts=512` is worst-case wall time |
| `verify_opening` | unchanged | unchanged | — |
| `amortise` (2 attributes) | ~5 ms | ~6 ms | +15–20 % (per-attribute witness split + CT scalar mul) |

Hardened prove latency is intentionally bounded by `max_attempts`, not by how quickly a mask passes rejection sampling. Choose `max_attempts` for your latency envelope; correctness requires it be large enough that failure is negligible.

## Security sign-off (lattice-ZKP CT hardening)

| Threat | Control | Evidence |
|--------|---------|----------|
| Secret-dependent norm branches | Branch-free `Poly::infinity_norm` / `polys_norm_within_bound` in `lib-q-ring` | `infinity_norm_matches_branchy_reference`; ML-DSA NIST KATs unchanged |
| Secret-dependent normalization / scalar mul | `normalize_mod_q_assign`, `scalar_mul_by_u32_mod_q` (Barrett) | `normalize_mod_q_and_scalar_mul_smoke`; amortise uses CT scalar path |
| First-order `c·wit` leakage | `MaskedWitness` additive shares; `accumulate_response_z_masked` | `masked_ring_mul_matches_*` tests; hardened prove/verify roundtrips |
| Early-exit timing on norm failure | `accept_transcript`: always run `verify_*` per attempt | `hardened.rs` + DESIGN §11 |
| Rejection-attempt count leakage | Fixed `max_attempts` loop + `first_accept_take` / `ct_select_polys` | `hardened.rs`; opening/linear/dual-ring prove paths |
| Mask / witness retention after reject | `scrub_rejected_*`, `SecretPolyVec` drop zeroization | `secrets` unit tests |
| Regression in shared ring semantics | Cross-crate KAT + smoke gates | `nistkats` 44/65/87; CI hardened smokes |

**Out of scope:** microarchitectural channels and independent laboratory certification. Higher-order masking is a planned milestone ([higher-order-masking-milestone.md](higher-order-masking-milestone.md)).
