# lib-q-sca-test

Workspace tooling crate for **first-order leakage screening** of hardened [**lib-q-ml-kem**](../lib-q-ml-kem) and [**lib-q-ml-dsa**](../lib-q-ml-dsa) paths.

## Contents

- **TVLA helper** — Welch’s *t*-test for fixed-vs-random class means on trace vectors (or any scalar measurements). The common first-order criterion \\(|t| < 4.5\\) after on the order of \\(10^6\\) traces is exposed as a configurable threshold.
- **Timing harness** — collects cycle or wall-clock samples for a user-supplied closure; intended for CI smoke runs with loose thresholds and for longer offline runs comparable to dudect-style methodology.

This crate does **not** assert certification-grade side-channel resistance. It provides a **repeatable statistical scaffold** that downstream CI or labs can feed with real traces.

## Running

```bash
cargo test -p lib-q-sca-test
```

Enable both backends (default):

```bash
cargo test -p lib-q-sca-test --features mlkem,mldsa
```

## Privacy-protocol workloads

Behind the `privacy` feature (enabled by default), [`privacy_workloads`](src/privacy_workloads.rs) exposes deterministic helpers that drive the constant-time-critical paths of the Phase 7 privacy stack:

| Helper | Crate / function | Path under test |
|--------|------------------|-----------------|
| `touch_nullifier` | [`lib-q-lattice-zkp`](../lib-q-lattice-zkp/) `registry_nullifier` | SHAKE256 over commitment wire and realm |
| `touch_federation_digest` | [`lib-q-ring-sig`](../lib-q-ring-sig/) `federation_digest` | SHAKE256 over ordered ring commitments |
| `touch_blind_verify` | [`lib-q-lattice-zkp`](../lib-q-lattice-zkp/) `BlindIssuance::verify` | Fiat-Shamir verifier transcript and opening check |
| `touch_federation_verify` | [`lib-q-ring-sig`](../lib-q-ring-sig/) `verify_federation_opening` | Federation opening proof verification |
| `touch_dualring_lb_verify` | [`lib-q-ring-sig`](../lib-q-ring-sig/) `verify_dualring_lb` | Full-ring DualRing-LB–style opening verification |
| `touch_witness_nullifier` | [`lib-q-lattice-zkp`](../lib-q-lattice-zkp/) `witness_nullifier` | SHAKE256 over witness wire and realm |
| `touch_blind_signature_verify` | [`lib-q-lattice-zkp`](../lib-q-lattice-zkp/) `BlindSignature::verify_blind_signature` | Pilot blind-signature bundle verification |
| `touch_private_membership` | [`lib-q-lattice-zkp`](../lib-q-lattice-zkp/) `verify_private_membership` | Private Merkle membership pilot verifier |

Prover-side rejection-sampling paths (`BlindIssuance::request`/`issuer_sign`, `sign_federation_message`) are intentionally excluded: their timing is data-dependent by construction and is not a meaningful TVLA target.

```bash
cargo test -p lib-q-sca-test --features privacy
```
