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

- Constant-time infinity-norm screening via [`module_norm_within_bound`](../lib-q-lattice-zkp/src/util.rs) on verifier paths (default build) and prover rejection loops (with `hardened`)
- Prover loops always run verification per attempt (no early `continue` on norm failure when `hardened` is enabled)
- Requires `random` for proving smoke tests

**Out of scope:** constant-time ring arithmetic, rejection-attempt counts, and full Fiat–Shamir prover uniformity.

## CI screening (not certification)

Workspace crate [`lib-q-sca-test`](../lib-q-sca-test) provides Welch *t*-test style timing probes (`dudect`-inspired). CI runs a **smoke** gate on `hardened` builds:

```bash
cargo test -p lib-q-ml-kem --features hardened,random hardened_dudect_smoke
cargo test -p lib-q-ml-dsa --features hardened,random,mldsa44 --test hardened_dudect_smoke
cargo test -p lib-q-lattice-zkp --features hardened,random --test hardened_dudect_smoke
```

This is a regression hook only. It does **not** constitute independent side-channel evaluation.

## Release attestation string template

Tagged releases that include attested `hardened` artifacts may publish:

```text
libQ hardened attestation: lib-q-ml-kem=<version> lib-q-ml-dsa=<version> lib-q-lattice-zkp=<version> sca_smoke=pass date=<ISO8601>
```

Downstream products map this string to their own attestation gate identifiers.

## Honest claims

- No crate in this workspace has completed independent side-channel certification unless explicitly stated in a signed release note.
- `hardened` reduces known implementation risks; it does not guarantee resistance on all targets.
