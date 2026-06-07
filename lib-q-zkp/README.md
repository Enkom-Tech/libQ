# lib-q-zkp

High-level **zero-knowledge proof** API for lib-Q, built on the in-tree **zk-STARK** stack (`lib-q-stark` and related crates). Optional integration with the **Plonky**-derived crates is available behind features (see `Cargo.toml`).

## Implemented AIRs (selection)

| AIR | Purpose |
|-----|---------|
| `RecoveryPolicyAir` | Recovery policy threshold / key-weight proofs (`air_id = 1`) |
| `StateTransitionAir` | State machine transitions with hash commitments |
| `HashPreimageNistAir` | NIST (SHAKE256) hash preimages |
| `CredentialAir` | Credential issuance constraints |
| `MerkleInclusionAir` | Merkle inclusion proofs |

See `src/air/` for the full set.

## Recovery policy proofs (v0)

Generic recovery-policy STARK proofs over weighted key sets:

- **Public inputs:** policy commitment, threshold, key count, time-lock bounds, freshness epoch, crypto suite id (58 bytes on wire).
- **Prove / verify:** `prove_recovery_policy`, `verify_recovery_policy_envelope`.
- **Wire:** `encode_recovery_zk_proof_v0` / `decode_recovery_zk_proof_v0` (max 512 KiB envelope).
- **Budgets:** [docs/recovery-policy-budgets.md](docs/recovery-policy-budgets.md).
- **KATs:** `tests/vectors/recovery-policy-v0/` — regenerate with `cargo test -p lib-q-zkp kat_regenerate_recovery_policy_vectors -- --ignored --release`.

## Where to read more

- [**docs/zkp-implementation.md**](../docs/zkp-implementation.md) — layout of `lib-q-zkp`, `lib-q-stark*`, `lib-q-plonky`, and how they differ from the research [**lib-q-lattice-zkp**](../lib-q-lattice-zkp) path.
- [**lib-q-plonky**](../lib-q-plonky) — batch STARK, Keccak AIR, lookups, etc.

## WASM

CI checks this crate for `wasm32-unknown-unknown` with the appropriate feature set; it is a normal Rust library (not the primary `wasm-pack` npm artifact).

## License

Apache-2.0 — see [LICENSE](../LICENSE).
