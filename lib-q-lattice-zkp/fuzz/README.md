# lib-q-lattice-zkp fuzzing

From this directory (with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) installed):

```bash
cargo fuzz run lattice_zkp_verify_opening
```

Available targets include `lattice_zkp_verify_opening`, `lattice_zkp_verify_nullifier_opening`, `lattice_zkp_verify_blind_bundle`, `lattice_zkp_verify_blind_signature`, `lattice_zkp_verify_witness_nullifier`, and `lattice_zkp_verify_private_membership`.

Each harness feeds arbitrary bytes into `MlDsaCompatibleChallenge::derive`, builds a small fixed-geometry commitment and proof blob, and runs the corresponding verifier. The goal is to catch panics or UB in verifier and XOF/challenge paths; harnesses do not assert cryptographic soundness.
