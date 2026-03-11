# STARK Test Suite

## Current Status

**Tests are enabled and use `Complex<Mersenne31>` as the base field.**

All integration tests have been migrated from raw `Mersenne31` to `Complex<Mersenne31>` (TWO_ADICITY = 32), with byte-based hashing (`SerializingHasher` + SHAKE256) and `ComplexFieldChallenger` for transcript consistency. No tests are marked with `#[ignore]`.

### Test Configuration

- **Val type**: `Complex<Mersenne31>` (TWO_ADICITY = 32, sufficient for FRI)
- **Challenge type**: `Complex<Mersenne31>` (same as Val)
- **Hash**: `SerializingHasher<Shake256Hash>` for Merkle trees (NIST-approved)
- **Challenger**: `ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>`

### Test Files

- **fib_air.rs**: One-row trace, public value, ZK (hiding MMCS)
- **mul_air.rs**: Two-adic FRI prove/verify (deg 2–5, including ZK)
- **mul_fib_pair.rs**: Mul+Fib pair with preprocessed columns, tampered preprocessed rejection
- **rc_sub_builder.rs**: Range-check sub-builder symbolic constraints and prove/verify
- **dos_protection_tests.rs**: DoS limits (public values, commitments, opened elements, byte size, degree)
- **transcript_integrity_tests.rs**: Different public values/trace change quotient commitment, challenger sync
- **soundness_tests.rs**: Verifier rejects tampered commitments, wrong public values, wrong width, constraint violations, tampered FRI auth path
- **zeroization_tests.rs**: `SecretWitness` zeroization (uses raw `Mersenne31` only for memory-safety checks, no prove/verify)

### Note on ComplexFieldChallenger

`ComplexFieldChallenger` is exported from `lib-q-stark-challenger` and imported by all test files and by `lib-q-zkp/src/stark.rs`.

### Circle STARKs

Circle STARK tests (`prove_m31_circle_deg2`, `prove_m31_circle_deg3`) remain commented out; Circle STARKs are not integrated.
