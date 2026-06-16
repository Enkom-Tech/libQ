# lib-q-poseidon

Poseidon hash function optimized for zero-knowledge proofs in lib-Q.

Used on selected ZKP paths (for example where documented in `lib-q-zkp`); the default STARK pipeline is SHAKE256-oriented. See [docs/zkp-implementation.md](../docs/zkp-implementation.md).

## Overview

Poseidon is an algebraic hash function designed specifically for efficient implementation in zero-knowledge proof systems. Unlike traditional hashes like SHA-3, Poseidon operates directly on field elements, making it orders of magnitude more efficient in circuit constraints.

## Features

- **Field-native**: Operates directly on `Complex<Mersenne31>` field elements
- **Efficient**: ~300 constraints per hash vs ~150,000 for Keccak-f[1600]
- **Post-quantum**: Designed for use in post-quantum zero-knowledge proofs

> **Security warning:** The round counts and sponge parameters in this crate have
> **not** been independently verified for the `Complex<Mersenne31>` extension field
> GF(p²). The standard Poseidon security analysis is stated over a prime field and
> does not directly cover this field and state. Do **not** rely on a specific
> bit-security level (e.g. 128-bit or 256-bit) until these parameters have been
> regenerated and analyzed for GF(p²).

## Usage

```rust
use lib_q_poseidon::{Poseidon, Poseidon128};
use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;

type Val = Complex<Mersenne31>;

let hasher = Poseidon128::default();
let input = vec![
    Val::from(Mersenne31::new(1)),
    Val::from(Mersenne31::new(2)),
];
let hash = hasher.hash(&input);
```

## Parameter Sets

The "128"/"256" labels reflect targeted capacity margins only. The round counts
are **not** independently verified for GF(p²); do not rely on a specific
bit-security level (see the security warning above).

- **Poseidon-128** (parameter set, unverified bit-security over GF(p²))
  - State width: 5 (rate=2, capacity=3)
  - Full rounds: 8 (4 before partial, 4 after)
  - Partial rounds: 56
  - S-box: x^5

- **Poseidon-256** (parameter set, unverified bit-security over GF(p²))
  - State width: 7 (rate=2, capacity=5)
  - Full rounds: 8 (4 before partial, 4 after)
  - Partial rounds: 60
  - S-box: x^5

## Architecture

This implementation follows the standard Poseidon design:
1. **AddRoundConstants (ARC)**: XOR round constants into state
2. **SubWords (S-box)**: Apply x^5 non-linear transformation
3. **MixLayer**: Multiply by MDS matrix for diffusion

The sponge construction is used for hashing variable-length inputs.

## Integration with lib-q-zkp

This crate is integrated with `lib-q-zkp` for use in STARK proofs. The Poseidon hash is used in:
- Hash preimage proofs
- Merkle tree inclusion proofs
- Other zero-knowledge proof applications

## Security Considerations

- MDS matrices use a Cauchy construction (every square submatrix is invertible)
- Round constants are derived deterministically via SHAKE256 ("nothing up my sleeve")
- The sponge uses standard 10*1 padding in the rate
- Round counts and parameters are **not** independently verified for GF(p²);
  do not rely on a specific bit-security level (see the security warning above)
- All operations are constant-time where applicable
