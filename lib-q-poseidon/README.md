# lib-q-poseidon

Poseidon hash function optimized for zero-knowledge proofs in lib-Q.

## Overview

Poseidon is an algebraic hash function designed specifically for efficient implementation in zero-knowledge proof systems. Unlike traditional hashes like SHA-3, Poseidon operates directly on field elements, making it orders of magnitude more efficient in circuit constraints.

## Features

- **Field-native**: Operates directly on `Complex<Mersenne31>` field elements
- **Efficient**: ~300 constraints per hash vs ~150,000 for Keccak-f[1600]
- **Secure**: Conservative round counts based on peer-reviewed research
- **Post-quantum**: Designed for use in post-quantum zero-knowledge proofs

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

## Security Parameters

- **Poseidon-128**: 128-bit security level
  - State width: 3 (rate=2, capacity=1)
  - Full rounds: 8 (4 before partial, 4 after)
  - Partial rounds: 56
  - S-box: x^5

- **Poseidon-256**: 256-bit security level
  - State width: 3 (rate=2, capacity=1)
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

- MDS matrices are generated using secure methods
- Round constants follow cryptographic best practices
- Parameters chosen conservatively above minimum security margins
- All operations are constant-time where applicable
