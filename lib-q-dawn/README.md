# lib-q-dawn

NTRU-based Key Encapsulation Mechanism with double encoding for smaller ciphertext sizes.

DAWN provides post-quantum security through NTRU lattice cryptography with optimized parameter sets for bandwidth-constrained applications. It offers smaller ciphertext sizes compared to ML-KEM while maintaining equivalent security levels.

## Features

- NTRU lattice-based post-quantum security
- Four parameter sets with NIST-I and NIST-V security levels
- Smaller ciphertext sizes than ML-KEM
- WASM compilation support
- Constant-time operations and side-channel resistance

## Usage

```rust
use lib_q_dawn::{DawnKem, DawnParameterSet};

let kem = DawnKem::new(DawnParameterSet::Alpha512);
let keypair = kem.generate_keypair()?;
let (ciphertext, shared_secret) = kem.encapsulate(&keypair.public_key)?;
let decrypted_secret = kem.decapsulate(&keypair.secret_key, &ciphertext)?;
```

### Available Parameter Sets

- `DawnParameterSet::Alpha512` - NIST-I security, minimal ciphertext size (default: production profile)
- `DawnParameterSet::Alpha1024` - NIST-V security, minimal ciphertext size  
- `DawnParameterSet::Beta512` - NIST-I security, minimal combined size
- `DawnParameterSet::Beta1024` - NIST-V security, minimal combined size

### Profiles (Alpha512)

- **Production** (currently experimental): Alpha512, Alpha1024, and Beta512 tuned profiles are available via `DawnKem::new(...)`; all remain experimental. Alpha512 was evaluated with a reliability-bounded decoder prototype (quick sweep: no zero-mismatch candidate). Path A sweeps (Alpha1024, Beta512, baseline decoder) also found no passing candidate. See SECURITY.md and reference/DAWN/DAWN-spec.md §6.8–6.9.
- **Spec / experimental**: Use `DawnKem::new_with_profile(DawnParameterSet::Alpha512, DawnProfile::SpecExperimental)` for paper-faithful parameters (d_c=7, k_s=96, k_e=160). Non-negligible decryption failure with current decoder; experimentation only.

## Parameter Sets

| Parameter Set | Security | Public Key | Secret Key | Ciphertext (spec / production α-512) |
|---------------|----------|------------|------------|--------------------------------------|
| DAWN-α-512    | NIST-I   | 640 bytes  | 1360 bytes | 448 (spec) / 640 (production)         |
| DAWN-α-1024   | NIST-V   | 1280 bytes | 2688 bytes | 1024 bytes                            |
| DAWN-β-512    | NIST-I   | 576 bytes  | 1248 bytes | 512 bytes                             |
| DAWN-β-1024   | NIST-V   | 1152 bytes | 2400 bytes | 1152 bytes                            |

- **α variants**: Minimal ciphertext size
- **β variants**: Minimal combined public key + ciphertext size

## Security

- NTRU lattice-based cryptography with double encoding
- Constant-time operations and side-channel resistance
- Secure memory management with automatic zeroization
- NIST-approved post-quantum security levels
- Resistance to quantum attacks under NTRU and Ring-LWE assumptions

## Implementation

The implementation includes:
- Power-of-2 cyclotomic rings R[x^n+1] with NTT optimization
- Zero divisor encoding with t = x^(n/2) + 1, w = x^(n/4) + 1
- Comprehensive test suite with 82 tests
- WASM bindings for web deployment

## Testing

```bash
cargo test
```

- Unit/integration: `cargo test`
- Stress tests (10k / 100k cycles): `tests/stress_tests.rs`; ignored by default. Run with `cargo test -p lib-q-dawn --test stress_tests -- --ignored`
- Parameter sweep (grid of k_s, k_e; 10k PKE + 10k KEM per candidate): `cargo test -p lib-q-dawn --features random --test parameter_sweep test_alpha512_parameter_sweep_grid -- --ignored --nocapture`. Quick sweep (1k/1k): `test_alpha512_parameter_sweep_quick`
- Deep stress for one candidate: set `DAWN_STRESS_KS`, `DAWN_STRESS_KE` (e.g. 24, 32), optionally `DAWN_STRESS_CYCLES=1000000`, then `cargo test -p lib-q-dawn --features random --test parameter_sweep test_alpha512_deep_stress_candidate -- --ignored --nocapture`

## License

See the main [lib-q license](../LICENSE).
