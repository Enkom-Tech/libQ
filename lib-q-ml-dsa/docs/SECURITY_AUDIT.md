# ML-DSA Security Audit Checklist

## Cryptographic Correctness

- [ ] All NIST FIPS 204 test vectors pass (keygen, siggen, sigver)
- [ ] ACVP test vectors pass for all parameter sets
- [ ] SIMD and portable implementations produce identical outputs
- [ ] Deterministic: same seed always produces same output
- [ ] Rejection sampling correctly implements FIPS 204 bounds
- [ ] Message representative derivation matches FIPS 204 Algorithm 2
- [ ] Signature encoding/decoding is bijective

## Entropy and Randomness

- [ ] All entropy sources properly validated
- [ ] RNG integration uses lib-q-random correctly
- [ ] No direct SHAKE usage bypassing RNG in hardened mode
- [ ] Entropy quality tests pass (non-duplicate, distribution)
- [ ] NIST DRBG mode works for KAT compatibility

## Side-Channel Resistance (Hardened Mode)

- [ ] Sensitive data zeroized after use (when zeroize feature enabled)
- [ ] Constant-time operations where possible (in `hardened` mode)
- [ ] No timing variations based on secret values
- [ ] No branching on secret data in critical paths

## Fault Injection

**Not covered by the checklist above, and until this card (`ENK-498`, 2026-09-05) nothing in this
crate's docs named fault injection as a threat at all.** The Side-Channel Resistance checklist
above only asks about timing/branching; there is no "Fault Injection" heading anywhere under
`lib-q-ml-dsa/docs/` or in `MODES.md` before this entry.

Two published attacks recover an ML-DSA/Dilithium secret key by fault injection during
**randomized (hedged) signing** — the mode FIPS 204 and this crate select by default (`random`
feature; see [MODES.md](MODES.md)), chosen specifically because randomized signing was believed to
blunt the deterministic-mode attacks:

- Krahmer, Pessl, Land, Güneysu, *"Correction Fault Attacks on Randomized CRYSTALS-Dilithium"*,
  IACR TCHES 2024(4) (ePrint 2024/138): a "skipping fault correction" attack that faults the key
  addition combining the secret masking polynomial with the random nonce, then corrects the faulty
  signature to recover a secret intermediate. Demonstrated on real hardware (clock glitches on an
  ARM Cortex-M4); 512–1024 faulty signatures suffice for Dilithium2 (≈ ML-DSA-44).
- Ouyang, Wang, Liu, Wu, Wang, Fan, *"Improving Skipping Fault Correction Attacks on Randomized
  Dilithium via MILP"*, ePrint 2026/1448 (card `ENK-498`): proves Krahmer et al.'s full-rank
  collection strategy is unnecessary, derives a minimum fault count `M_min` from an MILP model, and
  needs **fewer faults** than Krahmer et al. at every NIST level. Plain-setting reductions: 25.9%
  (L2/ML-DSA-44), 16.2% (L3/ML-DSA-65), 25.6% (L5/ML-DSA-87). **Shuffling-setting** reductions:
  25.6% (L2), 13.5% (L3), 26.3% (L5).

**The "shuffling setting" both papers attack is the same countermeasure class this crate's
`hardened` feature ships as `ntt_at_layer_0_shuffled` / `invert_ntt_at_layer_0_shuffled`
(`src/simd/portable/ntt.rs`, `src/simd/portable/invntt.rs`) — a Fisher-Yates-permuted execution
order for NTT layer 0.** That code's own doc comment scopes its purpose correctly ("mitigating
order-dependent side channels") and never claims fault resistance, so nothing here is
misadvertised (contrast the pre-2026-08-15 `fault_injection_protection` flags in `lib-q-aead` /
`lib-q-hpke`, corrected in `docs/crypto-signoff-register.md`'s fault cross-cutting section). But
neither paper's finding was reachable from this crate's docs before now: both model "shuffling" as
an attacked countermeasure and show it *raises the fault count an attacker needs by 13.5–26.3%, not
that it defeats key recovery*. A reader of `MODES.md`'s "Hardened Mode ... high-security
deployments" framing had no way to learn that shuffled NTT-layer-0 order is not a fault-injection
countermeasure.

**Nothing in this crate implements a fault-attack countermeasure of any kind** — no redundant
recomputation, no error detection on the masked-nonce combination both attacks fault, no infective
countermeasure. `lib-q-ml-dsa` does not even carry an advisory `fault_injection_protection` flag
like `lib-q-aead`/`lib-q-hpke` do.

**MLDSA-F-1 — is a software correction-fault countermeasure worth adding, or is this out of the
library's stated threat model?** Both attacks require physical fault-injection access
(clock/voltage glitching, EM/laser fault injection), which `docs/security.md`'s adversary list
(quantum, unlimited classical compute, timing/power/cache side-channel, memory-safety) does not
name. Whether `lib-q-ml-dsa` should add a detection/redundancy countermeasure — and which class, since
both attacks target the mode NIST selected specifically to blunt physical attacks — is a human
call. Recorded here as an open question, not as a fix in progress: neither paper proposes a
countermeasure to implement. Indexed in `docs/crypto-signoff-register.md`'s fault cross-cutting
section as **MLDSA-F-1**.

## Memory Safety

- [ ] No unsafe code with undefined behavior
- [ ] All array accesses bounds-checked
- [ ] No use-after-free or double-free issues
- [ ] Proper handling of uninitialized memory

## API Security

- [ ] Public API prevents misuse
- [ ] Clear separation between signing and verification keys
- [ ] Signature verification rejects invalid signatures
- [ ] No key recovery from signatures

## Implementation Quality

- [ ] All lints pass (cargo clippy)
- [ ] No compiler warnings
- [ ] Code coverage >80% for critical paths
- [ ] Documentation complete and accurate

## External Validation Requirements

### Timing Analysis
- [ ] Use Dudect or similar for constant-time validation
- [ ] Verify no timing variations based on secret values
- [ ] Test on multiple platforms and architectures

### Side-Channel Testing
- [ ] Power analysis on target hardware
- [ ] Electromagnetic emanation testing
- [ ] Cache timing analysis

### Fuzzing
- [ ] AFL++ or libFuzzer on parsing and signature verification
- [ ] Test with malformed inputs
- [ ] Test with edge case values

### Code Review
- [ ] External cryptographic expert review
- [ ] Security-focused code review
- [ ] Architecture review

### NIST Submission
- [ ] Submit for ACVP validation if seeking certification
- [ ] Pass all NIST test vectors
- [ ] Meet FIPS 204 compliance requirements

## Release Readiness Criteria

Before declaring implementation-complete:

1. All 30+ test suites passing (SIGGEN, mode tests, determinism, NIST comparison)
2. NIST FIPS 204 KAT vectors pass for all parameter sets
3. SIMD-portable byte-for-byte equivalence verified
4. Security audit checklist 100% complete
5. Documentation reviewed and published
6. CI pipeline passing on all platforms
7. External code review completed
8. No high-severity issues in cargo audit

## Automated Checks

The following automated checks are available:

```bash
# Run security audit script
./scripts/security_audit.sh

# Run specific security tests
cargo test --package lib-q-ml-dsa --features "hardened,zeroize" --test hardened_mode_tests

# Run compliance tests
cargo test --package lib-q-ml-dsa --features "fips-mode,acvp" --test fips_mode_tests

# Run determinism tests
cargo test --package lib-q-ml-dsa --features "simd256,random,acvp" --test determinism

# Run NIST KAT tests (vectors under `tests/kats/`)
cargo test --package lib-q-ml-dsa --features "mldsa44,mldsa65,mldsa87,std" --test nistkats
```
