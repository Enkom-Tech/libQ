# Recovery policy STARK proof budgets (v0)

Measured from `cargo test --release -p lib-q-zkp recovery_policy_budget_sizes --test recovery_policy_tests -- --ignored --nocapture`.

| Scenario | Keys | Threshold | Envelope bytes | STARK proof bytes | Within 512 KiB |
|----------|------|-----------|----------------|-------------------|----------------|
| Minimal | 2 | 3 | 56,462 | 56,392 | Yes |
| Standard | 5 | 3 | 102,182 | 102,112 | Yes |
| Maximum | 32 | 16 | 151,700 | 151,630 | Yes |

**Notes**

- Envelope = 6-byte header + 58-byte public inputs + 4-byte `proof_len` (LE u32) + STARK proof.
- Wire `proof_len` is **u32** so proofs up to 512 KiB fit the normative envelope cap.
- Regenerate after AIR or FRI parameter changes.
- Normative spec consumers reference this document for budget caps.
