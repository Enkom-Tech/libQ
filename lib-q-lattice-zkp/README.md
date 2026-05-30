# lib-q-lattice-zkp

Module-lattice anonymous credentials (BLNS-style). Algebraic lattice relations stay in this crate; the STARK stack in `lib-q-zkp` is not used for credential proofs.

## Wire profile v0

- Frozen profiles: [`src/profile.rs`](src/profile.rs) (`LatticeZkpProfileV0`)
- Canonical encoding: [`src/wire/`](src/wire/) (`lattice_zkp_wire_v0`)
- Byte budgets: PVTN membership ≤ **4096 B**; presentation / token spend ≤ **125 KiB**

## KAT vectors

Fixed-seed interoperability fixtures live under [`tests/vectors/`](tests/vectors/).

Regenerate fixtures:

```bash
cargo test -p lib-q-lattice-zkp kat_regenerate_vectors -- --ignored
```

Verify in CI:

```bash
cargo test -p lib-q-lattice-zkp --test kat_vectors
cargo test -p lib-q --test lattice_zkp_wire_budget_tests
```

Downstream integrators copy the `tests/vectors/` tree into their own conformance corpus and pin a released `lib-q-lattice-zkp` version.

## Status

Sigma protocols, issuer-keyed blind issuance, tokens, nullifiers, and PVTN membership ship on **wire v0** with frozen profiles, compact encodings, exportable KATs, and CI byte-budget gates. Fiat–Shamir uses a QROM committed-first-message transcript; PVTN hides Merkle position and clearance on the wire (see [DESIGN.md](DESIGN.md), [BLIND_ISSUANCE.md](BLIND_ISSUANCE.md)).

Protocol notes: [DESIGN.md](DESIGN.md). Security boundaries: workspace [SECURITY.md](../SECURITY.md).
