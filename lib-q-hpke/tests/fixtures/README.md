# HPKE interoperability fixtures

These files lock **negotiation-level** expectations for post-quantum HPKE profiles defined in
`docs/interoperability.md` and `docs/hpke-architecture.md`. They are consumed by
`tests/interop_fixtures.rs` (requires crate feature `std`).

## Provenance

- **Authoring**: Generated and reviewed in-tree; values correspond to `lib_q_hpke::interop`
  types (`HpkeInteropProfile`, `HpkeCipherSuite`, `HpkeMode`, `HpkePskWireFormat`).
- **Algorithm IDs**: KEM/KDF/AEAD numeric IDs match `HpkeKem::algorithm_id`,
  `HpkeKdf::algorithm_id`, and `HpkeAead::algorithm_id` in `lib-q-hpke` at the commit that added
  each fixture row.
- **Third-party vectors**: When IANA or NIST publishes ML-KEM HPKE test vectors aligned with this
  wire layout, prefer replacing or extending rows here and cite the document ID in this README.

## Optional external interop gate

Downstream CI may run a separate process (container or pinned binary) that implements the same
**RfcStrict_PQ** profile and compare bytes on the wire. That job should be **non-blocking** for forks
that do not ship the reference tool (for example `continue-on-error` or a repository variable).
