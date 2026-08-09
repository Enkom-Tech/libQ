# Provenance — lib-q-hpke/tests/fixtures/negotiated_params_strict_pq_base.json

Self-generated: `tests/interop_fixtures.rs` line 1 documents this as a "Frozen JSON fixture for
HPKE interoperability (negotiation and provider wiring)" — it pins lib-q-hpke's own negotiated
suite-parameter output for a fixed local/peer preference configuration, not any external corpus.

Renamed 2026-08-09 from `negotiated_params_rfc_strict_pq_base.json`: the old path contained "rfc"
(from the `RfcStrictPq` profile name) which the provenance guard's CHECK 4 naming ban correctly
refuses for a non-upstream entry — a self-generated file must not sit at a path implying upstream
(RFC) provenance. The file's content and origin are unchanged; only the name changed.

## Machine-checked sidecar lines

- `negotiated_params_strict_pq_base.json`: origin=self-generated; frozen fixture pinning lib-q-hpke's own strict-PQ suite negotiation output (formerly `negotiated_params_rfc_strict_pq_base.json`), per tests/interop_fixtures.rs
