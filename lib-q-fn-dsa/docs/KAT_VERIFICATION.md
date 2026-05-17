# Known answer tests (KAT) and FIPS 206 alignment

## Normative reference

Wire formats, `hash_to_point`, and domain separation are defined by **NIST FIPS 206**. When NIST or the CAVP program publishes official FN-DSA test vectors (ACVP sample files or `.rsp` fixtures), this implementation should be checked against them on each release that touches signing, verification, or serialization.

## In-repository vectors

- Integration and unit tests under [`fn-dsa`](../fn-dsa/) and [`lib-q-fn-dsa`](../tests/) exercise round-trip sign/verify and regression hashes stored in the codebase.
- The workspace does **not** vendor a full CAVP `.rsp` corpus; add one under `tests/kats/` when official vectors are available in a redistributable form.

## `shake256x4` feature

When the `shake256x4` feature is enabled, internal KAT digests may differ from the upstream reference implementation (see the main [README](../README.md) “SHAKE256x4 Implementation Differences” section). That divergence affects **self-test regression bytes**, not the mathematical validity of signatures under FIPS 206.

## Verification checklist (maintainers)

1. Obtain the latest **FIPS 206** PDF and any published errata.
2. If CAVP FN-DSA vectors are available, add a `cargo test` harness that parses them and compares sign/verify outputs.
3. Re-run `cargo test -p fn-dsa` and `cargo test -p lib-q-fn-dsa` with and without `shake256x4` on supported targets.
4. Record any wire-byte changes from earlier drafts in this file and in the changelog.
