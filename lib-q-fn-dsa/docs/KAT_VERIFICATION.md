# Known answer tests (KAT) and FN-DSA alignment (FIPS 206 not yet published)

## Normative reference

**FIPS 206 has not been published.** There is no finalized standard, and no public draft, defining wire formats, `hash_to_point`, or domain separation for FN-DSA today. This crate's wire formats, `hash_to_point`, and domain separation instead follow the pre-standardization FN-DSA / Falcon reference specification. When NIST publishes FIPS 206 (and once NIST or the CAVP program publishes official FN-DSA test vectors — ACVP sample files or `.rsp` fixtures), this implementation should be diffed against the finalized text and checked against those vectors on each release that touches signing, verification, or serialization.

## In-repository vectors

- Integration and unit tests under [`fn-dsa`](../fn-dsa/) and [`lib-q-fn-dsa`](../tests/) exercise round-trip sign/verify and regression hashes stored in the codebase.
- The workspace does **not** vendor a full CAVP `.rsp` corpus; add one under `tests/kats/` when official vectors are available in a redistributable form.

## `shake256x4` feature

When the `shake256x4` feature is enabled, internal KAT digests may differ from the upstream reference implementation (see the main [README](../README.md) “SHAKE256x4 Implementation Differences” section). That divergence affects **self-test regression bytes**, not the mathematical validity of signatures under the FN-DSA specification.

## Verification checklist (maintainers)

1. Obtain the **FIPS 206** text and any errata — once NIST publishes it. FIPS 206 is not yet published, so this step is currently not actionable and the steps below run against the pre-standardization reference specification instead.
2. If CAVP FN-DSA vectors are available, add a `cargo test` harness that parses them and compares sign/verify outputs.
3. Re-run `cargo test -p lib-q-fn-dsa-alg` and `cargo test -p lib-q-fn-dsa` with and without `shake256x4` on supported targets.
4. Record any wire-byte changes from earlier drafts in this file and in the changelog.
