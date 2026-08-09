# Known answer tests (KAT) and FN-DSA alignment (FIPS 206 not yet published)

## Normative reference

**FIPS 206 has not been published.** There is no finalized standard, and no public draft, defining wire formats, `hash_to_point`, or domain separation for FN-DSA today. This crate's wire formats, `hash_to_point`, and domain separation instead follow the pre-standardization FN-DSA / Falcon reference specification. When NIST publishes FIPS 206 (and once NIST or the CAVP program publishes official FN-DSA test vectors — ACVP sample files or `.rsp` fixtures), this implementation should be diffed against the finalized text and checked against those vectors on each release that touches signing, verification, or serialization.

## External-oracle vectors (the real conformance evidence)

`fn-dsa/tests/upstream_oracle_kat.rs` compares this implementation **byte-for-byte** — separately on `sk`, `vk` and `sig` — against vectors produced by the independently-authored upstream `fn-dsa` crate v0.3.0 (Thomas Pornin), built from the pristine crates.io tarball. The fixtures live in `fn-dsa/tests/kats/` and are registered in the repo-root `kats-manifest.toml` with `origin = "third-party"`; their headers state exactly how they were produced. The oracle driver was validated before use by reproducing upstream's own published `KAT` constant arrays 90/90 in both feature configurations.

Result, measured 2026-08-09:

- **`sk` and `vk` are byte-exact on 90/90 vectors in both feature configurations.** Key pair generation does not diverge from upstream at any degree.
- **`sig` is byte-exact for every vector at `logn >= 7`**, which covers both real parameter sets (`logn = 9` / N=512 and `logn = 10` / N=1024).
- At `logn <= 6` — the `KeyPairGeneratorWeak` toy degrees (N = 4..64), which exist only for testing and carry no security claim — 11 of 90 vectors (`shake256x4`) and 9 of 90 (non-`shake256x4`) have a different signature. The cause is localised: this implementation accepts the *first* candidate produced by the signing rejection loop where upstream rejects it and retries. Both rejection conditions (the `mq::SQBETA` norm bound and `codec::comp_encode`) are identical code in the two trees, so the attempt-0 candidate vectors themselves differ — a floating-point sampler-path difference at very small N. These cases are pinned in `KNOWN_WEAK_DIVERGENCES`, and an entry that starts *agreeing* also fails the test, so the list cannot rot.

This supersedes the claim previously made in `fn-dsa/src/lib.rs` that the in-repo KAT digests differ from upstream because of dependency versions, AVX2 codegen or "compiler optimization differences". The construction is seed-deterministic; that explanation was never available, and measurement shows 160 of the 180 digests do not differ at all.

## In-repository vectors

- The 90+90 `KAT` digest arrays in `fn-dsa/src/lib.rs` are maintained in this repository and are a **regression pin**, not conformance evidence, on their own. (As of the measurement above, 79/90 and 81/90 of them happen to equal upstream's — but that is a measured fact recorded here, not a property the arrays themselves assert.)
- Integration and unit tests under [`fn-dsa`](../fn-dsa/) and [`lib-q-fn-dsa`](../tests/) exercise round-trip sign/verify and regression hashes stored in the codebase.
- The workspace does **not** vendor a CAVP/ACVP `.rsp` corpus — none exists for FN-DSA, because FIPS 206 is unpublished. Add one under `fn-dsa/tests/kats/` when official vectors become available in a redistributable form; the upstream-oracle harness above is the interim substitute, not a replacement for NIST vectors.

## `shake256x4` feature

When the `shake256x4` feature is enabled, internal KAT digests may differ from the upstream reference implementation (see the main [README](../README.md) “SHAKE256x4 Implementation Differences” section). That divergence affects **self-test regression bytes**, not the mathematical validity of signatures under the FN-DSA specification.

## Verification checklist (maintainers)

1. Obtain the **FIPS 206** text and any errata — once NIST publishes it. FIPS 206 is not yet published, so this step is currently not actionable and the steps below run against the pre-standardization reference specification instead.
2. If CAVP FN-DSA vectors are available, add a `cargo test` harness that parses them and compares sign/verify outputs.
3. Re-run `cargo test -p lib-q-fn-dsa-alg` and `cargo test -p lib-q-fn-dsa` with and without `shake256x4` on supported targets.
4. Record any wire-byte changes from earlier drafts in this file and in the changelog.
