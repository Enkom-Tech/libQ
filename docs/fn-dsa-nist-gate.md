# FN-DSA NIST publication gate

## Current state

`lib-q-fn-dsa` implements FN-DSA per **FIPS 206** (FN-DSA / Falcon family). The workspace tracks NIST parameter sets FN-DSA-512 and FN-DSA-1024 with integration tests and documented KAT verification (`lib-q-fn-dsa/docs/KAT_VERIFICATION.md`).

## NIST gate

Final FN-DSA FIPS publication may introduce normative errata or vector updates. Before claiming full NIST alignment for production use:

1. Diff the published FIPS 206 text against the implementation's transcript and encoding paths.
2. Refresh NIST KAT corpora under `lib-q-fn-dsa/tests/` and re-run `cargo test -p lib-q-fn-dsa`.
3. Record the verified FIPS revision in `CHANGELOG.md` and release notes.

## Verification command

```bash
cargo test -p lib-q-fn-dsa --verbose
```

See also `lib-q-fn-dsa/docs/KAT_VERIFICATION.md` for vector import paths.
