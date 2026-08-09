# Provenance — lib-q-ml-kem/tests/*.json (NIST ACVP ML-KEM vectors)

Both files are genuine NIST ACVP conformance vectors, fetched by LIVE DOWNLOAD from
`github.com/usnistgov/ACVP-Server` at tag `v1.1.0.36` (the same tag already pinned for the
lib-q-ml-dsa ACVP entries in `kats-manifest.toml`) and confirmed byte-for-byte identical
(SHA-256 match, CRLF-normalised) on 2026-08-09.

- `encap-decap.json` <- `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json`
- `key-gen.json` <- `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json`

JSON has no comment syntax, so provenance is recorded here rather than in a file header (see
`scripts/ci_guard_kat_provenance.py` CHECK 5).

## Machine-checked sidecar lines

- `encap-decap.json`: origin=upstream; NIST ACVP-Server v1.1.0.36 ML-KEM-encapDecap-FIPS203 internalProjection.json, byte-for-byte verified 2026-08-09
- `key-gen.json`: origin=upstream; NIST ACVP-Server v1.1.0.36 ML-KEM-keyGen-FIPS203 internalProjection.json, byte-for-byte verified 2026-08-09
