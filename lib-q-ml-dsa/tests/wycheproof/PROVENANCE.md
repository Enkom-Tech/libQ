# Provenance — lib-q-ml-dsa/tests/wycheproof/*.json (Wycheproof ML-DSA test vectors)

All six files are genuine Wycheproof ML-DSA vectors from `github.com/C2SP/wycheproof` PR #112
(head commit `8e7fa6f87e6993d7b613cf48b46512a32df8084a`, closed but not yet merged at the time this
crate's `README.md` in this same directory was written). Fetched by LIVE DOWNLOAD from that exact
commit on 2026-08-09 and confirmed byte-for-byte identical (SHA-256 match, CRLF-normalised) for
all six files.

JSON has no comment syntax, so provenance is recorded here rather than in a file header (see
`scripts/ci_guard_kat_provenance.py` CHECK 5). See `README.md` in this directory for the
pre-existing (informal) provenance note this sidecar formalises.

## Machine-checked sidecar lines

- `mldsa_44_standard_sign_test.json`: origin=upstream; C2SP/wycheproof PR #112 @ 8e7fa6f87e6993d7b613cf48b46512a32df8084a, byte-for-byte verified 2026-08-09
- `mldsa_44_standard_verify_test.json`: origin=upstream; C2SP/wycheproof PR #112 @ 8e7fa6f87e6993d7b613cf48b46512a32df8084a, byte-for-byte verified 2026-08-09
- `mldsa_65_standard_sign_test.json`: origin=upstream; C2SP/wycheproof PR #112 @ 8e7fa6f87e6993d7b613cf48b46512a32df8084a, byte-for-byte verified 2026-08-09
- `mldsa_65_standard_verify_test.json`: origin=upstream; C2SP/wycheproof PR #112 @ 8e7fa6f87e6993d7b613cf48b46512a32df8084a, byte-for-byte verified 2026-08-09
- `mldsa_87_standard_sign_test.json`: origin=upstream; C2SP/wycheproof PR #112 @ 8e7fa6f87e6993d7b613cf48b46512a32df8084a, byte-for-byte verified 2026-08-09
- `mldsa_87_standard_verify_test.json`: origin=upstream; C2SP/wycheproof PR #112 @ 8e7fa6f87e6993d7b613cf48b46512a32df8084a, byte-for-byte verified 2026-08-09
