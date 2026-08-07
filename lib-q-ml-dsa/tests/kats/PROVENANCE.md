# Provenance of the ML-DSA KAT vector files in this directory

Machine-checked. `scripts/ci_guard_kat_provenance.py` (CHECK 5) reads the bullet list below and
requires that every registered KAT vector file under this tree that **cannot carry a leading
`#`-comment header** — JSON has no comment syntax at all — appears here exactly once, with an
`origin=` that agrees with `kats-manifest.toml`, and a description long enough to actually say
something. Lines here that name no registered file fail the guard too, so this document cannot
quietly rot. Do not hand-edit a line without updating the manifest entry in the same review.

Why a sidecar rather than a header: adding a `_provenance` key to these files would change their
bytes and therefore the SHA-256 the manifest pins — and it would destroy their byte-for-byte
equality with the upstream distribution, which *is* their provenance evidence.

**What "machine-checked" does and does not mean here** (measured in review, 2026-08-07; the guard's
own docstring carries the same disclosure under CHECK 5's RESIDUAL). The guard checks that a claim
*exists*, is *internally consistent* with `kats-manifest.toml`, and that the file's bytes still hash
to the pinned value. It cannot check that a claim is *true*: it has no network and no ground truth,
so a committer who writes `origin=upstream` here and in the manifest, with a fabricated URL and the
file's own hash copied into `upstream_sha256`, passes. That was verified by planting exactly that
input and observing exit 0. The `origin=upstream` claims below are believable because someone
re-fetched and re-hashed the sources — twice, independently, on 2026-08-07 — not because CI proved
them. Anyone re-verifying should re-fetch the URLs in `kats-manifest.toml`, not re-run the guard.

## The two groups are not equally strong. Read this before citing either.

**`acvp-1_1_0_36/` is genuine NIST conformance data.** Fetched from `usnistgov/ACVP-Server` at tag
`v1.1.0.36` — the tag this directory is named for — and byte-for-byte identical to it. This is the
strongest external evidence this crate has, and it is what `tests/acvp.rs` runs.

**`dilithium-py-kats-*.json` are not NIST vectors, and they are not generated here either.** They
were named `nistkats*.json` until 2026-08-07, which asserted NIST provenance they never had (card
t_71d4f79a); renaming them is why the files moved. What they actually are, established 2026-08-07
by live download rather than by trusting this repo's own gitignored `reference/` copy:

- All six are **byte-for-byte identical to `github.com/cryspen/libcrux` at commit
  `5c3fc214252573b1383ab54528aba3d8c21486a2`** ("Apply domain separation in the right order",
  2024-10-01), under `libcrux-ml-dsa/tests/kats/`. So is `dilithium.py` in this directory
  (`dae8399f307dc81986b4fbe2d19c9f7992533727b23386033714f5e50bbc9b5c`). `./generate_kats.py` can
  reproduce them, but it is not where these bytes came from.
- `dilithium.py` in turn descends from <https://github.com/GiacomoPope/dilithium-py> PR #1
  ("Add changes according to ML-DSA draft standard", head `cc1fd2adee5203fa52b87015229536892990621d`,
  2024-04-09) with modifications.

### How independent is this cross-check, really

Measured 2026-08-07 by diffing the vendored copies against PR #1 at that exact commit. Stated
without inflation in either direction, because both directions are tempting here.

1. **The base is genuinely independent.** Of the eight vendored support files, only `dilithium.py`
   differs from PR #1 in substance; the other seven are `black` reformatting and docstring
   whitespace only (confirmed by docstring-stripped AST comparison), and `requirements.txt` only
   bumps a pin. That base is third-party Python, and comparing a Rust implementation against it is
   a real check.
2. **The modifications are not independent of this crate, and they are the part that matters.**
   Everything separating FIPS 204 final from the IPD draft — domain-separated keygen
   `H(ξ ‖ k ‖ ℓ)`, the `M′ = 0x00 ‖ |ctx| ‖ ctx ‖ M` wrapper, full-`c̃` SampleInBall, and the whole
   `sign_internal` / `verify_internal` / `sign_pre_hashed_shake128` / `verify_pre_hashed` addition
   — was written by libcrux, and `lib-q-ml-dsa` is a `libcrux-ml-dsa` derivative: 59 of its 63
   `src/**.rs` file names are shared with it, and `src/sha3_shim.rs` says in its own doc comment
   that it exists "to eliminate the libcrux dependency". For exactly those algorithm details, the
   "independent implementation" and the code under test have the same author.
3. **The vendored `verify` is broken and has never run.** `Dilithium.verify` and
   `Dilithium.verify_pre_hashed` both end `return self.verify_internal(sk_bytes, m_prime, rnd)`,
   and neither name is bound in either scope, so any call raises `NameError`. `generate_kats.py`
   never calls them. These vectors cross-check keygen and sign only; nothing here has ever
   cross-checked libQ's verifier against another implementation.
4. **The pre-hashed vectors test a shared assumption, so they cannot falsify it.**
   `sign_pre_hashed_shake128` does not exist in PR #1 at all; the libcrux version takes 256
   **bytes** of SHAKE-128 output, and `lib-q-ml-dsa/src/pre_hash.rs` does the same
   (`debug_assert_eq!(output.len(), 256)`). Whether FIPS 204 §5.4 wants 256 bytes or 256 bits is a
   question these files are structurally unable to answer.

None of this is the `lib-q-hqc` pattern that card t_71d4f79a is about — vectors written by the code
under test itself — and it should not be filed as such. But "independent implementation", which is
what `tests/kats/README.md` implied before this pass, overstates it.

## Registered files

- `acvp-1_1_0_36/keygen/prompt.json`: origin=upstream; NIST ACVP ML-DSA-keyGen-FIPS204 prompts, live-downloaded from raw.githubusercontent.com/usnistgov/ACVP-Server at tag v1.1.0.36 and byte-for-byte identical; sha256 c90cd9411b567a17a1e2755693ccd4fa48eeb6875be4ef463ed33e9a23103f25.
- `acvp-1_1_0_36/keygen/expectedResults.json`: origin=upstream; NIST ACVP ML-DSA-keyGen-FIPS204 expected results, same download and tag, byte-for-byte identical; sha256 635a05104f40b9578d4618a4b05308a742d706362655344f22a12d491a58a87f.
- `acvp-1_1_0_36/siggen/prompt.json`: origin=upstream; NIST ACVP ML-DSA-sigGen-FIPS204 prompts, same download and tag, byte-for-byte identical; sha256 da759fd966f267a59327e9597a2a6ecb61d02a2e83584c9f6690d48419448287.
- `acvp-1_1_0_36/siggen/expectedResults.json`: origin=upstream; NIST ACVP ML-DSA-sigGen-FIPS204 expected results, same download and tag, byte-for-byte identical; sha256 1b78baf274be78c76dfefb46362e5fe58bb3a6859db86b3bd126e4cbc7ef3eb8.
- `acvp-1_1_0_36/sigver/prompt.json`: origin=upstream; NIST ACVP ML-DSA-sigVer-FIPS204 prompts, same download and tag, byte-for-byte identical; sha256 69f5327f0525fe9bc085d090214691f97c8cd45ff1d66afbf8263c322fe2602d.
- `acvp-1_1_0_36/sigver/expectedResults.json`: origin=upstream; NIST ACVP ML-DSA-sigVer-FIPS204 expected results, same download and tag, byte-for-byte identical; sha256 73196368b70a5f1b6f9f190c572dd97bb46c20a1e86786a41064a4b80d1ef2e9.
- `dilithium-py-kats-44.json`: origin=upstream; 100 ML-DSA-44 keygen+sign vectors, byte-identical to cryspen/libcrux @ 5c3fc214 libcrux-ml-dsa/tests/kats/nistkats-44.json (live-downloaded, HTTP 200). NOT NIST data; produced by the vendored dilithium-py, whose FIPS-204-final modifications share an author with this crate's lineage — see limit 2 above.
- `dilithium-py-kats-65.json`: origin=upstream; 100 ML-DSA-65 keygen+sign vectors, byte-identical to cryspen/libcrux @ 5c3fc214 libcrux-ml-dsa/tests/kats/nistkats-65.json (live-downloaded, HTTP 200). Same source, same caveats as the ML-DSA-44 file above.
- `dilithium-py-kats-87.json`: origin=upstream; 100 ML-DSA-87 keygen+sign vectors, byte-identical to cryspen/libcrux @ 5c3fc214 libcrux-ml-dsa/tests/kats/nistkats-87.json (live-downloaded, HTTP 200). Same source, same caveats as the ML-DSA-44 file above.
- `dilithium-py-kats-pre-hashed-44.json`: origin=upstream; 100 HashML-DSA-44 (SHAKE-128 pre-hash) vectors, byte-identical to cryspen/libcrux @ 5c3fc214 nistkats_pre_hashed-44.json. The pre-hash path exists in neither dilithium-py PR #1 nor NIST's vectors and shares libQ's 256-BYTE digest choice, so it cannot falsify that choice — see limit 4 above.
- `dilithium-py-kats-pre-hashed-65.json`: origin=upstream; 100 HashML-DSA-65 (SHAKE-128 pre-hash) vectors, byte-identical to cryspen/libcrux @ 5c3fc214 nistkats_pre_hashed-65.json; same libcrux-added pre-hash path and the same shared-assumption caveat as the ML-DSA-44 pre-hashed file.
- `dilithium-py-kats-pre-hashed-87.json`: origin=upstream; 100 HashML-DSA-87 (SHAKE-128 pre-hash) vectors, byte-identical to cryspen/libcrux @ 5c3fc214 nistkats_pre_hashed-87.json; same libcrux-added pre-hash path and the same shared-assumption caveat as the ML-DSA-44 pre-hashed file.

## Not covered here

`requirements.txt` in this directory is a pip pin, not a KAT file; it matches the guard's scanned
`.txt` extension and is listed in `[scan].exclude` in `kats-manifest.toml` for that reason. The
`.py` files are the generator, not vectors, and are outside the guard's scanned extensions —
`dilithium.py` in particular is vendored, not written here, and is unverified by this guard.
