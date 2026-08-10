# Upstream HQC reference vectors

External conformance oracle for `lib-q-hqc`. These are the HQC designers' own intermediate-value
dumps, vendored byte-for-byte and unmodified from the official implementation at
<https://gitlab.com/pqc-hqc/hqc> (v5.0.0, 2025-08-22), paths `kats/ref/hqc-{1,3,5}/`.

## Why these files and not the `.rsp` KATs sitting beside them upstream

The same upstream tree ships `kats/ref/hqc-N/PQCkemKAT_*.rsp`. Those are **not** usable as a
conformance oracle for this crate, and no amount of work makes them usable.

They are NIST-harness output: the 48-byte `seed` printed in the file is fed to AES-CTR-DRBG, and
the algorithm's randomness is drawn from the DRBG rather than from the seed itself. `lib-q-hqc`
takes the seed directly as `seedKEM` and expands it with SHAKE256, which is the path the
specification describes. The two never agree by construction.

That is demonstrable from upstream's own files, without reference to this crate: the `.rsp`
count=0 record does **not** contain the `seed_ek`, `seed_dk` or `s` values printed in the
`intermediates_values` file generated from the same seed, at any offset. Upstream's two files
disagree with each other, exactly as the DRBG indirection predicts.

`intermediates_values` dumps the direct-seed derivation, so it *is* comparable, and it exposes far
more than a `.rsp` does: `seed_ek`, `seed_dk`, `h`, `x`, `y`, `s` for keygen, plus `m`, `salt`,
`theta`, `r1`, `r2`, `e`, `c_kem` and `m_prime` for encapsulation and decapsulation.

## What they caught

These vectors are the reason card `t_62273504` exists. Compared against them, `lib-q-hqc` was
found to derive `seed_ek` and `seed_dk` correctly and expand `h` correctly, while producing `x`
and `y` at the wrong positions (correct Hamming weight, wrong support). That localised three
distinct bugs in fixed-weight sampling, all fixed at `113377f`:

1. the 24-bit candidate was assembled big-endian instead of little-endian,
2. `xof_get_bytes` discarded stream bytes on non-8-byte-aligned requests instead of squeezing
   exactly,
3. draws were buffered per-vector instead of taking exactly 3 bytes per attempt.

Before that fix, every HQC keypair this crate produced differed from the reference's. These files
are what makes a regression of that class impossible to land silently, which the self-generated
regression pins in `../regression-pins/` structurally could not do: a pin compares an
implementation against itself.

## Integrity

`sha256` equals `upstream_sha256` in `kats-manifest.toml` for all three, because they are vendored
unmodified. Any edit to these files is a provenance violation, not a maintenance action: they are
someone else's output and their value is precisely that we did not produce them. If they need
updating for a new upstream release, replace them wholesale from upstream and update both hashes
in the same change.

- `hqc-1/intermediates_values`: origin=upstream; vendored byte-for-byte from gitlab.com/pqc-hqc/hqc v5.0.0 (2025-08-22) `kats/ref/hqc-1/intermediates_values`; sha256 in kats-manifest.toml equals upstream_sha256 because the bytes are unmodified.
- `hqc-3/intermediates_values`: origin=upstream; vendored byte-for-byte from gitlab.com/pqc-hqc/hqc v5.0.0 (2025-08-22) `kats/ref/hqc-3/intermediates_values`; sha256 in kats-manifest.toml equals upstream_sha256 because the bytes are unmodified.
- `hqc-5/intermediates_values`: origin=upstream; vendored byte-for-byte from gitlab.com/pqc-hqc/hqc v5.0.0 (2025-08-22) `kats/ref/hqc-5/intermediates_values`; sha256 in kats-manifest.toml equals upstream_sha256 because the bytes are unmodified.
