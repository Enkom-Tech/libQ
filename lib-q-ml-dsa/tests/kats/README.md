# ML-DSA test vectors

Two groups live here and they are **not** equally strong. `PROVENANCE.md` in this directory is the
authoritative, machine-checked record (CI enforces it via `scripts/ci_guard_kat_provenance.py`
against the repository-root `kats-manifest.toml`); read it before citing either group.

- `acvp-1_1_0_36/` — **genuine NIST ACVP vectors**, byte-for-byte from `usnistgov/ACVP-Server` at
  tag `v1.1.0.36`. Exercised by `tests/acvp.rs`. This is the crate's real conformance evidence.
- `dilithium-py-kats-*.json` — **not NIST vectors, and not generated here.** They are byte-for-byte
  identical to `github.com/cryspen/libcrux` at commit `5c3fc214`, under
  `libcrux-ml-dsa/tests/kats/`, as is `dilithium.py` in this directory. `./generate_kats.py`
  reproduces them but is not where the bytes came from. They were named `nistkats*.json` until
  2026-08-07, which claimed a provenance they never had (card t_71d4f79a). Exercised by
  `tests/nistkats.rs`.

`dilithium.py` descends from <https://github.com/GiacomoPope/dilithium-py/pull/1> — genuinely
third-party — but the FIPS-204-final modifications to it were written by libcrux, and this crate is
a `libcrux-ml-dsa` derivative, so for those algorithm details the cross-check is same-author rather
than independent. Two further measured limits (2026-08-07): the vendored `verify` raises
`NameError` and has never run, so these vectors cover keygen and sign only; and the pre-hashed set
uses the same 256-byte SHAKE-128 pre-hash choice as `src/pre_hash.rs`, so it cannot falsify it.
Evidence for all of this is in `PROVENANCE.md`.
