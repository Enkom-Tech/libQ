# lib-q-threshold-raccoon (PROVISIONAL)

A post-quantum **lattice threshold signature** whose signing key is exactly the output of
[`lib-q-dkg`](../lib-q-dkg)'s dealerless DKG — closing the field-mismatch gap with the GF(256)
`lib-q-threshold-sig` placeholder.

- **Key:** the group key is a BDLOP commitment `T = commit(s; r)` to a **short** secret `s` (the
  DKG's reconstructed group secret); `r` is short (a sum of ternary constant-term randomness), so `T`
  binds `s` and hides it.
- **Signature:** a Fiat–Shamir proof of knowledge of the short opening `(s, r)` — uniform `R_q` mask
  on the non-short `s`, Gaussian + rejection on the short `r`, verifier norm bound on `z_r`.
  Unforgeability reduces to BDLOP binding + Module-LWE.
- **Co-designed with `lib-q-dkg`:** a `SecretShare` here is byte-identical to a
  `lib_q_dkg::SigningShare`, and `keygen_shares` (centralized reference) matches `dkg_run_honest`'s
  share format — so the dealerless DKG is a drop-in keygen.

## Distributed t-of-n signing

The `threshold` module implements a 3-round distributed protocol (Threshold-Raccoon style) where
**no party reconstructs the key** — each uses only its own share. The Lagrange blowup of per-party
randomness is hidden by **additive zero-sharing** (`Σ_{i∈S} m_i = 0`), which cancels on aggregation
to leave a short, clean response. A single trusted-combine path (`combine_opening` + `sign`) is also
available. Masks use noise flooding (research-grade; see `LIBQ_API.md` §3a/§7).

## Validation

```bash
cargo test -p lib-q-threshold-raccoon --release        # incl. the dealerless-DKG end-to-end test
```

## WASM / fuzz

```bash
cargo build -p lib-q-threshold-raccoon --features wasm --target wasm32-unknown-unknown
cargo +nightly fuzz run signature_decode               # in lib-q-threshold-raccoon/
```

## Status

**PROVISIONAL**, for controlled evaluation, not production standardization. See the `LIBQ_API.md`
contract for the scheme choice and RED-zone assumptions.
