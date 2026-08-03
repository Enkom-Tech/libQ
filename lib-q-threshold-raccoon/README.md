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
available. Masks use noise flooding (research-grade).

**Four absences.** Unforgeability under up to `t−1` static corruptions is the *entire* distributed-
signing guarantee — the protocol is abort-only:

- **No identifiable abort.** `aggregate_commitment` rejects a bad round-1 opening with an index-free
  error, and `aggregate` performs no per-party verification of round-3 partials — one corrupt partial
  yields an aggregate that fails `verify` with no indication of who cheated.
- **No accountability.** Round broadcasts are not authenticated, so even a detected fault cannot be
  attributed to a specific party after the fact in a way that resists framing.
- **No robustness.** Any dropout or corrupt signer aborts the run; there is no way to exclude a party
  and continue without a full retry.
- **No proactive refresh.** Shares are static for the life of the key, matching the
  **static**-corruption TS-UF-1 model — a mobile adversary corrupting `t` parties over the key's
  lifetime is out of model.

These are verified properties of **this implementation**, read directly off the code above. This
project has not read the cited Threshold-Raccoon paper (del Pino–Katsumata–Reichle–Takemure, CRYPTO
2024) closely enough to say whether the construction itself lacks them too, or whether this
implementation simply omits properties the construction provides — a reader must not infer either.
The full analysis lives in `LIBQ_API.md` §7 caveat 5 and `SECURITY_ANALYSIS.md`, both **repo-internal
and not part of the published crate** — this section is the summary a crates.io/docs.rs reader
actually gets.

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

**PROVISIONAL**, for controlled evaluation, not production standardization. The four absences above
are the load-bearing caveat for the distributed protocol; see `LIBQ_API.md` and `SECURITY_ANALYSIS.md`
(repo-internal — not packaged with this crate) for the full scheme choice and RED-zone assumptions.
