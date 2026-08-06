# lib-q-mayo

MAYO multivariate signature scheme — NIST additional-signatures **round 2**,
MAYO_2 parameter set (security level 1).

| | bytes |
|---|---|
| signing key (seed) | 24 |
| verification key | 4912 |
| signature (fixed) | 186 |

Hand-written in Rust from the round-2 MAYO specification and validated
byte-for-byte against the authors' reference implementation
([PQCMayo/MAYO-C](https://github.com/PQCMayo/MAYO-C)) via the official
round-2 KAT file (`PQCsignKAT_24_MAYO_2.rsp`, all 100 vectors: keygen, sign,
verify).

## Status

**Experimental / pre-standard.** MAYO is a round-2 candidate in NIST's
additional-signatures on-ramp, not a finished standard. Parameters may still
change between rounds; downstream protocols should pin suite identifiers to
"MAYO round-2 parameters" and retire the suite rather than swap parameters in
place. NIST's round-3 tweaked submissions are due 2026-08-14 — parameters,
and possibly the underlying field characteristic, may change again shortly
after this crate's parameter choice was made.

## Security notes

This crate ships **MAYO_2 only** (NIST security level 1). Two things worth
knowing before pinning on it. Each figure below is quoted from, and
attributed to, the document it comes from — the round-2 MAYO specification
([`mayo-spec-round2.pdf`](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/spec-files/mayo-spec-round2.pdf)),
[NIST IR 8610](https://doi.org/10.6028/NIST.IR.8610), and
[ePrint 2025/1143](https://eprint.iacr.org/2025/1143):

- **MAYO_2 is the parameter set NIST's own report singles out.** NIST IR
  8610 §3.12 says the characteristic-2 "wedge" attack's impact "was
  significant for the MAYO2 parameters that targeted security category 1,
  resulting in a deficiency of roughly 30 bits". The attack paper
  (ePrint 2025/1143, which is IR 8610's own citation for that sentence)
  reports a 28-bit reduction for MAYO_2; whether the two numbers denote the
  same quantity has not been checked against the paper's table here, so
  treat "28" and "roughly 30" as two statements of the same result rather
  than one refining the other. Separately, and *before* the wedge attack is
  applied at all, the designers' own Table 5.1 claw-finding row for MAYO_2
  is 2^141 bit operations, against the 2^143 bar the same chapter states
  for NIST level 1 — the spec argues this still reaches level 1 "since we
  have ignored significant overheads" in the estimate. None of this is a
  claim that MAYO_2 is broken; it is the margin a reviewer evaluating this
  crate will want to see stated rather than discovered.
- **The EUF-CMA proof is in the classical random-oracle model**, under the
  standard OV assumption plus a newer multi-target "whipped-MQ" assumption
  that the designers flag themselves: "Since one of the assumptions is
  relatively new, the security reduction in this chapter does not provide a
  hard guarantee for the security of the scheme by itself." The same
  chapter's §5.3 bounds how far the proof carries: the rejection-sampling
  leakage factor is `(1 - Qs·B)`, and for MAYO_2 the spec puts `B ≈ 2^-20`,
  "which means that as long as the adversary sees fewer than [...] 2^19
  signatures [...] the leakage provably does not degrade security much"
  (the companion 2^11 figure in that sentence is for MAYO1/MAYO3/MAYO5,
  whose `B ≈ 2^-12`). Past ~2^19 signatures under one MAYO_2 key the proof
  stops guaranteeing anything — the spec notes no attack is known that
  exploits this — so a long-lived signing identity wants a rotation policy
  that stays inside that count. This crate does not enforce one.

Track NIST IR 8610 and the round-3 MAYO submission (due 2026-08-14) for
whether either figure changes.

## Usage

```rust
use lib_q_mayo::mayo_2;

// randomness in, keys/signatures out — supply CSPRNG output in production
let keypair = mayo_2::generate_key_pair(key_seed);            // [u8; 24]
let signature = mayo_2::sign(&keypair.signing_key, msg, r)?;  // r: [u8; 24]
mayo_2::verify(&keypair.verification_key, msg, &signature)?;
```

Signing is hedged per the round-2 spec: the salt is derived from
`H(msg) || R || seed_sk`, so all-zero `R` gives deterministic signing while
fresh `R` gives the randomized mode (used by the KATs).

## Constant-time posture

- Integer-only GF(16) arithmetic — no lookup tables (nibble-sliced `u64`
  kernels, carryless multiply).
- Constant-time comparison masks pass through `core::hint::black_box`
  optimizer barriers (the Rust analogue of the reference implementation's
  volatile blockers), so the compiler cannot lower them back to branches.
- The linear-system solve is the reference implementation's constant-time
  echelon form: secret pivot rows are gathered and written back with masks;
  back-substitution never indexes memory by secret values.
- The only secret-derived branch in signing is the public "system unsolvable
  → restart" predicate of the retry loop, matching the reference
  implementation's explicit declassification.
- Secret material (expanded key, vinegar vectors, solver state) is wiped on
  exit; `Mayo2SigningKey` zeroizes on drop and `Debug`-prints `[REDACTED]`.
- A dudect-style wall-clock timing smoke for `sign` runs behind
  `--features hardened,dudect-smoke-tests`, comparing two fixed keys' signing
  timings as two separately-labeled sample classes (never interleaved into
  one sequence) via `lib-q-sca-test`'s two-class Welch-*t* gate, and reports
  its pass/fail from a single fixed-size measurement rather than a
  best-of-*N* retry. It is a regression tripwire, not a proof: being a
  wall-clock measurement, its resolving power is bounded by host noise —
  measured on one loaded dev box it resolves a key-dependent separation of
  roughly 4 % of signing time, and anything smaller passes. Read a green run
  as "no gross timing regression", never as "constant-time".

## Features

- `std` *(default)* — standard library.
- `mayo2` *(default)* — the MAYO_2 parameter set.
- `zeroize` / `hardened` — zeroize-backed secret wiping (constant-time masks
  and barriers are always on, not feature-gated).
- `no_std`: build with `--no-default-features --features mayo2`
  (wasm32-unknown-unknown supported).

## Internals

`P1`/`P2` expand from the 16-byte pk seed via AES-128-CTR (zero IV,
big-endian counter); everything else (secret-key expansion, message digest,
target vector, vinegar sampling, salt) uses SHAKE256 — exactly as the
round-2 spec mandates. The packed m-vector representation (16 GF(16)
coefficients per `u64` limb) is byte-exact with the wire encoding for MAYO_2
because `m = 64` is a multiple of 16.
