# Security notes: lib-q-hiae (provisional)

## Status

- Individual Internet-Draft (draft-pham-cfrg-hiae-06, expires November 2026).
  Not adopted by the CFRG.
- 256-bit key (about 2^128 post-Grover key search), 128-bit nonce, 128-bit tag
  only; the draft forbids truncation and longer tags.

## Security model caveat

The designers' claims (256-bit key recovery, 128-bit forgery) assume the
adversary cannot make repeated forgery attempts (draft Section 6.1, and the
designers' note in IACR ePrint 2025/1235). Attacks that do use decryption queries
recover the full key with about 2^128 data and 2^129.6 time in the
nonce-respecting setting (ePrint 2025/1180), or 2^130 data and 2^209 time
(ePrint 2025/1203). These are far from practical, but they fall well short of the
256-bit claim, and a network data plane gives every on-path attacker unlimited
decryption queries.

**Do not deploy HiAE where an adversary can submit many forgeries under one key.**
Use `lib-q-aegis` (AEGIS-256, RFC 10032) for negotiated AES-round use.

## Commitment

Key-committing (FROB, CMT-1, CMT-2) only at the 64-bit birthday bound. Not
context-committing (CMT-3).

## Constant-time contract

- Hardware backends (`AESENC`, `AESE`/`AESMC`) are constant-time.
- The portable backend (`lib-q-intrinsics`, `aes_round::soft`) is a bitsliced
  Boolean circuit: no tables, no secret-dependent branches or addresses.
- The state-rotation offset depends only on public lengths, never on secret data.
- Tag comparison is constant-time and runs after the full schedule. On failure the
  output buffer is zeroized and no plaintext is returned. Key staging buffers are
  zeroized and the state is wiped with volatile stores.

## Reporting

See the repository-level `SECURITY.md`.
