# lib-q-hiae

HiAE AEAD for lib-Q (draft-pham-cfrg-hiae-06). **Provisional.**

HiAE is an AES-round AEAD with a 2048-bit state: 256-bit key, 128-bit nonce,
128-bit tag (the draft forbids other tag lengths). It is fast on ARM and x86 at
large message sizes.

**Read `SECURITY.md` before using it.** HiAE is an individual Internet-Draft and its
security model excludes repeated forgery attempts. For a negotiated AES-round
AEAD on a network data plane, use `lib-q-aegis` (AEGIS-256, RFC 10032).

## Usage

```rust
use lib_q_hiae::Hiae;

let key = [0x42u8; 32];
let nonce = [0x24u8; 16]; // unique per key
let mut buf = *b"payload";
let tag = Hiae::encrypt_in_place_detached(&key, &nonce, b"ad", &mut buf)?;
Hiae::decrypt_in_place_detached(&key, &nonce, b"ad", &mut buf, &tag)?;
# Ok::<(), lib_q_hiae::Error>(())
```

`Hiae` also implements `lib_q_core::Aead` and `AeadDecryptSemantic`.

## Backends

The AES round comes from `lib-q-intrinsics` (`aes_round`), shared with
`lib-q-aegis`: hardware AES selected at runtime (`simd`, default), otherwise a
portable constant-time bitsliced round. The state rotation uses the draft's
cycling-index technique (Section 7.1) with literal offsets in 16-block batches.

## Tests

- `tests/hiae_kat.rs`: all eleven draft-06 Appendix A vectors, every backend.
- `tests/backend_equivalence.rs`: hardware vs portable, including the 16-block
  batch boundaries.

## License

Apache-2.0
