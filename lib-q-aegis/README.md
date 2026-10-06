# lib-q-aegis

AEGIS-256 AEAD for lib-Q (RFC 10032, Section 4).

AEGIS-256 is for protocols that negotiate a fast AEAD only when both peers have AES
hardware (x86 AES-NI, ARMv8 AES). It sits next to lib-Q's AES-free default AEAD,
Saturnin, and does not replace it.

| Type | Key | Nonce | Tag |
|------|-----|-------|-----|
| `Aegis256` | 32 B | 32 B | 32 B |
| `Aegis256Tag128` | 32 B | 32 B | 16 B |

## Usage

```rust
use lib_q_aegis::{Aegis256, hardware_aes_available};

// Advertise an AES-round suite only where it is fast.
let offer_aegis = hardware_aes_available();

let key = [0x42u8; 32];
let nonce = [0x24u8; 32]; // unique per key
let mut buf = *b"datagram payload";
let tag = Aegis256::encrypt_in_place_detached(&key, &nonce, b"header", &mut buf)?;
Aegis256::decrypt_in_place_detached(&key, &nonce, b"header", &mut buf, &tag)?;
# Ok::<(), lib_q_aegis::Error>(())
```

Both types also implement `lib_q_core::Aead` and `AeadDecryptSemantic`
(ciphertext is `ct || tag`).

## Backends

The AES round comes from `lib-q-intrinsics` (`aes_round`), shared with `lib-q-hiae`:

- **Hardware** (`simd`, default): `AESENC` on x86/x86_64, `AESE`+`AESMC` on
  aarch64. Selected at runtime; needs `std` for CPU detection.
- **Portable**: a bitsliced AES round (Boyar-Peralta S-box circuit). It is
  constant-time, with no tables and no secret-dependent branches or addresses,
  but slow. Protocols should not negotiate AEGIS-256 on hosts without AES hardware.

All backends produce identical output (`tests/backend_equivalence.rs`).

## Tests

- `tests/aegis256_kat.rs`: RFC 10032 Appendix A.3 (all nine AEGIS-256 vectors,
  128- and 256-bit tags, including the four must-fail vectors) on every backend.
  The Update vector (A.3.1) is a unit test; the AESRound vector (A.1) and the
  S-box circuit (all 256 inputs against FIPS-197) are tested in `lib-q-intrinsics`.
- `tests/backend_equivalence.rs`: hardware vs portable, lengths 0 to 600 and
  several larger sizes.

## Benchmarks

`cargo bench -p lib-q-aegis`

See `SECURITY.md` for the security model.

## License

Apache-2.0
