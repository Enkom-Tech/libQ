/-!
# Byte strings

Shared type used throughout this development. Every construction in `lib-q-saturnin` operates on
`&[u8]` / `Vec<u8>`; we model that as `List UInt8` so that length arguments (fixed-width keys,
nonces, tags; variable-width associated data) match the Rust source directly.
-/

namespace SaturninCTX

/-- A single byte, matching Rust's `u8`. -/
abbrev Byte := UInt8

/-- A byte string, matching Rust's `&[u8]` / `Vec<u8>`. -/
abbrev Bytes := List Byte

end SaturninCTX
