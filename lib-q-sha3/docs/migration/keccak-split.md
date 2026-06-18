# Migration: Keccak digests moved to `lib-q-keccak-digest`

**Audience:** monorepo consumers and any external code that imported raw Keccak types from `lib_q_sha3`.

## Summary

- **Before:** `Keccak224` … `Keccak512`, `Keccak256Full` were at the **crate root** of `lib_q_sha3`.
- **After:** those types are only in **`lib_q_keccak_digest`**. `lib_q_sha3` is NIST-aligned (SHA-3, SHAKE, cSHAKE, TurboSHAKE) and `block_core` for composition.

`lib-q-hash` re-exports both crates; `HashAlgorithm` / `Algorithm` names are unchanged.

## Grep (internal cleanup)

```text
rg "lib_q_sha3::Keccak" 
rg "use lib_q_sha3::\\{[^}]*Keccak"
```

Replace `lib_q_sha3` Keccak imports with `lib_q_keccak_digest` (or use `lib_q_hash` re-exports).

## `lib-q-sha3` test-only / dev

Integration tests that still compare Keccak to SHA-3 use a **dev-dependency** on `lib-q-keccak-digest` from `lib-q-sha3` (no new runtime dependency for normal `lib_q_sha3` users).

## References

- [ADR 001: Keccak vs FIPS-202 surface](../adr/001-keccak-nonfips-surface.md)
- [ADR 002 (follow-up dep graph)](../../lib-q-keccak-digest/docs/adr/002-keccak-digest-dependency-extraction.md)
