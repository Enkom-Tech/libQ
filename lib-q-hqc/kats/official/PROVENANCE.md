# HQC KEM KAT provenance

## Source

| Artifact | Origin |
|----------|--------|
| `hqc-*/PQCkemKAT_*.req` | NIST PQC KEM KAT request files (PQCgenKAT seed chain) |
| `hqc-*/PQCkemKAT_*.rsp` | Response vectors for the **Oct 2024 / current** parameter set (`PUBLIC_KEY_BYTES` = 2241 / 4522 / 7245, `seed_ek ‖ s` PK, SHA3 `H`=1 / `G`=0, XOF KEM `seedKEM` flow) |

Specification alignment: [HQC specifications (2025-08-22)](https://pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf), parameter table on [pqc-hqc.org](https://pqc-hqc.org/).

## RNG path (A1)

Keygen and encaps in `lib-q-hqc` use the **SHAKE256 XOF / PRNG** path (`keygen_with_seed`, `encapsulate_with_m_salt`), not NIST AES-256-CTR-DRBG over the record seed. Empirical gate: byte-exact `pk`/`ct`/`ss`/`sk` against the `.rsp` files below for all parameter sets.

Older NIST submission `.rsp` files used a **2249-byte** public key layout; this tree uses the Oct 2024 **2241-byte** `pk` wire format.

## SHA-256

| File | SHA-256 |
|------|---------|
| `hqc-1/PQCkemKAT_2321.req` | `801445dbdafdbc231fb585f28a155ad34767fa1f7467c5087c0a1fdd18270e98` |
| `hqc-1/PQCkemKAT_2321.rsp` | `c145005626ee681c9a5d9ce0ffc589a243d69b90c0a1ca5945568d514e5a8fd1` |
| `hqc-3/PQCkemKAT_4602.req` | `6ae569cc0da65d85b87b4c902ce7f42a89038dcbb1628af2b0e3a9c6f1a0cb5f` |
| `hqc-3/PQCkemKAT_4602.rsp` | `b831f65ee0068bc303f30dc0b7ded8b26b0537b7385df72515444d0e1e9e6944` |
| `hqc-5/PQCkemKAT_7333.req` | `6ae569cc0da65d85b87b4c902ce7f42a89038dcbb1628af2b0e3a9c6f1a0cb5f` |
| `hqc-5/PQCkemKAT_7333.rsp` | `e27cb44902bc68b45db21f00e0b194a95266db1458813f88cb3fb0caef67649a` |

The `.req` files for HQC-192 and HQC-256 share the same seed chain as the NIST generator template (identical file hash); outputs differ by parameter set in the `.rsp` files.

## Regeneration

Maintainers may refresh `.rsp` files (not CI-gated) with:

```bash
cargo test -p lib-q-hqc --release --features "alloc,hqc,random" \
  --test nist_kem_kat regenerate_official_kat_rsp_files -- --ignored
```
