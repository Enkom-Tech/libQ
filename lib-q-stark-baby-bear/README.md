# lib-q-stark-baby-bear

The **BabyBear** prime field `F_p`, where `p = 2^31 - 2^27 + 1 = 2013265921 = 0x78000001`,
implemented as a thin [`lib-q-stark-monty31`](../lib-q-stark-monty31) instance.

BabyBear is the unique 31-bit prime with **maximal 2-adicity (27)**, so the existing radix-2
`TwoAdicFriPcs` works natively over it (unlike Mersenne31, whose 2-adicity 1 forces a
circle-STARK PCS). This crate supplies only the BabyBear parameter struct — modulus, Montgomery
constants, the 2-adic generator table and the 8/16-th root precomputations — and re-exports the
resulting field plus its radix-2 two-adic DFT.

This field is the **base field for the Arm B membership STARK** (BabyBear + Poseidon2) in
[`lib-q-zkp`](../lib-q-zkp).

> **Status: RED / experimental.** The Arm B membership construction is **not** proven sound, not
> audited, and not production-ready — it is pending human cryptographer sign-off (ADR-113 freeze
> gate). It is **not peer-reviewed**: an IACR ePrint submission was desk-rejected; a self-published
> preprint + open-source reproduction artifact accompany it. With the **quintic `F_{p⁵}` challenge
> field** (this crate's `BinomialExtensionData<5>`), Arm B reaches **128-bit post-quantum at the
> PCS/commitment layer** (binding on the SHAKE256 Merkle commitment) — the field layer this crate
> provides is what lifted it there from the original degree-4 config (~116-bit conjectured / ~99-bit
> provable). The AIR/Poseidon2 round-count soundness obligations remain unverified, so this is not a
> complete soundness proof. This crate is the field layer only; the soundness caveats live with the
> proof system. Use it without hiding residual implementation risk.

## What it provides

- `BabyBear` — the field type (`MontyField31<BabyBearParameters>`).
- `BabyBearParameters` — the parameter marker (modulus, Montgomery `MONTY_MU`, multiplicative
  generator 31, two-adicity 27).
- `RecursiveDft<BabyBear>` (re-exported) and the `BabyBearDft` alias — the radix-2 two-adic DFT
  used by the FRI PCS config.
- Degree-4 binomial extension `F_{p^4} = F_p[x]/(x^4 - 11)` (~124-bit FRI challenge field) and
  degree-5 binomial extension `F_{p^5} = F_p[x]/(x^5 - 2)` (~155-bit challenge field for the
  Arm B config), available via `lib_q_stark_field::extension::BinomialExtensionField`.

All numeric constants are **derived and validated** by `tools/gen_constants.py` (and
`tools/gen_quintic_constants.py` for the quintic), cross-checked against the canonical Plonky3
BabyBear reference values.

## Features

| Feature  | Default | Description                                                        |
| -------- | :-----: | ------------------------------------------------------------------ |
| `alloc`  |   yes   | `no_std` + `alloc` (mirrors `lib-q-stark-monty31`).                |
| `std`    |         | Enables `alloc`; standard-library build.                           |
| `no_std` |         | Bare-metal marker.                                                  |

The crate is `#![no_std]` and `#![deny(unsafe_code)]`. The default and
`wasm32-unknown-unknown` builds use the scalar (`no_packing`) backend (no SIMD); under
`+avx2` / `+neon` / `+avx512` the underlying `lib-q-stark-monty31` provides vectorized packing
on every target architecture.

## License

See the workspace root for license details.
