//! The BabyBear prime field `F_p`, where `p = 2^31 - 2^27 + 1 = 2013265921`.
//!
//! BabyBear is the unique 31-bit prime with maximal 2-adicity (27), so the existing
//! radix-2 `TwoAdicFriPcs` works natively over it (unlike Mersenne31, whose 2-adicity 1
//! forces a circle-STARK PCS). This crate is a thin `lib-q-stark-monty31` instance: it
//! supplies the BabyBear parameter struct (modulus, Montgomery constants, the 2-adic
//! generator table and 8/16-th root precomputations) and re-exports the resulting field.
//!
//! All numeric constants are DERIVED and VALIDATED by `tools/gen_constants.py`, which
//! cross-checks them against the canonical Plonky3 BabyBear reference values
//! (`MONTY_MU = 0x88000001`, `2^27` generator `= 0x1a427a41`).
//!
//! `no_std` + `alloc` (mirrors `lib-q-stark-monty31`). The default and
//! `wasm32-unknown-unknown` builds use the scalar (`no_packing`) backend; no SIMD.
#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

mod baby_bear;
pub use baby_bear::*;
/// Radix-2 two-adic DFT over BabyBear (`TwoAdicSubgroupDft<BabyBear>`), for the STARK PCS.
/// BabyBear's 2-adicity 27 means the native radix-2 DFT works (unlike Mersenne31's circle DFT).
pub use lib_q_stark_monty31::dft::RecursiveDft;
/// Convenience alias: the BabyBear DFT used by the FRI PCS config.
pub type BabyBearDft = RecursiveDft<BabyBear>;
