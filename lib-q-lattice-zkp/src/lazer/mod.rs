//! Byte-exact ports of LaZer building blocks (BLNS presentation L4, first slice).
//!
//! Target: LaZer <https://github.com/lazer-crypto/lazer> at commit
//! `10eafeca4cd53ff4fc54193dce904dbd0026fefd`, the commit the LaZer README names for the
//! CCS 2024 paper and the one the L1 reproduction (`docs/lazer-blns-parameter-note.md`) pinned.
//!
//! **Scope of this slice.** Only the public-parameter layer of LaZer's BLNS anonymous-credential
//! demo (`python/anon_cred/anon_cred.py`): the AES-256-CTR generator, uniform polynomial-matrix
//! sampling, and the expansion of the blind-signature matrices `AR`, `AM`, `ATAU`. It is checked
//! against vectors that LaZer's own C code produced (`tests/lazer_anon_cred_pp_kat.rs`).
//!
//! Not here, and required before anything can be called a BLNS presentation: the linear-relation
//! prover (`lin-proofs.c`), ABDLOP commitments (`abdlop.c`), the LNP22 proof box (`lnp-tbox.c`,
//! `lnp-quad*.c`), rejection sampling (`rejection.c`), discrete-Gaussian sampling (`grandom.c`),
//! the proof encoder (`coder.c`) and the Falcon-based issuer. Nothing in this module proves or
//! verifies anything; it is RED and awaits human cryptographic review like the rest of the crate.
//!
//! Gated behind the opt-in `lazer-compat` feature because LaZer's generator is AES-256-CTR
//! (`config.h`: `RNG RNG_AES256CTR`), and libQ admits AES-256 only inside reviewed
//! implementations that need it for interoperability (`docs/security.md`).

pub mod anon_cred;
pub mod rng;
pub mod urandom;

pub use anon_cred::{AnonCredPublicParams, anon_cred_public_params};
pub use rng::LazerRng;
pub use urandom::{
    LAZER_DEG, LazerPoly, LazerPolyMat, LazerSampleError, log2mod_of, polymat_urandom, urandom_i64,
};
