//! Public parameters of LaZer's BLNS anonymous-credential demo.
//!
//! Reference: LaZer `python/anon_cred/anon_cred.py` lines 14-27 and
//! `python/anon_cred/anon_cred_p1_params.py` (`mod = 12289`, `deg = 64`) at commit
//! `10eafeca4cd53ff4fc54193dce904dbd0026fefd`:
//!
//! ```text
//! BLINDSIGPP = SHAKE128(0x00).digest(32)
//! P1PP       = SHAKE128(0x01).digest(32)
//! P2PP       = SHAKE128(0x02).digest(32)
//! AR   = polymat_t.urandom_static(RING, 8, 16, mod, BLINDSIGPP, 1)
//! AM   = polymat_t.urandom_static(RING, 8,  8, mod, BLINDSIGPP, 2)
//! ATAU = polymat_t.urandom_static(RING, 8,  8, mod, BLINDSIGPP, 3)
//! ```
//!
//! `B1` (the 8x8 identity) is not materialised. `B2` is the issuer's Falcon public key and is
//! not part of this slice.

use lib_q_sha3::{ExtendableOutput, Shake128, Update, XofReader};

use super::urandom::{LazerPolyMat, LazerSampleError, log2mod_of, polymat_urandom};

/// `anon_cred_p1_params.py`: `mod`, the blind-signature ring modulus.
pub const ANON_CRED_MOD: i64 = 12289;

/// `SHAKE128(tag).digest(32)`, as `anon_cred.py` derives its three public seeds.
pub fn anon_cred_seed(tag: u8) -> [u8; 32] {
    let mut h = Shake128::default();
    h.update(&[tag]);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

/// The expanded public parameters of the blind signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonCredPublicParams {
    pub blindsig_seed: [u8; 32],
    pub p1_seed: [u8; 32],
    pub p2_seed: [u8; 32],
    /// 8 x 16
    pub ar: LazerPolyMat,
    /// 8 x 8
    pub am: LazerPolyMat,
    /// 8 x 8
    pub atau: LazerPolyMat,
}

/// Recompute `BLINDSIGPP`, `P1PP`, `P2PP`, `AR`, `AM`, `ATAU` exactly as LaZer does.
pub fn anon_cred_public_params() -> Result<AnonCredPublicParams, LazerSampleError> {
    let blindsig_seed = anon_cred_seed(0x00);
    let log2mod = log2mod_of(ANON_CRED_MOD);
    let ar = polymat_urandom(8, 16, ANON_CRED_MOD, log2mod, &blindsig_seed, 1)?;
    let am = polymat_urandom(8, 8, ANON_CRED_MOD, log2mod, &blindsig_seed, 2)?;
    let atau = polymat_urandom(8, 8, ANON_CRED_MOD, log2mod, &blindsig_seed, 3)?;
    Ok(AnonCredPublicParams {
        blindsig_seed,
        p1_seed: anon_cred_seed(0x01),
        p2_seed: anon_cred_seed(0x02),
        ar,
        am,
        atau,
    })
}
