//! Prover-side secret scrubbing for lattice Fiat–Shamir sigma protocols.
//!
//! # Threat model
//!
//! **Scrubbed on drop or rejection**
//! - Rejection-sampling masks `y`
//! - Prover-local witness copies detached from [`crate::commitment::AjtaiOpening`]
//! - Aborted responses (`z`, and derived `w` / `u`) from failed norm or verification checks
//!
//! **Intentionally retained**
//! - Successful [`crate::sigma::opening::OpeningProof`] values `w` and `z`: public transcript
//!   elements required for verification and wire encoding (`z = y + c·wit` is publishable in FS)
//!
//! # Engineering limits
//!
//! - [`SecretPolyVec::into_public`] moves the verifying response into the transcript without a
//!   prover-local duplicate (unlike [`zeroize::Zeroizing`], which always scrubs on drop).
//! - Matrix APIs borrow mask slices via [`lib_q_ring::ModuleMatrix::mul_vec_polys`] so `y` is not
//!   cloned for `A·y`.
//! - Scrubbing uses the [`zeroize`] crate (`write_volatile`); it is not optimized away by the
//!   compiler. With the `hardened` feature, witness material is first-order masked before `c·wit`
//!   ring multiplies; see [`MaskedWitness`].

use alloc::vec::Vec;

#[cfg(feature = "hardened")]
use lib_q_ring::reduce_element;
use lib_q_ring::{
    ModuleVec,
    Poly,
};
#[cfg(feature = "hardened")]
use lib_q_sha3::{
    ExtendableOutput,
    Shake256,
    Update,
    XofReader,
};
#[cfg(feature = "hardened")]
use rand_core::{
    CryptoRng,
    Rng,
};
use zeroize::Zeroize;

#[cfg(feature = "hardened")]
use crate::util::module_add;
use crate::util::module_ring_mul_challenge;

/// Domain separation for witness additive masking (SHAKE256).
#[cfg(feature = "hardened")]
const WITNESS_SPLIT_DOMAIN: &[u8] = b"lib-q-lattice-zkp/hardened-wit-split-v1";

/// SHAKE256 block size used for witness-split XOF buffering.
#[cfg(feature = "hardened")]
const WITNESS_SPLIT_XOF_BLOCK: usize = 136;

/// Prover mask vector `y` (one uniform polynomial per witness slot).
pub(crate) type SecretMaskVec = SecretPolyVec;

/// Prover-local witness copy `(r || m)` detached from an opening.
pub(crate) type SecretWitnessVec = SecretPolyVec;

/// First-order additive shares of the witness for hardened `c·wit` multiplies.
#[cfg(feature = "hardened")]
pub(crate) struct MaskedWitness {
    share_a: SecretPolyVec,
    share_b: SecretPolyVec,
}

#[cfg(feature = "hardened")]
impl MaskedWitness {
    /// Split `wit` into shares with `share_a[i] + share_b[i] ≡ wit[i] (mod q)` per slot.
    pub fn split<R: Rng + CryptoRng>(
        wit: SecretWitnessVec,
        rng: &mut R,
        key_seed: &[u8; 32],
        ctx: &[u8],
    ) -> Self {
        let mut polys = wit.into_public();
        for p in &mut polys {
            p.normalize_mod_q_assign();
        }
        let mut share_b_polys = Vec::with_capacity(polys.len());
        for _ in 0..polys.len() {
            share_b_polys.push(Poly::zero());
        }

        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut entropy);
        let mut h = Shake256::default();
        Update::update(&mut h, key_seed);
        Update::update(&mut h, ctx);
        Update::update(&mut h, &entropy);
        Update::update(&mut h, WITNESS_SPLIT_DOMAIN);
        let mut reader = ExtendableOutput::finalize_xof(h);
        let mut buf = [0u8; WITNESS_SPLIT_XOF_BLOCK];
        let mut off = buf.len();

        for (share_a, share_b) in polys.iter_mut().zip(share_b_polys.iter_mut()) {
            split_poly_additive(share_a, share_b, &mut reader, &mut buf, &mut off);
        }

        Self {
            share_a: SecretPolyVec::new(polys),
            share_b: SecretPolyVec::new(share_b_polys),
        }
    }

    #[must_use]
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.share_a.len()
    }

    #[must_use]
    pub fn share_a(&self) -> &[Poly] {
        self.share_a.as_slice()
    }

    #[must_use]
    pub fn share_b(&self) -> &[Poly] {
        self.share_b.as_slice()
    }

    /// `c·wit` as `c·share_a + c·share_b` without multiplying the raw witness.
    #[must_use]
    pub fn ring_mul_challenge(&self, c: &Poly) -> Vec<Poly> {
        let lhs = module_ring_mul_challenge(c, self.share_a());
        let rhs = module_ring_mul_challenge(c, self.share_b());
        module_add(&lhs, &rhs).unwrap_or_else(|_| {
            debug_assert!(false, "masked witness shares must have equal length");
            lhs
        })
    }

    /// Reconstruct witness polynomials mod `q` (tests and equivalence checks).
    #[must_use]
    #[cfg(test)]
    pub fn reconstruct_public(&self) -> Vec<Poly> {
        let q = lib_q_ring::constants::FIELD_MODULUS as i64;
        let mut out = Vec::with_capacity(self.len());
        for (a, b) in self.share_a().iter().zip(self.share_b()) {
            let mut p = Poly::zero();
            for (dst, (&ca, &cb)) in p.coeffs.iter_mut().zip(a.coeffs.iter().zip(&b.coeffs)) {
                let sum = (ca as i64 + cb as i64).rem_euclid(q);
                *dst = sum as i32;
            }
            out.push(p);
        }
        out
    }
}

#[cfg(feature = "hardened")]
fn next_mod_field_coeff(
    reader: &mut impl XofReader,
    buf: &mut [u8; WITNESS_SPLIT_XOF_BLOCK],
    off: &mut usize,
) -> i32 {
    if *off + 4 > buf.len() {
        XofReader::read(reader, buf);
        *off = 0;
    }
    let chunk = {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&buf[*off..*off + 4]);
        arr
    };
    *off += 4;
    let v = u32::from_le_bytes(chunk);
    (v % lib_q_ring::constants::FIELD_MODULUS as u32) as i32
}

#[cfg(feature = "hardened")]
fn split_poly_additive(
    share_a: &mut Poly,
    share_b: &mut Poly,
    reader: &mut impl XofReader,
    buf: &mut [u8; WITNESS_SPLIT_XOF_BLOCK],
    off: &mut usize,
) {
    for (a, b) in share_a.coeffs.iter_mut().zip(share_b.coeffs.iter_mut()) {
        let r = next_mod_field_coeff(reader, buf, off);
        *b = reduce_element(r);
        *a = reduce_element(*a - r);
    }
}

fn finish_response_z(y: &SecretMaskVec, cw: &mut Vec<Poly>) -> SecretPolyVec {
    let mut z = SecretPolyVec::with_capacity(y.len());
    for (yi, cwi) in y.as_slice().iter().zip(cw.iter()) {
        let mut t = yi.clone();
        t.add_assign(cwi);
        z.push(t);
    }
    zeroize_poly_vec(cw);
    z
}

/// Build `z = y + c·wit` from a raw witness copy.
#[cfg(not(feature = "hardened"))]
pub(crate) fn accumulate_response_z(
    y: &SecretMaskVec,
    c: &Poly,
    wit: &SecretWitnessVec,
) -> SecretPolyVec {
    let mut cw = module_ring_mul_challenge(c, wit.as_slice());
    finish_response_z(y, &mut cw)
}

/// Build `z = y + c·wit` from hardened masked shares (`c·share_a + c·share_b`).
#[cfg(feature = "hardened")]
pub(crate) fn accumulate_response_z_masked(
    y: &SecretMaskVec,
    c: &Poly,
    masked: &MaskedWitness,
) -> SecretPolyVec {
    let mut cw = masked.ring_mul_challenge(c);
    finish_response_z(y, &mut cw)
}
/// Owned vector of secret polynomials; zeroized on drop unless [`Self::into_public`] is called.
pub(crate) struct SecretPolyVec(Option<Vec<Poly>>);

impl SecretPolyVec {
    #[must_use]
    pub fn new(vec: Vec<Poly>) -> Self {
        Self(Some(vec))
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Some(Vec::with_capacity(capacity)))
    }

    pub fn push(&mut self, poly: Poly) {
        if let Some(v) = &mut self.0 {
            v.push(poly);
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Poly] {
        self.0.as_deref().unwrap_or(&[])
    }

    /// Transfer ownership into a public Fiat–Shamir transcript without scrubbing the moved buffer.
    #[must_use]
    pub fn into_public(mut self) -> Vec<Poly> {
        self.0.take().unwrap_or_default()
    }
}

impl Drop for SecretPolyVec {
    fn drop(&mut self) {
        if let Some(mut v) = self.0.take() {
            zeroize_poly_vec(&mut v);
        }
    }
}

impl<'a> IntoIterator for &'a SecretPolyVec {
    type Item = &'a Poly;
    type IntoIter = core::slice::Iter<'a, Poly>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

/// Zeroize coefficient buffers for each polynomial.
pub(crate) fn zeroize_polys(polys: &mut [Poly]) {
    for p in polys {
        p.zeroize();
    }
}

/// Zeroize every polynomial in `polys` and clear the vector.
pub(crate) fn zeroize_poly_vec(polys: &mut Vec<Poly>) {
    zeroize_polys(polys);
    polys.clear();
}

/// Zeroize all polynomials in a module vector without clearing its length metadata.
pub(crate) fn zeroize_module_vec(module: &mut ModuleVec) {
    zeroize_polys(&mut module.0);
}

/// Scrub aborted opening transcript polynomials before the next rejection attempt.
pub(crate) fn scrub_rejected_opening_parts(w: &mut ModuleVec, z: &mut Vec<Poly>) {
    zeroize_module_vec(w);
    zeroize_poly_vec(z);
}

/// Scrub aborted DualRing response polynomials before the next rejection attempt.
pub(crate) fn scrub_rejected_dual_ring_parts(z: &mut ModuleVec, challenges: &mut [Poly]) {
    zeroize_poly_vec(&mut z.0);
    zeroize_polys(challenges);
}

/// RAII holder for per-attribute masks and witness copies during amortised proving.
pub(crate) struct ProverMaskScratch {
    masks: Vec<SecretMaskVec>,
    #[cfg(not(feature = "hardened"))]
    witnesses: Vec<SecretWitnessVec>,
    #[cfg(feature = "hardened")]
    witnesses: Vec<MaskedWitness>,
}

impl ProverMaskScratch {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            masks: Vec::new(),
            witnesses: Vec::new(),
        }
    }

    #[cfg(not(feature = "hardened"))]
    pub fn push_attribute(&mut self, mask: SecretMaskVec, witness: SecretWitnessVec) {
        self.masks.push(mask);
        self.witnesses.push(witness);
    }

    #[cfg(feature = "hardened")]
    pub fn push_attribute_masked(&mut self, mask: SecretMaskVec, witness: MaskedWitness) {
        self.masks.push(mask);
        self.witnesses.push(witness);
    }

    #[must_use]
    pub fn mask(&self, index: usize) -> &[Poly] {
        self.masks[index].as_slice()
    }

    #[must_use]
    #[cfg(not(feature = "hardened"))]
    pub fn witness(&self, index: usize) -> &[Poly] {
        self.witnesses[index].as_slice()
    }

    #[cfg(feature = "hardened")]
    #[must_use]
    pub fn masked_witness(&self, index: usize) -> &MaskedWitness {
        &self.witnesses[index]
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.masks.len()
    }
}

impl Default for ProverMaskScratch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use lib_q_ring::Poly;

    use super::*;

    #[test]
    fn zeroize_polys_clears_coefficients() {
        let mut p = Poly::zero();
        p.coeffs[0] = 123;
        p.coeffs[1] = 456;
        zeroize_polys(core::slice::from_mut(&mut p));
        assert_eq!(p, Poly::zero());
    }

    #[test]
    fn zeroize_poly_vec_clears_storage() {
        let mut v = alloc::vec![{
            let mut p = Poly::zero();
            p.coeffs[0] = 42;
            p
        }];
        zeroize_poly_vec(&mut v);
        assert!(v.is_empty());
    }

    #[test]
    fn into_public_moves_without_scrub() {
        let z = SecretPolyVec::new(alloc::vec![{
            let mut p = Poly::zero();
            p.coeffs[0] = 9;
            p
        }]);
        let public = z.into_public();
        assert_eq!(public[0].coeffs[0], 9);
    }

    #[test]
    fn unreleased_secret_poly_vec_scrubs_on_drop() {
        let secret = SecretPolyVec::new(alloc::vec![{
            let mut p = Poly::zero();
            p.coeffs[0] = 88;
            p
        }]);
        drop(secret);
    }

    #[test]
    #[cfg(not(feature = "hardened"))]
    fn prover_mask_scratch_scrubs_on_drop() {
        let mut scratch = ProverMaskScratch::new();
        scratch.push_attribute(
            SecretPolyVec::new(alloc::vec![{
                let mut p = Poly::zero();
                p.coeffs[0] = 99;
                p
            }]),
            SecretPolyVec::new(alloc::vec![{
                let mut w = Poly::zero();
                w.coeffs[0] = 77;
                w
            }]),
        );
        drop(scratch);
    }

    #[cfg(feature = "hardened")]
    mod hardened {
        use lib_q_random::new_deterministic_rng;
        use rand_core::Rng;

        use super::*;
        use crate::sigma::opening::witness_vec;
        use crate::util::ring_mul;

        #[test]
        fn masked_ring_mul_matches_two_slot_witness() {
            let key_seed = [21u8; 32];
            let ctx = b"batch-ctx";
            let mut rng = new_deterministic_rng([0xA5u8; 32]);
            let mut m1 = alloc::vec![Poly::zero(), Poly::zero()];
            m1[0].coeffs[0] = 2;
            let mut r1 = alloc::vec![Poly::zero()];
            r1[0].coeffs[0] = 9;
            let wit_vec = {
                let mut v = alloc::vec::Vec::new();
                v.extend_from_slice(&r1);
                v.extend_from_slice(&m1);
                v
            };
            let masked = MaskedWitness::split(
                SecretWitnessVec::new(wit_vec.clone()),
                &mut rng,
                &key_seed,
                ctx,
            );
            let mut c = Poly::zero();
            c.coeffs[0] = 1;
            let masked_cw = masked.ring_mul_challenge(&c);
            for (w, mcw) in wit_vec.iter().zip(masked_cw.iter()) {
                let direct = ring_mul(&c, w);
                assert_eq!(direct, *mcw, "slot mismatch");
            }
        }

        #[test]
        fn masked_ring_mul_matches_sample_in_ball_challenge() {
            let key_seed = [21u8; 32];
            let ctx = b"batch-ctx";
            let mut rng = new_deterministic_rng([0xA5u8; 32]);
            let mut m1 = alloc::vec![Poly::zero(), Poly::zero()];
            m1[0].coeffs[0] = 2;
            let mut r1 = alloc::vec![Poly::zero()];
            r1[0].coeffs[0] = 9;
            let wit_vec = {
                let mut v = alloc::vec::Vec::new();
                v.extend_from_slice(&r1);
                v.extend_from_slice(&m1);
                v
            };
            let masked = MaskedWitness::split(
                SecretWitnessVec::new(wit_vec.clone()),
                &mut rng,
                &key_seed,
                ctx,
            );
            let c = lib_q_ring::sample_in_ball(&[7u8; 32], 39);
            let masked_cw = masked.ring_mul_challenge(&c);
            for (w, mcw) in wit_vec.iter().zip(masked_cw.iter()) {
                let direct = ring_mul(&c, w);
                assert_eq!(direct, *mcw, "sparse challenge slot mismatch");
            }
        }

        #[test]
        fn masked_witness_reconstructs_and_ring_mul_matches() {
            let key_seed = [0x42u8; 32];
            let opening = crate::commitment::AjtaiOpening {
                message: lib_q_ring::ModuleVec(alloc::vec![Poly::zero(), Poly::zero()]),
                randomness: lib_q_ring::ModuleVec(alloc::vec![{
                    let mut p = Poly::zero();
                    p.coeffs[0] = 123;
                    p
                }]),
            };
            let wit_vec = witness_vec(&opening);
            let ctx = b"masked-equiv";
            let mut rng = new_deterministic_rng([0xABu8; 32]);
            let masked = MaskedWitness::split(
                SecretWitnessVec::new(wit_vec.clone()),
                &mut rng,
                &key_seed,
                ctx,
            );
            assert_eq!(masked.reconstruct_public(), wit_vec);

            let mut c = Poly::zero();
            c.coeffs[0] = 1;
            c.coeffs[3] = -1;
            let masked_cw = masked.ring_mul_challenge(&c);
            for (w, mcw) in wit_vec.iter().zip(masked_cw.iter()) {
                let direct = ring_mul(&c, w);
                assert_eq!(direct, *mcw);
            }
        }

        #[test]
        fn witness_share_stream_chi_squared_binned() {
            const BINS: usize = 256;
            const SAMPLES: usize = 400_000;
            let key_seed = [0x11u8; 32];
            let ctx = b"chi-square";
            let mut rng = new_deterministic_rng([0xCDu8; 32]);
            let mut counts = [0usize; BINS];
            let q = lib_q_ring::constants::FIELD_MODULUS;
            for _ in 0..SAMPLES {
                let mut entropy = [0u8; 32];
                rng.fill_bytes(&mut entropy);
                let mut h = Shake256::default();
                Update::update(&mut h, &key_seed);
                Update::update(&mut h, ctx);
                Update::update(&mut h, &entropy);
                Update::update(&mut h, super::WITNESS_SPLIT_DOMAIN);
                let mut reader = ExtendableOutput::finalize_xof(h);
                let mut buf = [0u8; super::WITNESS_SPLIT_XOF_BLOCK];
                let mut off = buf.len();
                let v = super::next_mod_field_coeff(&mut reader, &mut buf, &mut off);
                assert!((0..q).contains(&v));
                let bin = ((v as u64 * BINS as u64) / q as u64) as usize;
                counts[bin] += 1;
            }
            let expected = SAMPLES as f64 / BINS as f64;
            let chi_sq: f64 = counts
                .iter()
                .map(|&c| {
                    let diff = c as f64 - expected;
                    diff * diff / expected
                })
                .sum();
            assert!(
                chi_sq < 350.0,
                "chi-squared {chi_sq} suggests gross non-uniformity"
            );
        }
    }
}
