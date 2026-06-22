//! `lib-q-mve` — Multi-recipient Verifiable Encryption (verifiable rekey) for libQ.
//!
//! Implements the [`libq-mve-rekey-v0`] §4/§7 contract: a producer distributes a fresh group key
//! `K` to many recipients, each wrapped under that recipient's ML-KEM update key, and attaches a
//! **single proof** that **every** recipient receives the **same** `K` (bound to one
//! `key_commitment`) — checkable by an untrusted relay **without** learning `K`. This is the
//! insider-robustness gate: a malicious producer cannot hand divergent key material to different
//! recipients and split the group.
//!
//! ```text
//! Prove (K, r, {update_pk_i}, {ct_i}) -> π        # all ct_i deliver the same K
//! Verify(key_commitment, {ct_i}, {update_pk_i}, π) -> bool
//! ```
//!
//! ## Construction (mVE-v0)
//!
//! - `key_commitment = K12(libq.mve.commit.v0 ‖ K ‖ r ‖ epoch_ctx)` — **outside** the circuit (32 B).
//! - Per recipient `i`: `ct_i = ML-KEM.Encaps(update_pk_i) → (ss_i, kem_ct_i)`; the delivered wrap
//!   is `w_i = K + H_zk(ss_i)` (field-additive one-time wrap; `H_zk` = `hash_suite_id = 5`
//!   Poseidon-256). The recipient decapsulates `ss_i` from `kem_ct_i` and recovers
//!   `K = w_i − H_zk(ss_i)`, then checks `key_commitment` (libq-mve-rekey §4.3).
//! - The **proof** asserts, in zero knowledge of `(K, r, {ss_i})`, that there is a **single** `K`
//!   with `w_i = K + H_zk(ss_i)` for every `i` (see [`air`]). A split (different `K` to different
//!   recipients) cannot produce a verifying proof.
//!
//! ## RED — PENDING HUMAN CRYPTOGRAPHER SIGN-OFF
//!
//! This tier is **RED** for the same reasons as the membership AIR (shared Poseidon-256 over
//! GF(p²), round counts not human-verified) **plus** the mVE-specific obligations in
//! `docs/mve-freeze-gate-review.md` (M1–M4). In particular the in-circuit proof guarantees
//! single-`K` consistency across the wraps; binding `ss_i` to its KEM ciphertext `kem_ct_i` under
//! `update_pk_i` (full ML-KEM-encaps-in-circuit) is **NOT** proven and is backstopped by the
//! recipient commitment check (libq-mve-rekey §4.3, §6 fallback). Do **not** treat this as
//! load-bearing until a human cryptographer signs off.
//!
//! [`libq-mve-rekey-v0`]: ../../../libQ-SPEC/spec/security/libq-mve-rekey-v0.md

use lib_q_core::{
    Error,
    Result,
};
use lib_q_poseidon::PoseidonField;
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::air::{
    WIDE_DIGEST_ELEMS,
    WideDigest,
    poseidon_field_to_bytes,
    poseidon256_wide_hash,
};
use lib_q_zkp::membership::{
    WIDE_DIGEST_BYTES,
    wide_digest_from_bytes,
    wide_digest_to_bytes,
};

pub mod air;
pub mod prove;

pub use prove::{
    MveEncapsulationKey,
    mve_prove,
    mve_verify,
};

/// Number of field elements in the distributed key `K` (= [`WIDE_DIGEST_ELEMS`] = 5;
/// 5 × ~62-bit GF(p²) ≈ 310-bit key material ≥ 256-bit).
pub const KEY_ELEMS: usize = WIDE_DIGEST_ELEMS;
/// Bytes per serialized key / wrap (5 × 8-byte `Complex<Mersenne31>`).
pub const KEY_BYTES: usize = WIDE_DIGEST_BYTES;
/// ML-KEM shared-secret bytes packed into [`SS_ELEMS`] GF(p²) elements (8 bytes each).
pub const SS_ELEMS: usize = 4;
/// K12 commitment output length.
pub const COMMITMENT_BYTES: usize = 32;
/// Maximum recipient count for one envelope (DoS bound; trace height padded to a power of two).
pub const MAX_RECIPIENTS: usize = 1024;

/// K12 domain label for the distributed-key commitment (libq-mve-rekey §4.3).
pub const MVE_COMMIT_LABEL: &[u8] = b"libq.mve.commit.v0";

/// Mersenne31 prime modulus.
const MERSENNE31_P: u32 = 0x7FFF_FFFF;

/// The distributed key material `K` (RED-zone: never logged / FFI-exported).
pub type Key = [PoseidonField; KEY_ELEMS];
/// A per-recipient additive wrap `w_i = K + H_zk(ss_i)`.
pub type Wrap = [PoseidonField; KEY_ELEMS];

/// Pack ML-KEM shared-secret bytes into [`SS_ELEMS`] field elements (8 bytes each: 4 real + 4 imag,
/// reduced mod p). `ss` is a witness, not a wire-canonical value, so a reducing decode is fine —
/// the producer and recipient reduce identically. Used both value-level and in-circuit.
pub(crate) fn ss_to_felts(ss: &[u8]) -> [PoseidonField; SS_ELEMS] {
    let mut padded = [0u8; SS_ELEMS * 8];
    let n = core::cmp::min(ss.len(), padded.len());
    padded[..n].copy_from_slice(&ss[..n]);
    core::array::from_fn(|k| {
        let r = u32::from_le_bytes([
            padded[k * 8],
            padded[k * 8 + 1],
            padded[k * 8 + 2],
            padded[k * 8 + 3],
        ]) % MERSENNE31_P;
        let im = u32::from_le_bytes([
            padded[k * 8 + 4],
            padded[k * 8 + 5],
            padded[k * 8 + 6],
            padded[k * 8 + 7],
        ]) % MERSENNE31_P;
        Complex::new_complex(Mersenne31::new(r), Mersenne31::new(im))
    })
}

/// `key_commitment = K12(libq.mve.commit.v0 ‖ K ‖ r ‖ epoch_ctx)` (libq-mve-rekey §4.3).
/// Hiding + binding commitment to the distributed key; the value every recipient checks against.
pub fn key_commitment(key: &Key, r: &[u8], epoch_ctx: &[u8]) -> [u8; COMMITMENT_BYTES] {
    use lib_q_k12::Kt128;
    use lib_q_k12::digest::{
        ExtendableOutput,
        Update,
        XofReader,
    };
    let mut h = Kt128::new(MVE_COMMIT_LABEL);
    h.update(&poseidon_field_to_bytes(key));
    h.update(r);
    h.update(epoch_ctx);
    let mut out = [0u8; COMMITMENT_BYTES];
    h.finalize_xof().read(&mut out);
    out
}

/// `H_zk(ss)` — the per-recipient mask: Poseidon-256 (`hash_suite_id = 5`) of the packed ML-KEM
/// shared secret, truncated to [`KEY_ELEMS`] field elements. Deterministic in `ss`.
pub fn mask_from_shared_secret(ss: &[u8]) -> [PoseidonField; KEY_ELEMS] {
    let felts = ss_to_felts(ss);
    let digest: WideDigest = poseidon256_wide_hash(&felts);
    core::array::from_fn(|j| digest[j])
}

/// `w = K + H_zk(ss)` (field-additive wrap).
pub fn wrap_key(key: &Key, ss: &[u8]) -> Wrap {
    let mask = mask_from_shared_secret(ss);
    core::array::from_fn(|j| key[j] + mask[j])
}

/// `K = w − H_zk(ss)` (recipient unwrap). Inverse of [`wrap_key`] for the same `ss`.
pub fn unwrap_key(wrap: &Wrap, ss: &[u8]) -> Key {
    let mask = mask_from_shared_secret(ss);
    core::array::from_fn(|j| wrap[j] - mask[j])
}

/// One recipient's wire ciphertext: the ML-KEM encapsulation plus the additive key-wrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientCiphertext {
    /// ML-KEM ciphertext (`kem_id`-negotiated; no classical/hybrid leg on the wire).
    pub kem_ct: Vec<u8>,
    /// `w_i = K + H_zk(ss_i)`, serialized as [`KEY_BYTES`] bytes.
    pub wrap: [u8; KEY_BYTES],
}

impl RecipientCiphertext {
    /// Decode the wrap field-element vector (wraps are canonical field elements by construction).
    pub fn wrap_felts(&self) -> Wrap {
        match wide_digest_from_bytes(&self.wrap) {
            Ok(d) => d,
            Err(_) => [PoseidonField::ZERO; KEY_ELEMS],
        }
    }
}

/// `MveRekeyEnvelopeV0` (libq-mve-rekey §4.2) — producer → relay → recipients.
#[derive(Clone, Debug)]
pub struct MveRekeyEnvelopeV0 {
    /// The new key epoch this rekey establishes.
    pub epoch_id: u32,
    /// Ordered recipient identifiers (fixes the recipient set the proof is over).
    pub recipient_ids: Vec<Vec<u8>>,
    /// `Commit(K; r)` — hiding + binding commitment to the distributed key (§4.3).
    pub key_commitment: [u8; COMMITMENT_BYTES],
    /// Per-recipient ciphertexts, index-aligned with `recipient_ids`.
    pub ciphertexts: Vec<RecipientCiphertext>,
    /// The single mVE proof π (§7) — all `w_i` carry the same `K`.
    pub proof: Vec<u8>,
}

/// Serialize a wrap (5 field elements) to [`KEY_BYTES`] bytes (canonical `Complex<Mersenne31>`).
pub fn wrap_to_bytes(w: &Wrap) -> [u8; KEY_BYTES] {
    wide_digest_to_bytes(w)
}

/// Validate recipient-set / length invariants shared by producer and relay (libq-mve-rekey §6).
pub(crate) fn check_shape(n_ids: usize, n_cts: usize) -> Result<usize> {
    if n_ids == 0 || n_ids > MAX_RECIPIENTS {
        return Err(Error::InvalidState {
            operation: "mve".into(),
            reason: format!("recipient count {n_ids} out of 1..={MAX_RECIPIENTS}"),
        });
    }
    if n_ids != n_cts {
        return Err(Error::InvalidState {
            operation: "mve".into(),
            reason: "recipient_ids / ciphertexts length mismatch".into(),
        });
    }
    Ok(n_ids)
}

#[cfg(test)]
mod value_tests {
    use lib_q_ml_kem::array::Array;
    use lib_q_ml_kem::array::typenum::U32;
    use lib_q_ml_kem::{
        Decapsulate,
        EncapsulateDeterministic,
        KemCore,
        MlKem768,
    };

    use super::*;

    fn fe(x: u32) -> PoseidonField {
        Complex::<Mersenne31>::from(Mersenne31::new(x))
    }
    fn key(seed: u32) -> Key {
        core::array::from_fn(|i| fe(seed.wrapping_mul(7) + i as u32 + 1))
    }
    fn b32(seed: u8) -> Array<u8, U32> {
        Array::from([seed; 32])
    }

    /// A recipient that decapsulates its own ciphertext recovers exactly the producer's `K`.
    #[test]
    fn recipient_recovers_key() {
        let (dk, ek) = MlKem768::generate_deterministic(&b32(1), &b32(2));
        let k = key(42);
        let (ct, ss_send) = ek.encapsulate_deterministic(&b32(3)).expect("encaps");
        let w = wrap_key(&k, ss_send.as_slice());
        let ss_recv = dk.decapsulate(&ct).expect("decaps");
        let recovered = unwrap_key(&w, ss_recv.as_slice());
        assert_eq!(recovered, k, "recipient recovers the producer's K");
    }

    /// A wrong shared secret (divergent ciphertext) unwraps to a DIFFERENT key — the value-level
    /// basis of the recipient commitment check (libq-mve-rekey §4.3).
    #[test]
    fn wrong_shared_secret_recovers_wrong_key() {
        let k = key(7);
        let (_dk, ek) = MlKem768::generate_deterministic(&b32(10), &b32(11));
        let (_ct, ss_send) = ek.encapsulate_deterministic(&b32(12)).expect("encaps");
        let w = wrap_key(&k, ss_send.as_slice());
        let wrong = unwrap_key(&w, &[0xABu8; 32]);
        assert_ne!(wrong, k, "a divergent shared secret must not recover K");
    }

    #[test]
    fn commitment_binds_key_and_randomizer() {
        let k = key(5);
        let c1 = key_commitment(&k, &[1u8; 32], b"epoch:9");
        let c2 = key_commitment(&k, &[2u8; 32], b"epoch:9");
        let c3 = key_commitment(&key(6), &[1u8; 32], b"epoch:9");
        assert_ne!(c1, c2, "different randomizer ⇒ different commitment");
        assert_ne!(c1, c3, "different key ⇒ different commitment");
        assert_eq!(
            c1,
            key_commitment(&k, &[1u8; 32], b"epoch:9"),
            "deterministic"
        );
    }

    #[test]
    fn wrap_byte_round_trip() {
        let k = key(3);
        let w = wrap_key(&k, &[9u8; 32]);
        let bytes = wrap_to_bytes(&w);
        let rc = RecipientCiphertext {
            kem_ct: Vec::new(),
            wrap: bytes,
        };
        assert_eq!(rc.wrap_felts(), w);
    }
}
