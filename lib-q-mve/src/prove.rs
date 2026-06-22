//! mVE producer / relay entry points: `mve_prove` (build envelope + proof) and `mve_verify`
//! (relay gate). Reuses lib-q-zkp's `StarkProver`/`StarkVerifier` (FRI/AIR over GF(p²)) and
//! `ZkpProof` (de)serialization for the proof bytes.
//!
//! RED — PENDING HUMAN SIGN-OFF (see crate docs / `docs/mve-freeze-gate-review.md`).

use lib_q_core::{
    Error,
    Result,
};
use lib_q_ml_kem::array::Array;
use lib_q_ml_kem::array::typenum::U32;
use lib_q_ml_kem::{
    EncapsulateDeterministic,
    KemCore,
    MlKem768,
};
use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::stark::{
    StarkProver,
    StarkVerifier,
    ZkConfig,
    zk_config_with_params,
    zk_config_with_seed_bytes,
};
use lib_q_zkp::{
    ProofMetadata,
    ProofType,
    ZkpProof,
};

// Hiding-PCS FRI parameters (mirror lib-q-zkp membership ZK): log_blowup >= 3 for the degree-5
// Poseidon S-box; the trace is padded to >= MVE_MIN_ROWS = 8 to clear the ZK FRI minimum.
const ZK_LOG_BLOWUP: usize = 3;
const ZK_NUM_QUERIES: usize = 100;
const ZK_POW_BITS: usize = 16;

use crate::air::{
    MveConsistencyAir,
    generate_mve_trace,
    mve_public_values,
    padded_height,
};
use crate::{
    COMMITMENT_BYTES,
    Key,
    MveRekeyEnvelopeV0,
    RecipientCiphertext,
    Wrap,
    check_shape,
    key_commitment,
    wrap_key,
    wrap_to_bytes,
};

/// The recipient ML-KEM update key (encapsulation key) — ML-KEM-768 (`kem_id`-negotiated).
pub type MveEncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;

type Val = Complex<Mersenne31>;

/// Build an [`MveRekeyEnvelopeV0`]: encapsulate `K` to each recipient and prove all wraps carry
/// the same `K` (libq-mve-rekey §5). `encaps_coins[i]` is the (RED-zone) ML-KEM encapsulation
/// randomness for recipient `i` — production MUST pass fresh independent CSPRNG draws.
pub fn mve_prove(
    key: &Key,
    randomizer: &[u8],
    epoch_id: u32,
    epoch_ctx: &[u8],
    recipient_ids: &[Vec<u8>],
    recipient_eks: &[MveEncapsulationKey],
    encaps_coins: &[[u8; 32]],
) -> Result<MveRekeyEnvelopeV0> {
    let n = check_shape(recipient_ids.len(), recipient_eks.len())?;
    if encaps_coins.len() != n {
        return Err(Error::InvalidState {
            operation: "mve_prove".into(),
            reason: "encaps_coins length != recipient count".into(),
        });
    }

    let mut ciphertexts: Vec<RecipientCiphertext> = Vec::with_capacity(n);
    let mut shared_secrets: Vec<Vec<u8>> = Vec::with_capacity(n);
    for i in 0..n {
        let m: Array<u8, U32> = Array::from(encaps_coins[i]);
        let (ct, ss) = recipient_eks[i]
            .encapsulate_deterministic(&m)
            .map_err(|_| Error::InternalError {
                operation: "mve_prove".into(),
                details: "ML-KEM encapsulation failed".into(),
            })?;
        let w: Wrap = wrap_key(key, ss.as_slice());
        ciphertexts.push(RecipientCiphertext {
            kem_ct: ct.as_slice().to_vec(),
            wrap: wrap_to_bytes(&w),
        });
        shared_secrets.push(ss.as_slice().to_vec());
    }

    // Consistency proof: a single K underlies every wrap. Uses the HIDING (zero-knowledge) PCS so
    // the witness (K, ss_i) — K sits in constant trace columns — is NOT leaked by FRI openings.
    // Blinding seeds are drawn fresh from the OS CSPRNG per proof (reuse voids hiding).
    let trace = generate_mve_trace::<Val>(key, &shared_secrets);
    let padded = padded_wraps(key, &shared_secrets);
    let pubs = mve_public_values::<Val>(&padded);
    let mut salt_seed = [0u8; 32];
    let mut blinding_seed = [0u8; 32];
    lib_q_random::fill_entropy(&mut salt_seed).map_err(|_| Error::InternalError {
        operation: "mve_prove".into(),
        details: "no OS entropy source for ZK blinding seeds".into(),
    })?;
    lib_q_random::fill_entropy(&mut blinding_seed).map_err(|_| Error::InternalError {
        operation: "mve_prove".into(),
        details: "no OS entropy source for ZK blinding seeds".into(),
    })?;
    let config = zk_config_with_seed_bytes(
        ZK_LOG_BLOWUP,
        ZK_NUM_QUERIES,
        ZK_POW_BITS,
        salt_seed,
        blinding_seed,
    );
    let stark_proof = StarkProver::new(config)
        .prove(&MveConsistencyAir, trace, &pubs)
        .map_err(|e| Error::InternalError {
            operation: "mve_prove".into(),
            details: e.to_string(),
        })?;
    let zkp = ZkpProof::from_stark_proof(&stark_proof, ProofMetadata::None)?;

    Ok(MveRekeyEnvelopeV0 {
        epoch_id,
        recipient_ids: recipient_ids.to_vec(),
        key_commitment: key_commitment(key, randomizer, epoch_ctx),
        ciphertexts,
        proof: zkp.data,
    })
}

/// Relay verification gate (libq-mve-rekey §6): recipient-set/length checks + the consistency
/// proof. Returns `true` iff the envelope is well-formed and the proof shows every wrap carries a
/// single `K`. Never panics.
///
/// `key_commitment` and `update_pk_i` are part of the §7 `Verify` contract but are **not** used
/// in-circuit: the commitment is the recipient-side binding (§4.3) and the KEM-ciphertext↔shared-
/// secret binding is the documented RED residual (full ML-KEM-encaps-in-circuit). They are
/// accepted here for contract fidelity and forward compatibility.
pub fn mve_verify(
    _key_commitment: &[u8; COMMITMENT_BYTES],
    envelope: &MveRekeyEnvelopeV0,
    _update_pks: &[MveEncapsulationKey],
) -> bool {
    let n = match check_shape(envelope.recipient_ids.len(), envelope.ciphertexts.len()) {
        Ok(n) => n,
        Err(_) => return false,
    };

    // Reconstruct the padded wrap sequence the prover committed to (repeat last recipient).
    let real: Vec<Wrap> = envelope
        .ciphertexts
        .iter()
        .map(|c| c.wrap_felts())
        .collect();
    let height = padded_height(n);
    let padded: Vec<Wrap> = (0..height)
        .map(|row| real[core::cmp::min(row, n - 1)])
        .collect();
    let pubs = mve_public_values::<Val>(&padded);

    let zkp = ZkpProof {
        data: envelope.proof.clone(),
        proof_type: ProofType::Stark,
        security_level: 1,
        metadata: ProofMetadata::None,
    };
    let stark_proof = match zkp.to_stark_proof::<ZkConfig>() {
        Ok(p) => p,
        Err(_) => return false,
    };
    // Verifier needs only the (public) FRI params, not the prover's blinding seeds.
    let config = zk_config_with_params(ZK_LOG_BLOWUP, ZK_NUM_QUERIES, ZK_POW_BITS, 0, 1);
    StarkVerifier::new(config)
        .verify(&MveConsistencyAir, &stark_proof, &pubs)
        .is_ok()
}

/// The padded wrap sequence (real wraps + repeat-last padding), length = [`padded_height`].
fn padded_wraps(key: &Key, shared_secrets: &[Vec<u8>]) -> Vec<Wrap> {
    let n = shared_secrets.len();
    let height = padded_height(n);
    (0..height)
        .map(|row| wrap_key(key, &shared_secrets[core::cmp::min(row, n - 1)]))
        .collect()
}

#[cfg(test)]
mod tests {
    use lib_q_ml_kem::{
        Decapsulate,
        MlKem768,
    };

    use super::*;
    use crate::{
        mask_from_shared_secret,
        unwrap_key,
    };

    fn fe(x: u32) -> Val {
        Complex::<Mersenne31>::from(Mersenne31::new(x))
    }
    fn key(seed: u32) -> Key {
        core::array::from_fn(|i| fe(seed.wrapping_mul(7) + i as u32 + 1))
    }
    fn b32(seed: u8) -> Array<u8, U32> {
        Array::from([seed; 32])
    }

    fn make_recipients(
        n: usize,
    ) -> (
        Vec<MveEncapsulationKey>,
        Vec<<MlKem768 as KemCore>::DecapsulationKey>,
    ) {
        let mut eks = Vec::new();
        let mut dks = Vec::new();
        for i in 0..n {
            let (dk, ek) = MlKem768::generate_deterministic(&b32(i as u8 + 1), &b32(i as u8 + 100));
            eks.push(ek);
            dks.push(dk);
        }
        (eks, dks)
    }

    #[test]
    fn well_formed_envelope_verifies_and_recipients_recover_key() {
        let k = key(42);
        let (eks, dks) = make_recipients(3);
        let ids: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i]).collect();
        let coins: Vec<[u8; 32]> = (0..3u8).map(|i| [i + 7; 32]).collect();
        let env = mve_prove(&k, &[1u8; 32], 9, b"epoch:9", &ids, &eks, &coins).expect("prove");

        let kc = env.key_commitment;
        assert!(
            mve_verify(&kc, &env, &eks),
            "relay accepts a well-formed envelope"
        );

        // Each recipient decapsulates its own ciphertext and recovers K, matching the commitment.
        for (i, dk) in dks.iter().enumerate() {
            let ct = lib_q_ml_kem::Ciphertext::<MlKem768>::try_from(
                env.ciphertexts[i].kem_ct.as_slice(),
            )
            .expect("ct decode");
            let ss = dk.decapsulate(&ct).expect("decaps");
            let recovered = unwrap_key(&env.ciphertexts[i].wrap_felts(), ss.as_slice());
            assert_eq!(recovered, k, "recipient {i} recovers K");
        }
        let _ = mask_from_shared_secret(b"x");
    }

    /// Fresh OS blinding per proof ⇒ distinct proof bytes (the hiding PCS randomization is real),
    /// while the deterministic envelope fields are stable. Evidence for ZK-of-K (M3).
    #[test]
    fn fresh_proofs_differ_under_zk_blinding() {
        let k = key(5);
        let (eks, _dks) = make_recipients(2);
        let ids: Vec<Vec<u8>> = (0..2u8).map(|i| vec![i]).collect();
        let coins: Vec<[u8; 32]> = (0..2u8).map(|i| [i + 1; 32]).collect();
        let e1 = mve_prove(&k, &[1u8; 32], 1, b"e", &ids, &eks, &coins).expect("prove1");
        let e2 = mve_prove(&k, &[1u8; 32], 1, b"e", &ids, &eks, &coins).expect("prove2");
        assert_eq!(
            e1.ciphertexts[0].wrap, e2.ciphertexts[0].wrap,
            "deterministic encaps coins ⇒ identical wraps"
        );
        assert_ne!(
            e1.proof, e2.proof,
            "fresh ZK blinding ⇒ distinct proof bytes"
        );
        assert!(mve_verify(&e2.key_commitment, &e2, &eks));
    }

    /// A divergent-key envelope (recipient 1 wrapped under a different K) must be REJECTED by the
    /// relay — the core insider-robustness property (libq-mve-rekey §7 property 1).
    #[test]
    fn divergent_key_envelope_rejected() {
        let k = key(1);
        let k2 = key(999);
        let (eks, _dks) = make_recipients(2);
        let ids: Vec<Vec<u8>> = (0..2u8).map(|i| vec![i]).collect();
        let coins: Vec<[u8; 32]> = (0..2u8).map(|i| [i + 3; 32]).collect();
        let mut env = mve_prove(&k, &[2u8; 32], 1, b"epoch:1", &ids, &eks, &coins).expect("prove");

        // Tamper: overwrite recipient 1's wrap to deliver k2 (a group split) — the proof was made
        // for the single key k, so the relay must reject the tampered envelope.
        let ss1 = {
            // recover ss1 from the honest wrap (w1 = k + mask1 ⇒ mask1; ss is opaque, but we can
            // rebuild w1' = k2 + mask1 directly from the honest wrap's mask via k).
            let w1 = env.ciphertexts[1].wrap_felts();
            core::array::from_fn::<_, { crate::KEY_ELEMS }, _>(|j| w1[j] - k[j]) // = mask1
        };
        let w1_bad: Wrap = core::array::from_fn(|j| k2[j] + ss1[j]);
        env.ciphertexts[1].wrap = wrap_to_bytes(&w1_bad);

        let kc = env.key_commitment;
        assert!(
            !mve_verify(&kc, &env, &eks),
            "divergent-key envelope must be rejected"
        );
    }
}
