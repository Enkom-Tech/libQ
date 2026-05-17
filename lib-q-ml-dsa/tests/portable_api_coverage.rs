//! Extra integration coverage for portable ML-DSA entry points (sign/verify, pre-hash, ACVP, all parameter sets).

use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_ml_dsa::{
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,
};

fn seed(i: u8) -> [u8; KEY_GENERATION_RANDOMNESS_SIZE] {
    let mut s = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    s[0] = i;
    s[31] = i.wrapping_mul(3);
    s
}

fn sign_seed(i: u8) -> [u8; SIGNING_RANDOMNESS_SIZE] {
    let mut s = [0u8; SIGNING_RANDOMNESS_SIZE];
    s[0] = i;
    s[31] = i.wrapping_add(7);
    s
}

mod p44 {
    use lib_q_ml_dsa::ml_dsa_44::{
        MLDSA44Signature,
        MLDSA44SigningKey,
        MLDSA44VerificationKey,
    };

    use super::*;

    #[test]
    fn roundtrip_and_prehash() {
        let kp = ml_dsa_44::generate_key_pair(seed(1));
        let msg = b"m";
        let sig = ml_dsa_44::sign(&kp.signing_key, msg, b"", sign_seed(9)).expect("s");
        assert!(ml_dsa_44::verify(&kp.verification_key, msg, b"", &sig).is_ok());

        let sig_ph = ml_dsa_44::sign_pre_hashed_shake128(&kp.signing_key, msg, b"c", sign_seed(10))
            .expect("sph");
        assert!(
            ml_dsa_44::verify_pre_hashed_shake128(&kp.verification_key, msg, b"c", &sig_ph).is_ok()
        );
    }

    #[cfg(feature = "acvp")]
    #[test]
    fn acvp_internal_roundtrip_44() {
        let kp = ml_dsa_44::generate_key_pair(seed(1));
        let msg_ds = [0u8; 33];
        let sig_i = ml_dsa_44::sign_internal(&kp.signing_key, &msg_ds, sign_seed(11)).expect("si");
        assert!(ml_dsa_44::verify_internal(&kp.verification_key, &msg_ds, &sig_i).is_ok());
    }

    #[test]
    fn portable_submodule_prehash_matches_root() {
        let kp = ml_dsa_44::generate_key_pair(seed(21));
        let msg = b"ph44";
        let ctx = b"ctxp";
        let r = sign_seed(55);
        let sig_root =
            ml_dsa_44::sign_pre_hashed_shake128(&kp.signing_key, msg, ctx, r).expect("root");
        let sig_port = ml_dsa_44::portable::sign_pre_hashed_shake128(&kp.signing_key, msg, ctx, r)
            .expect("port");
        assert_eq!(sig_root.as_ref(), sig_port.as_ref());
        ml_dsa_44::portable::verify_pre_hashed_shake128(&kp.verification_key, msg, ctx, &sig_port)
            .expect("vport");
    }

    #[test]
    fn portable_submodule_routes_through_same_stack() {
        let kp = ml_dsa_44::portable::generate_key_pair(seed(5));
        let sig = ml_dsa_44::portable::sign(&kp.signing_key, b"x", b"", sign_seed(12)).expect("ps");
        ml_dsa_44::portable::verify(&kp.verification_key, b"x", b"", &sig).expect("pv");
    }

    #[test]
    fn portable_sign_mut_roundtrip() {
        let kp = ml_dsa_44::generate_key_pair(seed(6));
        let mut sig_buf = *MLDSA44Signature::zero().as_ref();
        ml_dsa_44::portable::sign_mut(
            kp.signing_key.as_ref(),
            b"mut",
            b"",
            sign_seed(13),
            &mut sig_buf,
        )
        .expect("sm");
        let sig = MLDSA44Signature::new(sig_buf);
        ml_dsa_44::verify(&kp.verification_key, b"mut", b"", &sig).expect("v");
    }

    #[test]
    fn keygen_mut_matches_generate_key_pair() {
        let mut sk = *MLDSA44SigningKey::zero().as_ref();
        let mut vk = *MLDSA44VerificationKey::zero().as_ref();
        ml_dsa_44::portable::generate_key_pair_mut(seed(7), &mut sk, &mut vk);
        let kp2 = ml_dsa_44::generate_key_pair(seed(7));
        assert_eq!(sk, *kp2.signing_key.as_ref());
        assert_eq!(vk, *kp2.verification_key.as_ref());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let kp = ml_dsa_44::generate_key_pair(seed(18));
        let mut sig = ml_dsa_44::sign(&kp.signing_key, b"t44", b"", sign_seed(14)).expect("s");
        sig.as_ref_mut()[0] ^= 0xFF;
        assert!(ml_dsa_44::verify(&kp.verification_key, b"t44", b"", &sig).is_err());
    }
}

mod p65 {
    use lib_q_ml_dsa::ml_dsa_65::{
        MLDSA65Signature,
        MLDSA65SigningKey,
        MLDSA65VerificationKey,
    };

    use super::*;

    #[test]
    fn roundtrip_prehash() {
        let kp = ml_dsa_65::generate_key_pair(seed(2));
        let msg = b"m65";
        let sig = ml_dsa_65::sign(&kp.signing_key, msg, b"", sign_seed(20)).expect("s");
        ml_dsa_65::verify(&kp.verification_key, msg, b"", &sig).expect("v");
        let sig_ph =
            ml_dsa_65::sign_pre_hashed_shake128(&kp.signing_key, msg, b"cx", sign_seed(21))
                .expect("sph");
        ml_dsa_65::verify_pre_hashed_shake128(&kp.verification_key, msg, b"cx", &sig_ph)
            .expect("vph");
    }

    #[cfg(feature = "acvp")]
    #[test]
    fn acvp_internal_roundtrip_65() {
        let kp = ml_dsa_65::generate_key_pair(seed(2));
        let msg_ds = [1u8; 33];
        let sig_i = ml_dsa_65::sign_internal(&kp.signing_key, &msg_ds, sign_seed(22)).expect("si");
        ml_dsa_65::verify_internal(&kp.verification_key, &msg_ds, &sig_i).expect("vi");
    }

    #[test]
    fn portable_submodule_prehash_matches_root() {
        let kp = ml_dsa_65::generate_key_pair(seed(22));
        let msg = b"ph65";
        let ctx = b"c65";
        let r = sign_seed(56);
        let sig_root =
            ml_dsa_65::sign_pre_hashed_shake128(&kp.signing_key, msg, ctx, r).expect("root");
        let sig_port = ml_dsa_65::portable::sign_pre_hashed_shake128(&kp.signing_key, msg, ctx, r)
            .expect("port");
        assert_eq!(sig_root.as_ref(), sig_port.as_ref());
        ml_dsa_65::portable::verify_pre_hashed_shake128(&kp.verification_key, msg, ctx, &sig_port)
            .expect("vport");
    }

    #[test]
    fn portable_sign_mut_roundtrip() {
        let kp = ml_dsa_65::portable::generate_key_pair(seed(8));
        let mut buf = *MLDSA65Signature::zero().as_ref();
        ml_dsa_65::portable::sign_mut(
            kp.signing_key.as_ref(),
            b"y",
            b"ctx",
            sign_seed(23),
            &mut buf,
        )
        .expect("sm");
        let sig = MLDSA65Signature::new(buf);
        ml_dsa_65::portable::verify(&kp.verification_key, b"y", b"ctx", &sig).expect("v");
    }

    #[test]
    fn keygen_mut_matches() {
        let mut sk = *MLDSA65SigningKey::zero().as_ref();
        let mut vk = *MLDSA65VerificationKey::zero().as_ref();
        ml_dsa_65::portable::generate_key_pair_mut(seed(41), &mut sk, &mut vk);
        let kp2 = ml_dsa_65::generate_key_pair(seed(41));
        assert_eq!(sk, *kp2.signing_key.as_ref());
        assert_eq!(vk, *kp2.verification_key.as_ref());
    }
}

mod p87 {
    use lib_q_ml_dsa::ml_dsa_87::{
        MLDSA87Signature,
        MLDSA87SigningKey,
        MLDSA87VerificationKey,
    };

    use super::*;

    #[test]
    fn roundtrip_prehash() {
        let kp = ml_dsa_87::generate_key_pair(seed(3));
        let msg = b"m87";
        let sig = ml_dsa_87::sign(&kp.signing_key, msg, b"", sign_seed(30)).expect("s");
        ml_dsa_87::verify(&kp.verification_key, msg, b"", &sig).expect("v");
        let sig_ph = ml_dsa_87::sign_pre_hashed_shake128(&kp.signing_key, msg, b"z", sign_seed(31))
            .expect("sph");
        ml_dsa_87::verify_pre_hashed_shake128(&kp.verification_key, msg, b"z", &sig_ph)
            .expect("vph");
    }

    #[cfg(feature = "acvp")]
    #[test]
    fn acvp_internal_roundtrip_87() {
        let kp = ml_dsa_87::generate_key_pair(seed(3));
        let msg_ds = [2u8; 33];
        let sig_i = ml_dsa_87::sign_internal(&kp.signing_key, &msg_ds, sign_seed(32)).expect("si");
        ml_dsa_87::verify_internal(&kp.verification_key, &msg_ds, &sig_i).expect("vi");
    }

    #[test]
    fn portable_submodule_prehash_matches_root() {
        let kp = ml_dsa_87::generate_key_pair(seed(23));
        let msg = b"ph87";
        let ctx = b"c87";
        let r = sign_seed(57);
        let sig_root =
            ml_dsa_87::sign_pre_hashed_shake128(&kp.signing_key, msg, ctx, r).expect("root");
        let sig_port = ml_dsa_87::portable::sign_pre_hashed_shake128(&kp.signing_key, msg, ctx, r)
            .expect("port");
        assert_eq!(sig_root.as_ref(), sig_port.as_ref());
        ml_dsa_87::portable::verify_pre_hashed_shake128(&kp.verification_key, msg, ctx, &sig_port)
            .expect("vport");
    }

    #[test]
    fn tampered_signature_rejected() {
        let kp = ml_dsa_87::generate_key_pair(seed(4));
        let mut sig = ml_dsa_87::sign(&kp.signing_key, b"t", b"", sign_seed(33)).expect("s");
        sig.as_ref_mut()[5] ^= 1;
        assert!(ml_dsa_87::verify(&kp.verification_key, b"t", b"", &sig).is_err());
    }

    #[test]
    fn portable_sign_mut_roundtrip() {
        let kp = ml_dsa_87::portable::generate_key_pair(seed(19));
        let mut buf = *MLDSA87Signature::zero().as_ref();
        ml_dsa_87::portable::sign_mut(&kp.signing_key, b"sm87", b"", sign_seed(34), &mut buf)
            .expect("sm");
        let sig = MLDSA87Signature::new(buf);
        ml_dsa_87::verify(&kp.verification_key, b"sm87", b"", &sig).expect("v");
    }

    #[test]
    fn keygen_mut_matches_generate_key_pair() {
        let mut sk = *MLDSA87SigningKey::zero().as_ref();
        let mut vk = *MLDSA87VerificationKey::zero().as_ref();
        ml_dsa_87::portable::generate_key_pair_mut(seed(8), &mut sk, &mut vk);
        let kp2 = ml_dsa_87::generate_key_pair(seed(8));
        assert_eq!(sk, *kp2.signing_key.as_ref());
        assert_eq!(vk, *kp2.verification_key.as_ref());
    }
}
