//! Must-reject coverage for HQC KEM decapsulation.
//!
//! The audit lens under card `t_f0d676d1` recorded that HQC and Classic McEliece "parse
//! attacker-supplied ciphertexts with zero must-reject cases". This is the HQC half; the Classic
//! McEliece half is `lib-q-cb-kem/tests/implicit_rejection.rs`.
//!
//! HQC's KEM is an FO transform over the PKE, so a tampered ciphertext must NOT produce an error
//! (signalling failure is itself the oracle a chosen-ciphertext attacker wants). It must return a
//! deterministic secret-derived value instead. The assertion is therefore "decapsulation does not
//! reproduce the genuine shared secret", not "decapsulation fails".
//!
//! The KEM ciphertext is `(c_pke, salt)` and BOTH halves are attacker-supplied, so both are
//! tampered here. The salt is the easier one to overlook: it is only 16 bytes and it feeds the
//! re-encryption check rather than the decryption itself, so an implementation that forgot to
//! bind it would still round-trip correctly and pass every positive test in the crate.

use lib_q_hqc::Hqc1Params;
use lib_q_hqc::hqc_kem::HqcKem;
use lib_q_hqc::shake256_prng::create_shake256_prng_rng;

type P = Hqc1Params;

/// One keypair and one genuine encapsulation, shared by the cases below. HQC keygen is the
/// expensive part, so the tampering loops reuse it rather than regenerating per case.
fn setup() -> (
    HqcKem<P>,
    lib_q_hqc::hqc_kem::HqcKemSecretKey<P>,
    lib_q_hqc::hqc_kem::HqcKemCiphertext<P>,
    lib_q_hqc::hqc_kem::HqcKemSharedSecret<P>,
) {
    let kem = HqcKem::<P>::new().expect("HQC KEM construction");
    let mut entropy = [0u8; 48];
    entropy[0] = 0x5A;
    let mut rng = create_shake256_prng_rng(entropy);
    let (pk, sk) = kem.keygen(&mut rng).expect("keygen");
    let (ct, ss) = kem.encapsulate(&pk, &mut rng).expect("encapsulate");
    (kem, sk, ct, ss)
}

/// Baseline. Without it every "the tampered result differs" assertion below could be satisfied by
/// decapsulation being broken for all inputs, genuine ones included.
#[test]
fn genuine_ciphertext_decapsulates_to_the_encapsulated_secret() {
    let (kem, sk, ct, ss) = setup();
    let recovered = kem.decapsulate(&sk, &ct).expect("decapsulate");
    assert_eq!(
        recovered.as_bytes(),
        ss.as_bytes(),
        "the unmodified ciphertext must decapsulate to the secret encapsulation produced; if this \
         fails, every other assertion in this file is vacuous"
    );
}

/// Every bit of the 16-byte salt must fail to recover the genuine secret.
///
/// Exhaustive over the salt because it is small enough to be, and because the salt is exactly the
/// component an FO implementation can forget to bind: it does not participate in decryption, only
/// in the re-encryption comparison, so omitting it breaks nothing a positive test would see.
#[test]
fn every_salt_bit_flip_fails_to_recover_the_genuine_secret() {
    let (kem, sk, ct, ss) = setup();
    let (c_pke, salt) = ct.parse();
    let genuine = ss.as_bytes();

    let mut checked = 0usize;
    for byte_index in 0..salt.len() {
        for bit in 0..8u8 {
            let mut tampered_salt = salt;
            tampered_salt[byte_index] ^= 1 << bit;
            let tampered = lib_q_hqc::hqc_kem::HqcKemCiphertext::new(c_pke.clone(), tampered_salt);

            let recovered = kem.decapsulate(&sk, &tampered).expect(
                "decapsulation must not error on a tampered ciphertext: an error is the \
                         distinguishing oracle that implicit rejection exists to avoid",
            );
            assert_ne!(
                recovered.as_bytes(),
                genuine,
                "flipping bit {bit} of salt byte {byte_index} still recovered the genuine shared \
                 secret, so the salt is not bound into the FO re-encryption check"
            );
            checked += 1;
        }
    }

    assert_eq!(checked, salt.len() * 8, "expected to cover every salt bit");
}

/// Tampering the wire-visible part of the PKE ciphertext must not recover the genuine secret.
///
/// Scoped deliberately to the first `VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES` bytes, which is
/// exactly what `HqcKemCiphertext::as_bytes` serialises and therefore all an attacker can reach.
/// `c_pke.data` is a much larger working buffer (17724 bytes against a 4417-byte wire prefix for
/// HQC-128), and flipping a bit in that tail changes nothing because decapsulation never reads
/// it. An earlier version of this test sampled at `len/4` and failed there; the ciphertext was
/// genuinely unchanged as far as the algorithm is concerned, so that was the test being wrong,
/// not a malleability finding. Sampling past the wire prefix would assert something HQC does not
/// claim and cannot be attacked through.
///
/// Sampled rather than exhaustive within that prefix: it is 4417 bytes and each case runs a full
/// decode. Positions cover both ends and the `u`/`v` seam at VEC_N_SIZE_BYTES, since an offset
/// error at that boundary is the realistic bug.
#[test]
fn sampled_pke_ciphertext_bit_flips_fail_to_recover_the_genuine_secret() {
    use lib_q_hqc::params::HqcParams as _;

    let (kem, sk, ct, ss) = setup();
    let (c_pke, salt) = ct.parse();
    let genuine = ss.as_bytes();

    let wire_len = P::VEC_N_SIZE_BYTES + P::VEC_N1N2_SIZE_BYTES;
    assert!(
        c_pke.data.len() >= wire_len,
        "c_pke buffer ({}) is shorter than the wire prefix ({wire_len}); the sample positions \
         below would be meaningless",
        c_pke.data.len()
    );

    let seam = P::VEC_N_SIZE_BYTES;
    let positions = [
        0usize,
        1,
        seam - 1,
        seam,
        seam + 1,
        wire_len - 2,
        wire_len - 1,
    ];
    let mut checked = 0usize;
    for &pos in &positions {
        for bit in [0u8, 3, 7] {
            let mut data = c_pke.data.clone();
            data[pos] ^= 1 << bit;
            let tampered = lib_q_hqc::hqc_kem::HqcKemCiphertext::new(
                lib_q_hqc::hqc_pke::HqcPkeCiphertext::new(data),
                salt,
            );

            let recovered = kem
                .decapsulate(&sk, &tampered)
                .expect("decapsulation must not error on a tampered ciphertext");
            assert_ne!(
                recovered.as_bytes(),
                genuine,
                "flipping bit {bit} of c_pke byte {pos} still recovered the genuine shared secret"
            );
            checked += 1;
        }
    }

    assert_eq!(
        checked,
        positions.len() * 3,
        "expected to cover every sampled position"
    );
}

/// The rejection value must be a deterministic function of (key, ciphertext). A fallback drawing
/// fresh randomness would be distinguishable from a genuine decapsulation by calling it twice.
#[test]
fn implicit_rejection_is_deterministic_for_a_fixed_key_and_ciphertext() {
    let (kem, sk, ct, _ss) = setup();
    let (c_pke, mut salt) = ct.parse();
    salt[0] ^= 0x01;
    let tampered = lib_q_hqc::hqc_kem::HqcKemCiphertext::new(c_pke, salt);

    let first = kem.decapsulate(&sk, &tampered).expect("decapsulate");
    let second = kem.decapsulate(&sk, &tampered).expect("decapsulate");
    assert_eq!(
        first.as_bytes(),
        second.as_bytes(),
        "the implicit-rejection value must be deterministic; differing results across calls mean \
         the fallback draws fresh randomness, which is itself an oracle"
    );
}

/// Two distinct rejected ciphertexts must not collapse to one constant. A fallback that hashed
/// only the secret seed would pass the determinism test above while still revealing that both
/// inputs were rejected.
#[test]
fn distinct_rejected_ciphertexts_give_distinct_values() {
    let (kem, sk, ct, _ss) = setup();
    let (c_pke, salt) = ct.parse();

    let mut salt_a = salt;
    salt_a[0] ^= 0x01;
    let mut salt_b = salt;
    salt_b[1] ^= 0x80;

    let a = kem
        .decapsulate(
            &sk,
            &lib_q_hqc::hqc_kem::HqcKemCiphertext::new(c_pke.clone(), salt_a),
        )
        .expect("decapsulate");
    let b = kem
        .decapsulate(
            &sk,
            &lib_q_hqc::hqc_kem::HqcKemCiphertext::new(c_pke, salt_b),
        )
        .expect("decapsulate");

    assert_ne!(
        a.as_bytes(),
        b.as_bytes(),
        "two distinct rejected ciphertexts produced the same value, so the rejection fallback is \
         not binding the ciphertext into its output"
    );
}
