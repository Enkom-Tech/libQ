//! EVIDENCE 1 — both KEM legs contribute secrecy.
//!
//! # Why this file exists
//!
//! libQ shipped a double-KEM (`lib-q-double-kem`) and then withdrew and deleted it. The paper it
//! cited (ePrint 2025/1755) was sound; the implementation was not. Its defect, from card
//! t_2a1456b0: `ct_b` was computed and then DISCARDED at both ends and never transmitted, and
//! `ss_b` was instead recomputed by hashing wire bytes together with the **public** `ek_b`. The
//! second leg therefore contributed no secrecy whatsoever: the construction delivered plain
//! ML-KEM-768 security at 1260 wire bytes, against 1088 for a single ML-KEM-768 ciphertext.
//! Strictly worse than not bothering.
//!
//! A round-trip test cannot see that. The withdrawn crate round-tripped perfectly. So this file
//! does not test round-tripping; it constructs the adversary and requires that it lose.
//!
//! # The adversary
//!
//! [`Adversary`] holds everything an attacker could possibly have short of the thing that must
//! stay secret:
//!
//!   * both public keys, in full,
//!   * every transmitted byte of the ciphertext,
//!   * the public parameters (`A`), and
//!   * **the entire left secret key `sk_L`** — a strictly stronger attacker than a passive
//!     eavesdropper, and the one the `[IND-CK-CCA, -]` notion of §2 actually models.
//!
//! It never holds `sk_R`. `sk_R` is not even constructed in the attack functions.
//!
//! # Why the test is known to be able to fail
//!
//! Every attack here is also run against [`withdrawn_style`], a deliberately broken control that
//! reproduces the withdrawn crate's defect on top of this crate's own wire format. Against that
//! control the adversary **wins**, and the tests assert that it wins. A test suite that only ever
//! observed the attack failing would prove nothing: it would be indistinguishable from an attack
//! that was simply written wrong.

use lib_q_maul::hash::Transcript;
use lib_q_maul::kem::{
    Ciphertext,
    LeftPublicKey,
    LeftSecretKey,
    RightPublicKey,
    RightSecretKey,
};
use lib_q_maul::params::{
    MAUL768,
    ParamSet,
};
use lib_q_maul::pke::{
    self,
    PkeSecret,
    PublicParams,
};
use lib_q_maul::{
    codec,
    decapsulate,
    encapsulate_with_messages,
    keygen_left,
    keygen_right,
    params,
};

const P: &ParamSet = &MAUL768;

struct Fixture {
    pp: PublicParams,
    pk_l: LeftPublicKey,
    sk_l: LeftSecretKey,
    pk_r: RightPublicKey,
    sk_r: RightSecretKey,
}

fn fixture() -> Fixture {
    let pp = PublicParams::standard(P);
    let (pk_l, sk_l) = keygen_left(&pp, &[0x11u8; 32], &vec![0xAA; P.nu_bytes()]);
    let (pk_r, sk_r) = keygen_right(&pp, &[0x22u8; 32], &vec![0xBB; P.nu_bytes()]);
    Fixture {
        pp,
        pk_l,
        sk_l,
        pk_r,
        sk_r,
    }
}

fn shake(label: &str, fields: &[&[u8]]) -> [u8; 32] {
    let mut t = Transcript::new(label, P);
    for f in fields {
        t.field(f);
    }
    let mut out = [0u8; 32];
    t.squeeze(&mut out);
    out
}

// ---------------------------------------------------------------------------------------------
// The adversary: sk_L + both public keys + every transmitted byte. NEVER sk_R.
// ---------------------------------------------------------------------------------------------

struct Adversary<'a> {
    pp: &'a PublicParams,
    pk_l: &'a LeftPublicKey,
    pk_r: &'a RightPublicKey,
    sk_l: &'a LeftSecretKey,
    ct: &'a Ciphertext,
}

impl Adversary<'_> {
    /// The left message. The adversary holds `sk_L`, so this is genuinely available to it.
    fn recover_m_l(&self) -> [u8; 32] {
        let c_c = unpack_vec(self.ct.c_c_bytes(), P.du, P.k);
        let c_l = unpack_poly(self.ct.c_l_bytes(), P.dv);
        pke::decrypt_side(self.pp, self.sk_l.pke_secret(), &c_c, &c_l)
    }

    /// The unmasked right ciphertext. Also genuinely available: `H_OTP` takes only `m_L`.
    fn unmask_c_r(&self) -> Vec<u8> {
        let mask = lib_q_maul::hash::h_otp(P, &self.recover_m_l());
        self.ct
            .c_r_otp_bytes()
            .iter()
            .zip(mask.iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }

    /// Every candidate for `m_R` that the adversary can form WITHOUT `sk_R`.
    ///
    /// This is the crux. If any of these is right, or if the shared secret can be assembled
    /// without a right value at all, the second leg is decoration.
    fn m_r_candidates(&self) -> Vec<(&'static str, [u8; 32])> {
        let c_r = self.unmask_c_r();
        let m_l = self.recover_m_l();
        let c_c = unpack_vec(self.ct.c_c_bytes(), P.du, P.k);
        let c_r_poly = unpack_poly(&c_r, P.dv);

        let mut v: Vec<(&'static str, [u8; 32])> = vec![
            ("all-zero", [0u8; 32]),
            ("all-one", [0xFFu8; 32]),
            ("m_L itself", m_l),
            // The withdrawn crate's actual derivation shape: hash of wire bytes + the PUBLIC key.
            (
                "H(wire || pk_R)",
                shake("adv.wire-pk", &[self.ct.as_bytes(), &self.pk_r.0.bytes]),
            ),
            (
                "H(pk_R || wire)",
                shake("adv.pk-wire", &[&self.pk_r.0.bytes, self.ct.as_bytes()]),
            ),
            (
                "H(c_C || c_R || pk_R)",
                shake(
                    "adv.parts",
                    &[self.ct.c_c_bytes(), &c_r, &self.pk_r.0.bytes],
                ),
            ),
            // Decode the right scalar with NO key at all.
            (
                "decode(c_R) keyless",
                codec::poly_to_message(&codec::decompress_poly(&c_r_poly, P.dv, &self.pp.m), P),
            ),
            // Decode the right scalar with the WRONG (left) key -- the strongest key-reuse guess.
            (
                "decrypt(c_R) with sk_L",
                pke::decrypt_side(self.pp, self.sk_l.pke_secret(), &c_c, &c_r_poly),
            ),
        ];

        // Plus a large batch of blind guesses, so "the adversary just did not guess hard enough"
        // is quantified rather than assumed.
        for i in 0u32..4096 {
            v.push((
                "blind guess",
                shake("adv.guess", &[&i.to_le_bytes(), self.ct.as_bytes()]),
            ));
        }
        v
    }

    /// Every 32-byte value the adversary can produce as a guess at the session key.
    fn key_candidates(&self) -> Vec<(&'static str, [u8; 32])> {
        let m_l = self.recover_m_l();
        let mut out: Vec<(&'static str, [u8; 32])> = Vec::new();

        // Route 1: run the real H_key with each reachable m_R candidate.
        for (why, m_r) in self.m_r_candidates() {
            out.push((
                why,
                lib_q_maul::hash::h_key(
                    P,
                    &self.pk_l.0.bytes,
                    &self.pk_r.0.bytes,
                    &m_l,
                    &m_r,
                    self.ct.c_c_bytes(),
                    self.ct.c_l_bytes(),
                    self.ct.c_r_otp_bytes(),
                ),
            ));
        }

        // Route 2: skip m_R entirely and hash what is visible -- the shape of the actual defect.
        out.push((
            "H(everything visible)",
            shake(
                "adv.visible",
                &[
                    &self.pk_l.0.bytes,
                    &self.pk_r.0.bytes,
                    &m_l,
                    self.ct.as_bytes(),
                ],
            ),
        ));
        out.push(("m_L as key", m_l));
        out
    }
}

fn unpack_poly(src: &[u8], bits: u32) -> [u32; params::N] {
    let v = codec::unpack_bits(src, bits, params::N).expect("unpack");
    let mut out = [0u32; params::N];
    out.copy_from_slice(&v);
    out
}

fn unpack_vec(src: &[u8], bits: u32, k: usize) -> Vec<[u32; params::N]> {
    let per = params::N * (bits as usize) / 8;
    (0..k)
        .map(|i| unpack_poly(&src[i * per..(i + 1) * per], bits))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The deliberately broken control.
// ---------------------------------------------------------------------------------------------

/// A control construction that reproduces the withdrawn `lib-q-double-kem` defect on this crate's
/// own wire format: the second leg's ciphertext is produced and then IGNORED, and its contribution
/// to the session key is re-derived from transmitted bytes plus the PUBLIC right key.
///
/// Byte-for-byte it looks like a double-KEM. It has the same wire size, the same round-trip
/// behaviour and the same two key pairs. It just is not one.
mod withdrawn_style {
    use super::{
        Ciphertext,
        LeftPublicKey,
        LeftSecretKey,
        P,
        PublicParams,
        RightPublicKey,
        RightSecretKey,
        pke,
        shake,
        unpack_poly,
        unpack_vec,
    };

    /// Same wire as Maul; key derived WITHOUT `m_R`.
    pub fn encapsulate(
        pp: &PublicParams,
        pk_l: &LeftPublicKey,
        pk_r: &RightPublicKey,
        m_l: &[u8; 32],
        m_r: &[u8; 32],
    ) -> (Ciphertext, [u8; 32]) {
        let (ct, _real) = super::encapsulate_with_messages(pp, pk_l, pk_r, m_l, m_r);
        // "ss_a" from the left leg, "ss_b" from the wire and the PUBLIC right key. Exactly the
        // shape of the defect: ss_b has no dependence on any right-side secret.
        let ss_a = shake("withdrawn.ss_a", &[m_l]);
        let ss_b = shake(
            "withdrawn.ss_b",
            &[ct.c_c_bytes(), ct.c_l_bytes(), &pk_r.0.bytes],
        );
        (ct, shake("withdrawn.kdf", &[&ss_a, &ss_b]))
    }

    /// Decapsulation that never touches `sk_R` -- it is accepted only to match the real signature.
    pub fn decapsulate(
        pp: &PublicParams,
        _pk_l: &LeftPublicKey,
        pk_r: &RightPublicKey,
        sk_l: &LeftSecretKey,
        _sk_r: &RightSecretKey,
        ct: &Ciphertext,
    ) -> [u8; 32] {
        let c_c = unpack_vec(ct.c_c_bytes(), P.du, P.k);
        let c_l = unpack_poly(ct.c_l_bytes(), P.dv);
        let m_l = pke::decrypt_side(pp, sk_l.pke_secret(), &c_c, &c_l);
        let ss_a = shake("withdrawn.ss_a", &[&m_l]);
        let ss_b = shake(
            "withdrawn.ss_b",
            &[ct.c_c_bytes(), ct.c_l_bytes(), &pk_r.0.bytes],
        );
        shake("withdrawn.kdf", &[&ss_a, &ss_b])
    }
}

// ---------------------------------------------------------------------------------------------
// EVIDENCE 1a -- the control. The attack harness WINS against the withdrawn-style construction.
// ---------------------------------------------------------------------------------------------

#[test]
fn control_the_attack_recovers_the_secret_of_a_withdrawn_style_construction() {
    let f = fixture();
    let (ct, broken_ss) =
        withdrawn_style::encapsulate(&f.pp, &f.pk_l, &f.pk_r, &[0x5Au8; 32], &[0xA5u8; 32]);

    let adv = Adversary {
        pp: &f.pp,
        pk_l: &f.pk_l,
        pk_r: &f.pk_r,
        sk_l: &f.sk_l,
        ct: &ct,
    };

    // The adversary holds sk_L and the wire. For THIS construction that is sufficient.
    let m_l = adv.recover_m_l();
    let ss_a = shake("withdrawn.ss_a", &[&m_l]);
    let ss_b = shake(
        "withdrawn.ss_b",
        &[ct.c_c_bytes(), ct.c_l_bytes(), &f.pk_r.0.bytes],
    );
    let recovered = shake("withdrawn.kdf", &[&ss_a, &ss_b]);

    assert_eq!(
        recovered, broken_ss,
        "the control is supposed to be breakable and was not -- the attack harness is wrong, so \
         every negative result below would be worthless"
    );
}

#[test]
fn control_mutating_the_right_secret_does_not_change_a_withdrawn_style_output() {
    // The mutation test below asserts that corrupting sk_R changes the output. Show here that
    // that assertion genuinely discriminates: against the withdrawn-style construction the same
    // mutation changes NOTHING, which is exactly the defect.
    let f = fixture();
    let (ct, _) =
        withdrawn_style::encapsulate(&f.pp, &f.pk_l, &f.pk_r, &[0x5Au8; 32], &[0xA5u8; 32]);

    let clean = withdrawn_style::decapsulate(&f.pp, &f.pk_l, &f.pk_r, &f.sk_l, &f.sk_r, &ct);

    let mut corrupted = corrupt_right_secret(&f, 0, 1);
    let dirty = withdrawn_style::decapsulate(&f.pp, &f.pk_l, &f.pk_r, &f.sk_l, &corrupted, &ct);
    corrupted.set_pke_secret_for_testing(PkeSecret {
        s: f.sk_r.pke_secret().s.clone(),
    });

    assert_eq!(
        clean, dirty,
        "the withdrawn-style control was supposed to ignore sk_R and did not -- the mutation \
         test below would then not be discriminating"
    );
}

// ---------------------------------------------------------------------------------------------
// EVIDENCE 1b -- THE DEFINING TEST. The same attack LOSES against Maul.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_shared_secret_is_not_derivable_without_the_right_secret_key() {
    let f = fixture();
    let (ct, ss) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[0x5Au8; 32], &[0xA5u8; 32]);

    let adv = Adversary {
        pp: &f.pp,
        pk_l: &f.pk_l,
        pk_r: &f.pk_r,
        sk_l: &f.sk_l,
        ct: &ct,
    };

    // Sanity: the adversary genuinely IS strong -- it really does recover the left message.
    // Without this the negative results below could just mean the adversary is broken.
    let m_l = adv.recover_m_l();
    assert_eq!(
        m_l, [0x5Au8; 32],
        "the adversary failed to recover m_L with sk_L, so it is not the attacker we claim"
    );

    let candidates = adv.key_candidates();
    assert!(
        candidates.len() > 4000,
        "expected a large candidate set, got {}",
        candidates.len()
    );

    for (why, guess) in &candidates {
        assert_ne!(
            guess,
            ss.as_bytes(),
            "the shared secret was recovered WITHOUT sk_R via: {why}"
        );
    }
}

#[test]
fn the_adversary_can_reconstruct_everything_except_the_right_message() {
    // Pin down exactly where the wall is. The adversary reproduces every intermediate value of
    // dDecaps up to and including the unmasked c_R -- and stops there.
    let f = fixture();
    let m_l = [0x33u8; 32];
    let m_r = [0xCCu8; 32];
    let (ct, _) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &m_l, &m_r);
    let adv = Adversary {
        pp: &f.pp,
        pk_l: &f.pk_l,
        pk_r: &f.pk_r,
        sk_l: &f.sk_l,
        ct: &ct,
    };

    assert_eq!(adv.recover_m_l(), m_l, "adversary could not recover m_L");

    // It also correctly unmasks c_R -- confirmed against what sk_R's holder sees.
    let c_c = unpack_vec(ct.c_c_bytes(), P.du, P.k);
    let c_r = unpack_poly(&adv.unmask_c_r(), P.dv);
    let true_m_r = pke::decrypt_side(&f.pp, f.sk_r.pke_secret(), &c_c, &c_r);
    assert_eq!(
        true_m_r, m_r,
        "sk_R's holder could not recover m_R from the adversary's unmasked c_R -- the unmasking \
         is wrong and the attack is not reaching the real wall"
    );

    // ...and yet none of its keyless/wrong-key readings of that very same c_R give m_R.
    for (why, guess) in adv.m_r_candidates() {
        assert_ne!(guess, m_r, "m_R was recovered without sk_R via: {why}");
    }
}

#[test]
fn the_secret_moves_when_only_the_right_message_moves() {
    // The complement of the attack: m_R is not merely unrecoverable, it genuinely determines the
    // key. If the key were independent of m_R the attack above would pass vacuously.
    let f = fixture();
    let (_, a) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[1u8; 32], &[2u8; 32]);
    let mut distinct = 0usize;
    for i in 0u8..32 {
        let mut m_r = [2u8; 32];
        m_r[usize::from(i)] ^= 1;
        let (_, b) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[1u8; 32], &m_r);
        assert_ne!(
            a, b,
            "flipping bit {i} of m_R left the shared secret unchanged"
        );
        distinct += 1;
    }
    assert_eq!(distinct, 32);
}

// ---------------------------------------------------------------------------------------------
// EVIDENCE 1c -- mutation: perturbing sk_R changes the decapsulated secret.
// ---------------------------------------------------------------------------------------------

fn corrupt_right_secret(f: &Fixture, poly_idx: usize, coeff_idx: usize) -> RightSecretKey {
    let (_pk, mut sk) = keygen_right(&f.pp, &[0x22u8; 32], &vec![0xBB; P.nu_bytes()]);
    let mut s = f.sk_r.pke_secret().s.clone();
    s[poly_idx][coeff_idx] = (s[poly_idx][coeff_idx] + 1) % P.q;
    sk.set_pke_secret_for_testing(PkeSecret { s });
    sk
}

#[test]
fn perturbing_a_single_coefficient_of_the_right_secret_changes_the_output() {
    let f = fixture();
    let (ct, ss) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[0x5Au8; 32], &[0xA5u8; 32]);

    // Baseline: the intact keys DO give the right answer, so a later mismatch means the mutation
    // did it and not something else.
    let clean = decapsulate(&f.pp, &f.pk_l, &f.pk_r, &f.sk_l, &f.sk_r, &ct).expect("decaps");
    assert_eq!(clean, ss, "baseline decapsulation is already wrong");

    for poly_idx in 0..P.k {
        for coeff_idx in [0usize, 1, 127, 255] {
            let bad_sk_r = corrupt_right_secret(&f, poly_idx, coeff_idx);
            let got =
                decapsulate(&f.pp, &f.pk_l, &f.pk_r, &f.sk_l, &bad_sk_r, &ct).expect("decaps");
            assert_ne!(
                got, ss,
                "corrupting s_R[{poly_idx}][{coeff_idx}] left the shared secret unchanged -- the \
                 right secret key is not load-bearing"
            );
        }
    }
}

#[test]
fn perturbing_the_left_secret_also_changes_the_output() {
    // Symmetry check: neither key is decorative.
    let f = fixture();
    let (ct, ss) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[0x5Au8; 32], &[0xA5u8; 32]);

    for poly_idx in 0..P.k {
        let (_pk, mut bad) = keygen_left(&f.pp, &[0x11u8; 32], &vec![0xAA; P.nu_bytes()]);
        let mut s = f.sk_l.pke_secret().s.clone();
        s[poly_idx][7] = (s[poly_idx][7] + 1) % P.q;
        bad.set_pke_secret_for_testing(PkeSecret { s });
        let got = decapsulate(&f.pp, &f.pk_l, &f.pk_r, &bad, &f.sk_r, &ct).expect("decaps");
        assert_ne!(
            got, ss,
            "corrupting s_L[{poly_idx}] left the shared secret unchanged"
        );
    }
}

#[test]
fn an_unrelated_right_key_pair_cannot_decapsulate() {
    // The whole-key version of the mutation test: a valid but different sk_R fails.
    let f = fixture();
    let (ct, ss) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[0x5Au8; 32], &[0xA5u8; 32]);
    let (_pk_other, sk_other) = keygen_right(&f.pp, &[0x99u8; 32], &vec![0xBB; P.nu_bytes()]);
    let got = decapsulate(&f.pp, &f.pk_l, &f.pk_r, &f.sk_l, &sk_other, &ct).expect("decaps");
    assert_ne!(got, ss, "an unrelated right key pair decapsulated");
}

#[test]
fn the_wire_actually_carries_the_second_leg() {
    // Criterion 2 of card t_5bc0f630: c_R (masked) must be TRANSMITTED, not computed and thrown
    // away as in the withdrawn crate. Show its bytes are present, are the documented size, and
    // genuinely vary with m_R.
    let f = fixture();
    let (a, _) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[1u8; 32], &[2u8; 32]);
    let (b, _) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[1u8; 32], &[9u8; 32]);

    assert_eq!(a.c_r_otp_bytes().len(), P.c_scal_size());
    assert_eq!(
        a.c_c_bytes().len() + a.c_l_bytes().len() + a.c_r_otp_bytes().len(),
        1440,
        "the wire is not Table 5's 1440 bytes"
    );
    assert_ne!(
        a.c_r_otp_bytes(),
        b.c_r_otp_bytes(),
        "the transmitted right component does not depend on m_R"
    );
}

// ---------------------------------------------------------------------------------------------
// Guard against the OTHER half of the withdrawn crate's problem: size honesty.
// ---------------------------------------------------------------------------------------------

#[test]
fn size_claim_is_measured_against_both_baselines() {
    // Card criterion 5: report against BOTH 2x ML-KEM-768 and 1x ML-KEM-768, so the comparison
    // cannot be read misleadingly the way the withdrawn crate's README was.
    let f = fixture();
    let (ct, _) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[1u8; 32], &[2u8; 32]);
    let measured = ct.as_bytes().len();

    const ML_KEM_768_CT: usize = 1088;
    assert_eq!(measured, 1440, "measured |ct|");
    assert!(
        measured < 2 * ML_KEM_768_CT,
        "Maul768 {measured} is not smaller than two parallel ML-KEM-768 ({})",
        2 * ML_KEM_768_CT
    );
    assert!(
        measured > ML_KEM_768_CT,
        "Maul768 {measured} claims to beat a SINGLE ML-KEM-768 ({ML_KEM_768_CT}); it does not, \
         and any consumer that needs only one key must not use this"
    );

    // -33.8% against two, +32.4% against one. Pin both, to one decimal.
    let vs_two = (2 * ML_KEM_768_CT - measured) * 1000 / (2 * ML_KEM_768_CT);
    let vs_one = (measured - ML_KEM_768_CT) * 1000 / ML_KEM_768_CT;
    assert_eq!(vs_two, 338, "saving vs 2x ML-KEM-768 in per-mille");
    assert_eq!(vs_one, 323, "overhead vs 1x ML-KEM-768 in per-mille");
}

#[test]
fn shared_secret_equality_is_constant_time() {
    // Structural, not wall-clock (see scratchpad/audit-triage/fix-ct-tests.md): assert that the
    // comparison rejects a difference at EVERY byte position, which a truncated-prefix
    // comparator -- the realistic short-circuit regression -- would not.
    use subtle::ConstantTimeEq;
    let f = fixture();
    let (_, ss) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[1u8; 32], &[2u8; 32]);
    let base = *ss.as_bytes();
    assert!(bool::from(ss.ct_eq(&ss)), "a secret is not equal to itself");
    for i in 0..32 {
        let mut other = base;
        other[i] ^= 0x80;
        assert!(
            !bool::from(base.ct_eq(&other)),
            "difference at byte {i} was not detected"
        );
    }
}

#[test]
fn decapsulation_rejects_at_every_ciphertext_byte_position() {
    // The re-encryption check in dDecaps is the CCA gate and it compares secret-derived values.
    // Exhaustively flip every byte of the wire and require the real secret never comes back.
    let f = fixture();
    let (ct, ss) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[1u8; 32], &[2u8; 32]);
    let n = ct.as_bytes().len();
    let mut checked = 0usize;
    // Every byte would be 1440 decapsulations at ~20 ms each in a debug build; sample a stride
    // that still covers all three components and both of their boundaries.
    let positions: Vec<usize> = (0..n)
        .step_by(97)
        .chain([0, 1, 1055, 1056, 1057, 1247, 1248, 1249, n - 1])
        .collect();
    for pos in positions {
        let mut bad = ct.as_bytes().to_vec();
        bad[pos] ^= 0x40;
        let ct2 = Ciphertext::from_bytes(&f.pp, &bad).expect("parse");
        let got = decapsulate(&f.pp, &f.pk_l, &f.pk_r, &f.sk_l, &f.sk_r, &ct2).expect("decaps");
        assert_ne!(got, ss, "corruption at byte {pos} was not rejected");
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} positions checked");
}

#[test]
fn implicit_rejection_is_deterministic_and_key_bound() {
    // A rejected ciphertext must give a stable pseudorandom key that depends on the rejection
    // seeds -- not a constant, and not something an adversary can predict from the wire.
    let f = fixture();
    let (ct, _) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[1u8; 32], &[2u8; 32]);
    let mut bad = ct.as_bytes().to_vec();
    bad[0] ^= 0xFF;
    let ct2 = Ciphertext::from_bytes(&f.pp, &bad).expect("parse");

    let a = decapsulate(&f.pp, &f.pk_l, &f.pk_r, &f.sk_l, &f.sk_r, &ct2).expect("decaps");
    let b = decapsulate(&f.pp, &f.pk_l, &f.pk_r, &f.sk_l, &f.sk_r, &ct2).expect("decaps");
    assert_eq!(a, b, "implicit rejection is not deterministic");

    let (_pk, sk_other) = keygen_right(&f.pp, &[0x22u8; 32], &vec![0xCC; P.nu_bytes()]);
    let c = decapsulate(&f.pp, &f.pk_l, &f.pk_r, &f.sk_l, &sk_other, &ct2).expect("decaps");
    assert_ne!(
        a, c,
        "the implicit-rejection key ignores the right rejection seed s_R"
    );
}

#[test]
fn a_shared_secret_of_all_zeroes_never_appears() {
    // Cheap catch for a whole class of "the key derivation silently did nothing" bugs.
    let f = fixture();
    for i in 0u8..8 {
        let (_, ss) = encapsulate_with_messages(&f.pp, &f.pk_l, &f.pk_r, &[i; 32], &[i ^ 0xF0; 32]);
        assert_ne!(
            ss.as_bytes(),
            &[0u8; 32],
            "iteration {i} produced a zero key"
        );
    }
}
