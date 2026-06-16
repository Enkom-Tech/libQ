//! Tamper-rejection and domain-separation tests (PLAN Part 8).

use lib_q_sah::{Sah256, Sah256Key, Sah256Nonce, SahError};

fn kn() -> (Sah256Key, Sah256Nonce) {
    (Sah256Key::new([0x24; 32]), Sah256Nonce::new([0x91; 16]))
}

#[test]
fn wrong_tag_rejected_each_bit() {
    let (k, n) = kn();
    let pt = b"tamper detection check, multi-byte payload here";
    let mut ct = vec![0u8; pt.len()];
    let tag = Sah256::seal_detached(&k, &n, b"aad", pt, &mut ct).unwrap();

    for byte in 0..16 {
        for bit in 0..8 {
            let mut bad = tag;
            bad[byte] ^= 1 << bit;
            let mut out = vec![0u8; ct.len()];
            assert_eq!(
                Sah256::open_detached(&k, &n, b"aad", &ct, &bad, &mut out),
                Err(SahError::AuthenticationFailed)
            );
            assert!(out.iter().all(|&b| b == 0), "plaintext not zeroized on failure");
        }
    }
    // unmodified tag still verifies
    let mut out = vec![0u8; ct.len()];
    Sah256::open_detached(&k, &n, b"aad", &ct, &tag, &mut out).unwrap();
    assert_eq!(out, pt);
}

#[test]
fn mutated_ciphertext_rejected() {
    let (k, n) = kn();
    let pt = vec![0xA5u8; 70];
    let mut ct = vec![0u8; pt.len()];
    let tag = Sah256::seal_detached(&k, &n, b"", &pt, &mut ct).unwrap();

    for &p in &[0usize, 31, 32, 63, 64, pt.len() - 1] {
        let mut bad = ct.clone();
        bad[p] ^= 0x80;
        let mut out = vec![0u8; ct.len()];
        assert_eq!(
            Sah256::open_detached(&k, &n, b"", &bad, &tag, &mut out),
            Err(SahError::AuthenticationFailed)
        );
    }
}

#[test]
fn mutated_aad_rejected() {
    let (k, n) = kn();
    let aad = vec![0x5Au8; 33];
    let pt = b"payload";
    let mut ct = vec![0u8; pt.len()];
    let tag = Sah256::seal_detached(&k, &n, &aad, pt, &mut ct).unwrap();

    for &p in &[0usize, 31, 32] {
        let mut bad = aad.clone();
        bad[p] ^= 0x01;
        let mut out = vec![0u8; ct.len()];
        assert_eq!(
            Sah256::open_detached(&k, &n, &bad, &ct, &tag, &mut out),
            Err(SahError::AuthenticationFailed)
        );
    }
}

#[test]
fn aad_pt_boundary_is_domain_separated() {
    let (k, n) = kn();
    let data = b"ABCDEFGHabcdefgh";

    // (aad=8, pt=8) vs (aad=9, pt=7) over the same 16-byte string.
    let mut c1 = [0u8; 8];
    let t1 = Sah256::seal_detached(&k, &n, &data[..8], &data[8..], &mut c1).unwrap();
    let mut c2 = [0u8; 7];
    let t2 = Sah256::seal_detached(&k, &n, &data[..9], &data[9..], &mut c2).unwrap();
    assert_ne!(t1, t2, "split between aad/pt must change the tag");

    // (aad=all, pt=empty) vs (aad=empty, pt=all)
    let t3 = Sah256::seal_detached(&k, &n, data, b"", &mut []).unwrap();
    let mut c4 = [0u8; 16];
    let t4 = Sah256::seal_detached(&k, &n, b"", data, &mut c4).unwrap();
    assert_ne!(t3, t4);
}

#[test]
fn s2_padding_is_injective() {
    // 0.2.0 pad10*: AAD `D0..D30` (31 B) and `D0..D30,0x01` (32 B) must no longer
    // collide. Under the same message they now produce distinct ciphertext.
    let (k, n) = kn();
    let msg = b"the same message under both AADs";
    let d: Vec<u8> = (0..31u8).collect();
    let mut d2 = d.clone();
    d2.push(0x01);

    let mut c1 = vec![0u8; msg.len()];
    Sah256::seal_detached(&k, &n, &d, msg, &mut c1).unwrap();
    let mut c2 = vec![0u8; msg.len()];
    Sah256::seal_detached(&k, &n, &d2, msg, &mut c2).unwrap();
    assert_ne!(c1, c2, "pad10* must make these AADs produce distinct ciphertext");
}

#[test]
fn nonce_reuse_is_observable() {
    // Documented hazard (spec section 9): same key+nonce, two messages, the
    // first-block keystream repeats so ct1 ^ ct2 == pt1 ^ pt2.
    let (k, n) = kn();
    let pt1 = [0x00u8; 32];
    let pt2 = [0xFFu8; 32];
    let mut c1 = [0u8; 32];
    let mut c2 = [0u8; 32];
    Sah256::seal_detached(&k, &n, b"", &pt1, &mut c1).unwrap();
    Sah256::seal_detached(&k, &n, b"", &pt2, &mut c2).unwrap();
    for i in 0..32 {
        assert_eq!(c1[i] ^ c2[i], pt1[i] ^ pt2[i]);
    }
}
