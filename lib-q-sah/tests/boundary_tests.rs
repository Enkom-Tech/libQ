//! Boundary-length and shape roundtrip tests (PLAN Part 8).

use lib_q_sah::{Sah256, Sah256Key, Sah256Nonce};

fn kn() -> (Sah256Key, Sah256Nonce) {
    let mut k = [0u8; 32];
    let mut n = [0u8; 16];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(5);
    }
    for (i, b) in n.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(2);
    }
    (Sah256Key::new(k), Sah256Nonce::new(n))
}

// Simple deterministic filler so tests don't depend on an RNG.
fn fill(buf: &mut [u8], seed: u8) {
    let mut x = seed;
    for b in buf.iter_mut() {
        x = x.wrapping_mul(0x1f).wrapping_add(0x3b);
        *b = x;
    }
}

#[test]
fn roundtrip_boundary_matrix() {
    let (k, n) = kn();
    let pt_lens = [0usize, 1, 15, 16, 31, 32, 33, 63, 64, 65, 1000, 4096];
    let aad_lens = [0usize, 1, 15, 16, 31, 32, 33, 1000];

    for &pl in &pt_lens {
        for &al in &aad_lens {
            let mut aad = vec![0u8; al];
            let mut pt = vec![0u8; pl];
            fill(&mut aad, 0x11);
            fill(&mut pt, 0x77);

            let sealed = Sah256::seal(&k, &n, &aad, &pt).unwrap();
            assert_eq!(sealed.len(), pl + 16);
            let opened = Sah256::open(&k, &n, &aad, &sealed).unwrap();
            assert_eq!(opened, pt, "pt_len={pl} aad_len={al}");
        }
    }
}

#[test]
fn aad_only_and_msg_only_and_empty() {
    let (k, n) = kn();

    // both empty
    let s = Sah256::seal(&k, &n, b"", b"").unwrap();
    assert_eq!(s.len(), 16);
    assert_eq!(Sah256::open(&k, &n, b"", &s).unwrap(), Vec::<u8>::new());

    // aad-only
    let s = Sah256::seal(&k, &n, b"associated-only", b"").unwrap();
    assert_eq!(Sah256::open(&k, &n, b"associated-only", &s).unwrap(), Vec::<u8>::new());

    // msg-only
    let s = Sah256::seal(&k, &n, b"", b"message-only-payload").unwrap();
    assert_eq!(Sah256::open(&k, &n, b"", &s).unwrap(), b"message-only-payload");
}
