//! Known-answer tests for Rocca-S (IETF `draft-nakano-rocca-s`).
//!
//! Vector A is the official all-zero test vector from the reference
//! implementation (<https://github.com/jedisct1/rust-rocca-s>). Vectors B–D are
//! cross-generated from the reference algorithm to cover non-zero key/nonce,
//! partial associated-data and message blocks, and the empty-message case; they
//! pin this implementation against the reference round/init/finalize logic.

use lib_q_rocca_s::{
    Aead,
    AeadKey,
    Nonce,
    RoccaSAead,
};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

struct Kat {
    key: &'static str,
    nonce: &'static str,
    ad: &'static str,
    msg: &'static str,
    ct: &'static str,
    tag: &'static str,
}

const VECTORS: &[Kat] = &[
    // A — official all-zero vector.
    Kat {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "00000000000000000000000000000000",
        ad: "0000000000000000000000000000000000000000000000000000000000000000",
        msg: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ct: "9ac3326495a8d414fe407f47b54410502481cf79cab8c0a669323e07711e46170de5b2fbba0fae8de7c1fccaeefc362624fcfdc15f8bb3e64457e8b7e37557bb",
        tag: "8df934d1483710c9410f6a089c4ced9791901b7e2e661206202db2cc7a24a386",
    },
    // B — key=01.., nonce=08.., empty AD, 47-byte message (partial final block).
    Kat {
        key: "0101010101010101010101010101010101010101010101010101010101010101",
        nonce: "08080808080808080808080808080808",
        ad: "",
        msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e",
        ct: "ac014e9c680728fdbd6407ee970f19ecb6d8a81bbd299f446e09d8f16d5f0d57328984554ec3dd997fae3b2121e9db",
        tag: "70a4b9bc3a1e06875a1d44bf6a032d6efed3110ac05c05b9d1c22c994247fd11",
    },
    // C — incrementing key/nonce, 16-byte AD (partial AD block), 32-byte message.
    Kat {
        key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        nonce: "000102030405060708090a0b0c0d0e0f",
        ad: "000102030405060708090a0b0c0d0e0f",
        msg: "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
        ct: "757c021f499d86e3d8c9f2bddb6d8998f4201d41b6e1ad864690f9a4ec16dc44",
        tag: "c1477de9a7e62b616ad873f2cb13a7c9337b80bd379c551bbe7162588981e907",
    },
    // D — empty message, 5-byte AD (tag-only output).
    Kat {
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        nonce: "55555555555555555555555555555555",
        ad: "0102030405",
        msg: "",
        ct: "",
        tag: "364ad665251f54666bd866de08932f020ca9b63b25821c564d9867db72cd435e",
    },
];

#[test]
fn known_answer_vectors() {
    let aead = RoccaSAead::new();
    for (i, v) in VECTORS.iter().enumerate() {
        let key = AeadKey::new(unhex(v.key));
        let nonce = Nonce::new(unhex(v.nonce));
        let ad = unhex(v.ad);
        let msg = unhex(v.msg);
        let mut expected = unhex(v.ct);
        expected.extend_from_slice(&unhex(v.tag));

        let ct = aead
            .encrypt(&key, &nonce, &msg, Some(&ad))
            .expect("encrypt");
        assert_eq!(ct, expected, "vector {i} ciphertext||tag mismatch");

        let back = aead.decrypt(&key, &nonce, &ct, Some(&ad)).expect("decrypt");
        assert_eq!(back, msg, "vector {i} round-trip mismatch");
    }
}
