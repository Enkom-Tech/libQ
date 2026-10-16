//! AEGIS-256 known-answer tests: RFC 10032 Appendix A.3.2 to A.3.10, copied
//! verbatim from the RFC text, for both the 128-bit and the 256-bit tag.
//!
//! Vectors 1 to 5 must encrypt and decrypt; vectors 6 to 9 must fail
//! verification. Each is run on the dispatched backend (hardware AES when
//! present), on the portable constant-time backend, and through the public types.

use lib_q_aegis::_internals::{
    aegis256_open_dispatch,
    aegis256_open_soft,
    aegis256_seal_dispatch,
    aegis256_seal_soft,
};
use lib_q_aegis::{
    Aead,
    AeadKey,
    Aegis256,
    Aegis256Tag128,
    Nonce,
};

struct Kat {
    name: &'static str,
    key: &'static str,
    nonce: &'static str,
    ad: &'static str,
    msg: &'static str,
    ct: &'static str,
    tag128: &'static str,
    tag256: &'static str,
}

const K: &str = "1001000000000000000000000000000000000000000000000000000000000000";
const N: &str = "1000020000000000000000000000000000000000000000000000000000000000";

const VALID: &[Kat] = &[
    Kat {
        name: "A.3.2 Test Vector 1",
        key: K,
        nonce: N,
        ad: "",
        msg: "00000000000000000000000000000000",
        ct: "754fc3d8c973246dcc6d741412a4b236",
        tag128: "3fe91994768b332ed7f570a19ec5896e",
        tag256: "1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13",
    },
    Kat {
        name: "A.3.3 Test Vector 2",
        key: K,
        nonce: N,
        ad: "",
        msg: "",
        ct: "",
        tag128: "e3def978a0f054afd1e761d7553afba3",
        tag256: "6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a",
    },
    Kat {
        name: "A.3.4 Test Vector 3",
        key: K,
        nonce: N,
        ad: "0001020304050607",
        msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ct: "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711",
        tag128: "8d86f91ee606e9ff26a01b64ccbdd91d",
        tag256: "b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a",
    },
    Kat {
        name: "A.3.5 Test Vector 4",
        key: K,
        nonce: N,
        ad: "0001020304050607",
        msg: "000102030405060708090a0b0c0d",
        ct: "f373079ed84b2709faee37358458",
        tag128: "c60b9c2d33ceb058f96e6dd03c215652",
        tag256: "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
    },
    Kat {
        name: "A.3.6 Test Vector 5",
        key: K,
        nonce: N,
        ad: concat!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "20212223242526272829"
        ),
        msg: concat!(
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            "3031323334353637"
        ),
        ct: concat!(
            "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca25",
            "2a9b1b8b30cc4a67"
        ),
        tag128: "ab8a7d53fd0e98d727accca94925e128",
        tag256: "a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734",
    },
];

/// Vectors that MUST return "verification failed" (`msg` unused).
const INVALID: &[Kat] = &[
    Kat {
        name: "A.3.7 Test Vector 6 (swapped key and nonce)",
        key: "1000020000000000000000000000000000000000000000000000000000000000",
        nonce: "1001000000000000000000000000000000000000000000000000000000000000",
        ad: "0001020304050607",
        msg: "",
        ct: "f373079ed84b2709faee37358458",
        tag128: "c60b9c2d33ceb058f96e6dd03c215652",
        tag256: "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
    },
    Kat {
        name: "A.3.8 Test Vector 7 (ciphertext bit flip)",
        key: K,
        nonce: N,
        ad: "0001020304050607",
        msg: "",
        ct: "f373079ed84b2709faee37358459",
        tag128: "c60b9c2d33ceb058f96e6dd03c215652",
        tag256: "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
    },
    Kat {
        name: "A.3.9 Test Vector 8 (associated data bit flip)",
        key: K,
        nonce: N,
        ad: "0001020304050608",
        msg: "",
        ct: "f373079ed84b2709faee37358458",
        tag128: "c60b9c2d33ceb058f96e6dd03c215652",
        tag256: "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
    },
    Kat {
        name: "A.3.10 Test Vector 9 (tag bit flip)",
        key: K,
        nonce: N,
        ad: "0001020304050607",
        msg: "",
        ct: "f373079ed84b2709faee37358458",
        tag128: "c60b9c2d33ceb058f96e6dd03c215653",
        tag256: "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2da",
    },
];

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const L: usize>(s: &str) -> [u8; L] {
    hex(s).try_into().unwrap()
}

/// `(key, nonce, ad, buf) -> tag` in-place backend entry point.
type Op<const T: usize> = fn(&[u8; 32], &[u8; 32], &[u8], &mut [u8]) -> [u8; T];

fn check_valid<const T: usize>(kat: &Kat, tag_hex: &str, seal: Op<T>, open: Op<T>, backend: &str) {
    let key = arr::<32>(kat.key);
    let nonce = arr::<32>(kat.nonce);
    let ad = hex(kat.ad);
    let msg = hex(kat.msg);
    let ct = hex(kat.ct);
    let tag = arr::<T>(tag_hex);

    let mut buf = msg.clone();
    assert_eq!(
        seal(&key, &nonce, &ad, &mut buf),
        tag,
        "{} tag{} ({backend})",
        kat.name,
        T * 8
    );
    assert_eq!(buf, ct, "{} ct ({backend})", kat.name);
    let mut back = ct.clone();
    assert_eq!(
        open(&key, &nonce, &ad, &mut back),
        tag,
        "{} ({backend})",
        kat.name
    );
    assert_eq!(back, msg, "{} pt ({backend})", kat.name);
}

#[test]
fn rfc10032_valid_vectors_on_every_backend() {
    for kat in VALID {
        check_valid::<16>(
            kat,
            kat.tag128,
            aegis256_seal_dispatch,
            aegis256_open_dispatch,
            "dispatch",
        );
        check_valid::<16>(
            kat,
            kat.tag128,
            aegis256_seal_soft,
            aegis256_open_soft,
            "soft",
        );
        check_valid::<32>(
            kat,
            kat.tag256,
            aegis256_seal_dispatch,
            aegis256_open_dispatch,
            "dispatch",
        );
        check_valid::<32>(
            kat,
            kat.tag256,
            aegis256_seal_soft,
            aegis256_open_soft,
            "soft",
        );
    }
}

#[test]
fn rfc10032_valid_vectors_through_public_types() {
    for kat in VALID {
        let key = AeadKey::new(hex(kat.key));
        let nonce = Nonce::new(hex(kat.nonce));
        let ad = hex(kat.ad);
        let msg = hex(kat.msg);

        let mut c128 = hex(kat.ct);
        c128.extend_from_slice(&hex(kat.tag128));
        let mut c256 = hex(kat.ct);
        c256.extend_from_slice(&hex(kat.tag256));

        let a = Aegis256Tag128::new();
        assert_eq!(
            a.encrypt(&key, &nonce, &msg, Some(&ad)).unwrap(),
            c128,
            "{}",
            kat.name
        );
        assert_eq!(
            a.decrypt(&key, &nonce, &c128, Some(&ad)).unwrap(),
            msg,
            "{}",
            kat.name
        );
        let b = Aegis256::new();
        assert_eq!(
            b.encrypt(&key, &nonce, &msg, Some(&ad)).unwrap(),
            c256,
            "{}",
            kat.name
        );
        assert_eq!(
            b.decrypt(&key, &nonce, &c256, Some(&ad)).unwrap(),
            msg,
            "{}",
            kat.name
        );
    }
}

#[test]
fn rfc10032_invalid_vectors_fail_and_wipe() {
    for kat in INVALID {
        let key = arr::<32>(kat.key);
        let nonce = arr::<32>(kat.nonce);
        let ad = hex(kat.ad);

        let mut buf = hex(kat.ct);
        let r = Aegis256Tag128::decrypt_in_place_detached(
            &key,
            &nonce,
            &ad,
            &mut buf,
            &arr::<16>(kat.tag128),
        );
        assert!(r.is_err(), "{} tag128 must fail", kat.name);
        assert!(
            buf.iter().all(|&b| b == 0),
            "{} plaintext not wiped",
            kat.name
        );

        let mut buf = hex(kat.ct);
        let r = Aegis256::decrypt_in_place_detached(
            &key,
            &nonce,
            &ad,
            &mut buf,
            &arr::<32>(kat.tag256),
        );
        assert!(r.is_err(), "{} tag256 must fail", kat.name);
        assert!(
            buf.iter().all(|&b| b == 0),
            "{} plaintext not wiped",
            kat.name
        );
    }
}
