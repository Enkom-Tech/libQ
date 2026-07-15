//! Official MAYO_2 round-2 KAT vectors (PQCsignKAT_24_MAYO_2.rsp from the
//! authors' reference implementation), driven by the NIST AES-256-CTR DRBG
//! exactly like PQCgenKAT_sign.c: one 24-byte randombytes call for the
//! keygen seed, one 24-byte call for the signing randomizer per message.

#![cfg(feature = "mayo2")]

use lib_q_mayo::mayo_2;
use lib_q_random::EntropySource;
use lib_q_random::entropy::NistAes256CtrDrbg;

struct Vector {
    count: usize,
    seed: [u8; 48],
    msg: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    sm: Vec<u8>,
}

fn parse_kats() -> Vec<Vector> {
    let text = include_str!("kats/PQCsignKAT_24_MAYO_2.rsp");
    let mut out = Vec::new();
    let mut count = None;
    let mut seed = None;
    let mut msg = None;
    let mut pk = None;
    let mut sk = None;
    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        match key {
            "count" => count = Some(value.parse::<usize>().unwrap()),
            "seed" => seed = Some(hex::decode(value).unwrap()),
            "msg" => msg = Some(hex::decode(value).unwrap()),
            "pk" => pk = Some(hex::decode(value).unwrap()),
            "sk" => sk = Some(hex::decode(value).unwrap()),
            "sm" => {
                let sm = hex::decode(value).unwrap();
                out.push(Vector {
                    count: count.take().unwrap(),
                    seed: seed.take().unwrap().try_into().unwrap(),
                    msg: msg.take().unwrap(),
                    pk: pk.take().unwrap(),
                    sk: sk.take().unwrap(),
                    sm,
                });
            }
            _ => {}
        }
    }
    out
}

#[test]
fn mayo2_round2_kats() {
    let vectors = parse_kats();
    assert_eq!(vectors.len(), 100);

    for v in &vectors {
        let mut drbg = NistAes256CtrDrbg::new();
        drbg.randombytes_init(v.seed);

        // keygen: one randombytes(seed_sk)
        let mut seed_sk = [0u8; mayo_2::KEY_GENERATION_RANDOMNESS_SIZE];
        drbg.get_entropy(&mut seed_sk).unwrap();
        let keypair = mayo_2::generate_key_pair(seed_sk);
        assert_eq!(
            keypair.verification_key.as_slice(),
            &v.pk[..],
            "pk mismatch count={}",
            v.count
        );
        assert_eq!(
            keypair.signing_key.as_slice(),
            &v.sk[..],
            "sk mismatch count={}",
            v.count
        );

        // sign: one randombytes(R)
        let mut randomizer = [0u8; mayo_2::SIGNING_RANDOMNESS_SIZE];
        drbg.get_entropy(&mut randomizer).unwrap();
        let signature = mayo_2::sign(&keypair.signing_key, &v.msg, randomizer).unwrap();

        assert_eq!(
            v.sm.len(),
            mayo_2::SIGNATURE_SIZE + v.msg.len(),
            "smlen count={}",
            v.count
        );
        assert_eq!(
            signature.as_slice(),
            &v.sm[..mayo_2::SIGNATURE_SIZE],
            "sig mismatch count={}",
            v.count
        );
        assert_eq!(
            &v.sm[mayo_2::SIGNATURE_SIZE..],
            &v.msg[..],
            "sm message part count={}",
            v.count
        );

        // verify + tamper rejection
        mayo_2::verify(&keypair.verification_key, &v.msg, &signature)
            .unwrap_or_else(|_| panic!("verify failed count={}", v.count));
        let mut bad = signature.clone();
        bad.as_ref_mut()[0] ^= 1;
        assert!(
            mayo_2::verify(&keypair.verification_key, &v.msg, &bad).is_err(),
            "tampered signature accepted count={}",
            v.count
        );
    }
}
