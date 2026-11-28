//! Known-answer tests for the ML-KEM-1024 + HQC-256 combiner.
//!
//! Run with: cargo test -p lib-q-kem --features combiner-kat --test combiner_kat
//!
//! # Provenance (origin: self-generated, KDF independently cross-checked)
//!
//! The component values (public keys, ciphertexts, component secrets) are produced by libQ's own
//! ML-KEM-1024 and HQC-256 code from the fixed seeds below; they pin libQ against itself, and
//! ML-KEM-1024 is separately covered by the FIPS 203 / ACVP vectors in `lib-q-ml-kem/tests`.
//!
//! The COMBINED values are not just self-generated: every `ss` below, and every `KDF_ONLY` output,
//! was recomputed from the dumped KDF input bytes by an independent pure-Python TurboSHAKE256
//! (Keccak-p[1600,12], RFC 9861), which shares no code with libQ. That reference was itself
//! checked against the RFC 9861 vectors vendored in `lib-q-sha3/tests/data/turboshake/`. To redo
//! the check, run `dump_kdf_inputs` (ignored by default) and hash each `input=` line with
//! TurboSHAKE256(D=0x1F, 32 bytes).
//!
//! Large values (keys, ciphertexts) are pinned by their SHA3-256 digest.
#![cfg(feature = "combiner-kat")]

use lib_q_kem::combiner::{self, COMBINER_LABEL, ENCAPS_COINS_SIZE, KEYGEN_SEED_SIZE};
use lib_q_ml_kem::{
    MLKEM1024_CIPHERTEXT_SIZE, MLKEM1024_PUBLIC_KEY_SIZE, MLKEM1024_SECRET_KEY_SIZE,
};
use lib_q_sha3::{Digest, Sha3_256};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha3(b: &[u8]) -> String {
    hex(&Sha3_256::digest(b))
}

/// `seed[i] = base + 7*i (mod 256)`.
fn pattern<const N: usize>(base: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = base.wrapping_add((i as u8).wrapping_mul(7));
    }
    out
}

struct Vector {
    keygen_base: u8,
    coins_base: u8,
    pk_sha3: &'static str,
    sk_sha3: &'static str,
    ct_sha3: &'static str,
    ss: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        keygen_base: 0x00,
        coins_base: 0x80,
        pk_sha3: "7d530e0403158d333644559c3a72b655c927f07f66a83884c7b742294decb893",
        sk_sha3: "9461f4c1f0cbd2a11d0d79e34ef1877f238a8bfd8c9c5080bd8a4104e661f700",
        ct_sha3: "19a3175fb93f3a684ffda6053f8f1d829621157e8f29eda6d22691babf76dbe1",
        ss: "e62be780b6cd97bda795d91b26c84f8fd6ca9258c3875f8854158f6d09cd4c44",
    },
    Vector {
        keygen_base: 0x11,
        coins_base: 0x5A,
        pk_sha3: "2b3612cb8813a8f8b966d306dfa26a2afde6782c3e617d0faa24c1733ef637cf",
        sk_sha3: "40e2b3a398cd1be0a4afc6b3a23a9a1a462213f6a8c5b01186c3be7f1c65c788",
        ct_sha3: "42041dd0be69591fe206c58af721f568f99cdc039a369a612c892f2d63d6d47f",
        ss: "3cda5d74a53e4e3808e8a450da9c4de582b33296bfc4890b6a1fc8d1d9cd7bf8",
    },
    Vector {
        keygen_base: 0xF3,
        coins_base: 0x29,
        pk_sha3: "85a5b0848d2041ebc8eb13d6fc1d1a15022bd9b4de5f26328716741b18c22eba",
        sk_sha3: "e2e57c8a022a982bf7ed8d8ec63f7f63a961b20cbed490f9b19e57e986f9f1c3",
        ct_sha3: "281228eb111307446c75ecb6aa3225fc9118ec53ea871328928645d4513c3d29",
        ss: "5f2fd2dd778d0429e6c07299e7341daddc7c4ac87f1f461d5b03eb5c32373207",
    },
];

#[test]
fn combiner_kats() {
    for (i, v) in VECTORS.iter().enumerate() {
        let kp = combiner::generate_keypair_from_seed(&pattern::<KEYGEN_SEED_SIZE>(v.keygen_base))
            .unwrap();
        let (ct, ss) = combiner::encapsulate_with_coins(
            &kp.public_key,
            &pattern::<ENCAPS_COINS_SIZE>(v.coins_base),
        )
        .unwrap();
        let ss_dec = combiner::decapsulate(&kp.secret_key, &ct).unwrap();
        assert_eq!(ss.as_slice(), ss_dec.as_slice(), "vector {i}: round trip");
        assert_eq!(sha3(&kp.public_key), v.pk_sha3, "vector {i}: pk");
        assert_eq!(sha3(&kp.secret_key), v.sk_sha3, "vector {i}: sk");
        assert_eq!(sha3(&ct), v.ct_sha3, "vector {i}: ct");
        assert_eq!(hex(ss.as_slice()), v.ss, "vector {i}: ss");
    }
}

/// The KDF on its own, on synthetic inputs, so another implementation can check its combine step
/// without implementing either KEM. Inputs: `ss_mlkem = pattern(a)`, `ss_hqc = pattern(b)`,
/// `ct_mlkem`, `ct_hqc`, `pk_mlkem`, `pk_hqc` = `pattern(c)`, `pattern(d)`, `pattern(e)`,
/// `pattern(f)` at their real lengths.
const KDF_ONLY: &[([u8; 6], &str)] = &[
    (
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        "d7795e7fd52b66719f9f21ae28e2e47637767a7fe72da02e6323c7a8719e0563",
    ),
    (
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        "31dd8934f9892f2b7a459b1e260f83d3b05464df8a1e3443a1767dea66cc7809",
    ),
    // Same as the row above with ONLY ct_hqc changed (d: 0x04 -> 0x44).
    (
        [0x01, 0x02, 0x03, 0x44, 0x05, 0x06],
        "814c9ee2e4a0d24b6be97d368af5dab96b8b5e5a13bc3e30acfd15f03b6b7845",
    ),
    // Same as row 2 with ONLY pk_hqc changed (f: 0x06 -> 0x46).
    (
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x46],
        "12b9eda0dbe81ffff03a8e3ac79d5e8f2d36753683af7eaf7e4db7859a8c9c33",
    ),
];

/// `(ss_mlkem, ss_hqc, ct_mlkem, ct_hqc, pk_mlkem, pk_hqc)`.
type KdfInputs = (
    [u8; 32],
    [u8; 32],
    [u8; MLKEM1024_CIPHERTEXT_SIZE],
    [u8; combiner::HQC256_CIPHERTEXT_SIZE],
    [u8; MLKEM1024_PUBLIC_KEY_SIZE],
    [u8; combiner::HQC256_PUBLIC_KEY_SIZE],
);

fn kdf_inputs(p: [u8; 6]) -> KdfInputs {
    (
        pattern::<32>(p[0]),
        pattern::<32>(p[1]),
        pattern::<MLKEM1024_CIPHERTEXT_SIZE>(p[2]),
        pattern::<{ combiner::HQC256_CIPHERTEXT_SIZE }>(p[3]),
        pattern::<MLKEM1024_PUBLIC_KEY_SIZE>(p[4]),
        pattern::<{ combiner::HQC256_PUBLIC_KEY_SIZE }>(p[5]),
    )
}

#[test]
fn kdf_only_kats() {
    for (i, (p, want)) in KDF_ONLY.iter().enumerate() {
        let (a, b, c, d, e, f) = kdf_inputs(*p);
        let got = combiner::combine(&a, &b, &c, &d, &e, &f);
        assert_eq!(hex(got.as_slice()), *want, "KDF_ONLY row {i}");
    }
    let outs: Vec<&str> = KDF_ONLY.iter().map(|r| r.1).collect();
    assert_ne!(
        outs[1], outs[2],
        "changing ct_hqc alone must change the output"
    );
    assert_ne!(
        outs[1], outs[3],
        "changing pk_hqc alone must change the output"
    );
}

#[test]
fn label_is_32_bytes_and_ascii() {
    assert_eq!(COMBINER_LABEL.len(), 32);
    assert!(
        COMBINER_LABEL
            .iter()
            .all(|b| b.is_ascii_graphic() || *b == b' ')
    );
    assert_eq!(MLKEM1024_SECRET_KEY_SIZE, 3168);
}

/// Prints every vector's values and the exact KDF input bytes, for the independent cross-check.
/// `cargo test -p lib-q-kem --features combiner-kat --test combiner_kat -- --ignored --nocapture`
#[test]
#[ignore = "generator / cross-check helper, not a test"]
fn dump_kdf_inputs() {
    for v in VECTORS {
        let kp = combiner::generate_keypair_from_seed(&pattern::<KEYGEN_SEED_SIZE>(v.keygen_base))
            .unwrap();
        let (ct, ss) = combiner::encapsulate_with_coins(
            &kp.public_key,
            &pattern::<ENCAPS_COINS_SIZE>(v.coins_base),
        )
        .unwrap();
        // Component secrets, recomputed from the component halves (decapsulate each half alone).
        let ss_m = mlkem_ss(&kp.secret_key, &ct[..MLKEM1024_CIPHERTEXT_SIZE]);
        let ss_h = hqc_ss(&kp.secret_key, &ct[MLKEM1024_CIPHERTEXT_SIZE..]);
        let (pk_m, pk_h) = kp.public_key.split_at(MLKEM1024_PUBLIC_KEY_SIZE);
        let (ct_m, ct_h) = ct.split_at(MLKEM1024_CIPHERTEXT_SIZE);
        let input = [
            COMBINER_LABEL.as_slice(),
            &ss_m,
            &ss_h,
            ct_m,
            ct_h,
            pk_m,
            pk_h,
        ]
        .concat();
        println!("VECTOR {:02x} {:02x}", v.keygen_base, v.coins_base);
        println!("pk_sha3={}", sha3(&kp.public_key));
        println!("sk_sha3={}", sha3(&kp.secret_key));
        println!("ct_sha3={}", sha3(&ct));
        println!("ss={}", hex(ss.as_slice()));
        println!("input={}", hex(&input));
    }
    for (p, _) in KDF_ONLY {
        let (a, b, c, d, e, f) = kdf_inputs(*p);
        let got = combiner::combine(&a, &b, &c, &d, &e, &f);
        let input = [COMBINER_LABEL.as_slice(), &a, &b, &c, &d, &e, &f].concat();
        println!("KDF {}", hex(p));
        println!("ss={}", hex(got.as_slice()));
        println!("input={}", hex(&input));
    }
}

fn mlkem_ss(sk: &[u8], ct: &[u8]) -> Vec<u8> {
    use lib_q_ml_kem::array::Array;
    use lib_q_ml_kem::{Decapsulate, KemCore, MlKem1024};
    let enc = Array::try_from(&sk[..MLKEM1024_SECRET_KEY_SIZE]).unwrap();
    let dk = <MlKem1024 as KemCore>::DecapsulationKey::try_from_bytes(&enc).unwrap();
    dk.decapsulate(&Array::try_from(ct).unwrap())
        .unwrap()
        .to_vec()
}

fn hqc_ss(sk: &[u8], ct: &[u8]) -> Vec<u8> {
    use lib_q_core::{Algorithm, KemOperations, KemSecretKey};
    lib_q_hqc::LibQHqcProvider::new()
        .unwrap()
        .decapsulate(
            Algorithm::Hqc256,
            &KemSecretKey::new(sk[MLKEM1024_SECRET_KEY_SIZE..].to_vec()),
            ct,
        )
        .unwrap()
}
