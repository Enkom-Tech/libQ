//! Known-answer regression vectors for Maul.
//!
//! # These are SELF-GENERATED and carry no third-party conformance evidence
//!
//! ePrint 2025/1755 publishes no test vectors, and there is no reference implementation of Maul
//! to check against — the authors' published artefact
//! (<https://github.com/tlegavre/dake_estimator>) is a *parameter/size estimator*, not an
//! implementation. So these vectors were produced by the code under test and prove exactly one
//! thing: that this crate still emits the bytes it emitted when they were frozen. They are a
//! wire-format pin, not a correctness proof, and they must never be described as anything else.
//! Registered in `kats-manifest.toml` as `origin = "self-generated"`.
//!
//! # Regenerating
//!
//! ```text
//! cargo test -p lib-q-maul --test kat -- --ignored --nocapture regenerate_vectors
//! ```
//!
//! then paste the printed file over `tests/vectors/maul_kat.txt` and update the `sha256` in
//! `kats-manifest.toml`. A regeneration that changes any existing line is a WIRE-FORMAT BREAK,
//! not a test fix.

use lib_q_maul::params::{
    ALL,
    ParamSet,
};
use lib_q_maul::{
    PublicParams,
    decapsulate,
    encapsulate_with_messages,
    keygen_left,
    keygen_right,
};

const VECTORS: &str = include_str!("vectors/maul_kat.txt");

#[derive(Default, Debug)]
struct Vector {
    set: String,
    pk_l_seed: Vec<u8>,
    pk_r_seed: Vec<u8>,
    m_l: Vec<u8>,
    m_r: Vec<u8>,
    pk_l: Vec<u8>,
    pk_r: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

fn parse(text: &str) -> Vec<Vector> {
    let mut out: Vec<Vector> = Vec::new();
    let mut cur: Option<Vector> = None;
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("line {}: no '=' in {line:?}", lineno + 1));
        let key = key.trim();
        let value = value.trim();
        if key == "set" {
            if let Some(v) = cur.take() {
                out.push(v);
            }
            cur = Some(Vector {
                set: value.to_string(),
                ..Vector::default()
            });
            continue;
        }
        let v = cur
            .as_mut()
            .unwrap_or_else(|| panic!("line {}: field before `set`", lineno + 1));
        let bytes =
            hex::decode(value).unwrap_or_else(|e| panic!("line {}: bad hex: {e}", lineno + 1));
        match key {
            "pk_l_seed" => v.pk_l_seed = bytes,
            "pk_r_seed" => v.pk_r_seed = bytes,
            "m_l" => v.m_l = bytes,
            "m_r" => v.m_r = bytes,
            "pk_l" => v.pk_l = bytes,
            "pk_r" => v.pk_r = bytes,
            "ct" => v.ct = bytes,
            "ss" => v.ss = bytes,
            other => panic!("line {}: unknown field {other:?}", lineno + 1),
        }
    }
    if let Some(v) = cur.take() {
        out.push(v);
    }
    out
}

fn seed32(v: &[u8]) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(v);
    s
}

/// `(parameter set, pk_l seed, pk_r seed, m_L, m_R)`.
type Case = (&'static ParamSet, [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for p in ALL {
        out.push((p, [0u8; 32], [1u8; 32], [0u8; 32], [0u8; 32]));
        out.push((
            p,
            seed32(&(0..32u8).collect::<Vec<_>>()),
            seed32(&(0..32u8).map(|i| i ^ 0xFF).collect::<Vec<_>>()),
            [0x5Au8; 32],
            [0xA5u8; 32],
        ));
        out.push((
            p,
            [0xDEu8; 32],
            [0xADu8; 32],
            seed32(&(0..32u8).map(|i| i.wrapping_mul(37)).collect::<Vec<_>>()),
            seed32(&(0..32u8).map(|i| i.wrapping_mul(91)).collect::<Vec<_>>()),
        ));
    }
    out
}

/// The FO rejection seeds are derived from the key seeds so a vector needs no extra field.
fn fo_seed(p: &ParamSet, key_seed: &[u8; 32], side: u8) -> Vec<u8> {
    (0..p.nu_bytes())
        .map(|i| key_seed[i % 32] ^ side ^ (i as u8))
        .collect()
}

fn run_case(c: &Case) -> Vector {
    let (p, sl, sr, m_l, m_r) = c;
    let pp = PublicParams::standard(p);
    let (pk_l, sk_l) = keygen_left(&pp, sl, &fo_seed(p, sl, 0));
    let (pk_r, sk_r) = keygen_right(&pp, sr, &fo_seed(p, sr, 1));
    let (ct, ss) = encapsulate_with_messages(&pp, &pk_l, &pk_r, m_l, m_r);
    let got = decapsulate(&pp, &pk_l, &pk_r, &sk_l, &sk_r, &ct).expect("decapsulate");
    assert_eq!(got, ss, "{}: encaps/decaps disagree", p.name);
    Vector {
        set: p.name.to_string(),
        pk_l_seed: sl.to_vec(),
        pk_r_seed: sr.to_vec(),
        m_l: m_l.to_vec(),
        m_r: m_r.to_vec(),
        pk_l: pk_l.0.bytes.clone(),
        pk_r: pk_r.0.bytes.clone(),
        ct: ct.as_bytes().to_vec(),
        ss: ss.as_bytes().to_vec(),
    }
}

#[test]
fn vectors_still_reproduce_byte_for_byte() {
    let vectors = parse(VECTORS);
    assert_eq!(
        vectors.len(),
        cases().len(),
        "the vector file has {} records but the generator defines {} cases",
        vectors.len(),
        cases().len()
    );
    for (i, (v, c)) in vectors.iter().zip(cases().iter()).enumerate() {
        assert_eq!(v.set, c.0.name, "record {i}: parameter set");
        assert_eq!(v.pk_l_seed, c.1.to_vec(), "record {i}: pk_l_seed");
        assert_eq!(v.pk_r_seed, c.2.to_vec(), "record {i}: pk_r_seed");
        let got = run_case(c);
        assert_eq!(
            hex::encode(&got.pk_l),
            hex::encode(&v.pk_l),
            "record {i}: pk_l"
        );
        assert_eq!(
            hex::encode(&got.pk_r),
            hex::encode(&v.pk_r),
            "record {i}: pk_r"
        );
        assert_eq!(hex::encode(&got.ct), hex::encode(&v.ct), "record {i}: ct");
        assert_eq!(hex::encode(&got.ss), hex::encode(&v.ss), "record {i}: ss");
        assert_eq!(v.ct.len(), c.0.ciphertext_size(), "record {i}: |ct|");
        assert_eq!(v.pk_l.len(), c.0.public_key_size(), "record {i}: |pk|");
    }
}

#[test]
fn the_vector_file_covers_every_parameter_set() {
    let vectors = parse(VECTORS);
    for p in ALL {
        assert!(
            vectors.iter().any(|v| v.set == p.name),
            "no vector for {}",
            p.name
        );
    }
}

#[test]
fn parser_rejects_a_malformed_record() {
    // A parser that silently ignored bad input would let the vector file rot unnoticed.
    let bad = "set = Maul768\nnot-a-field = 00\n";
    let err = std::panic::catch_unwind(|| parse(bad));
    assert!(err.is_err(), "the parser accepted an unknown field");
}

#[test]
#[ignore = "regenerator: writes vectors to stdout, run explicitly"]
fn regenerate_vectors() {
    let mut s = String::new();
    s.push_str(
        "# Maul known-answer vectors -- origin: self-generated.\n\
         #\n\
         # PRODUCED BY THE CODE UNDER TEST. ePrint 2025/1755 publishes no test vectors and there\n\
         # is no reference implementation of Maul to check against (the authors' artefact,\n\
         # https://github.com/tlegavre/dake_estimator, is a parameter/size estimator, not an\n\
         # implementation). These vectors therefore carry NO third-party conformance evidence\n\
         # whatsoever -- they show only that this crate still produces the bytes it produced when\n\
         # they were frozen.\n\
         #\n\
         # Generator: lib-q-maul/tests/kat.rs::regenerate_vectors\n\
         #   cargo test -p lib-q-maul --test kat -- --ignored --nocapture regenerate_vectors\n\
         # A change to any existing line here is a WIRE-FORMAT BREAK, not a test fix.\n\
         #\n\
         # Public parameters are PublicParams::standard(set); the FO rejection seeds are derived\n\
         # from the key seeds by tests/kat.rs::fo_seed. Fields are hex.\n",
    );
    for c in &cases() {
        let v = run_case(c);
        s.push_str(&format!("\nset = {}\n", v.set));
        s.push_str(&format!("pk_l_seed = {}\n", hex::encode(&v.pk_l_seed)));
        s.push_str(&format!("pk_r_seed = {}\n", hex::encode(&v.pk_r_seed)));
        s.push_str(&format!("m_l = {}\n", hex::encode(&v.m_l)));
        s.push_str(&format!("m_r = {}\n", hex::encode(&v.m_r)));
        s.push_str(&format!("pk_l = {}\n", hex::encode(&v.pk_l)));
        s.push_str(&format!("pk_r = {}\n", hex::encode(&v.pk_r)));
        s.push_str(&format!("ct = {}\n", hex::encode(&v.ct)));
        s.push_str(&format!("ss = {}\n", hex::encode(&v.ss)));
    }
    std::fs::write("tests/vectors/maul_kat.txt", &s).expect("write vectors");
    println!("wrote {} bytes to tests/vectors/maul_kat.txt", s.len());
    assert!(!s.is_empty(), "regenerator produced nothing");
}
