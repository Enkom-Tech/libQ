//! NIST HQC KEM Known Answer Tests (byte-exact vs authoritative `.rsp` vectors).
//!
//! Authoritative tree: `kats/official/` (NIST `.req` seeds from the PQC KEM KAT package,
//! `.rsp` responses for the Oct 2024 parameter set — 2241-byte `pk`, XOF/SHAKE KEM flow).
//! See `kats/official/PROVENANCE.md` and `kats/README.md`.
//!
//! KAT flow (reference-aligned, A1-confirmed):
//! - `seed` in `.req`/`.rsp` is `seedKEM` (48 bytes).
//! - Keygen: XOF(`seedKEM`, domain 1) → `seedPKE`, `σ`; PKE.Keygen(`seedPKE`).
//! - Encaps: `m` = `seed[32..48]`; `salt` = first 16 bytes of the **next** record's `seed`.

#![cfg(all(feature = "alloc", feature = "hqc", feature = "random"))]

use std::fs;
use std::path::Path;

use lib_q_hqc::hqc_kem::HqcKem;
use lib_q_hqc::params_correct::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
    HqcParams,
};

const OFFICIAL_HQC1_RSP: &str = "kats/official/hqc-1/PQCkemKAT_2321.rsp";
const OFFICIAL_HQC3_RSP: &str = "kats/official/hqc-3/PQCkemKAT_4602.rsp";
const OFFICIAL_HQC5_RSP: &str = "kats/official/hqc-5/PQCkemKAT_7333.rsp";

const PRNG_BYTES_CONSUMED_BY_KEYGEN: usize = 32;
const KEM_MESSAGE_BYTES: usize = 16;
const KEM_SALT_BYTES: usize = 16;

/// One KEM KAT record from a NIST `.rsp` file.
#[derive(Debug, Clone)]
struct KemKatVector {
    count: u32,
    seed: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

fn hex_upper(bytes: &[u8]) -> String {
    hex::encode(bytes).to_ascii_uppercase()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars().peekable();
    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let s = format!("{c1}{c2}");
        out.push(u8::from_str_radix(&s, 16).expect("invalid hex in KAT file"));
    }
    out
}

fn parse_req_seeds(path: &Path) -> Vec<(u32, Vec<u8>)> {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read KAT req {}: {e}", path.display()));
    let mut records = Vec::new();
    let mut count: Option<u32> = None;
    let mut seed = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("count = ") {
            if let Some(c) = count.take() {
                records.push((c, hex_to_bytes(&seed)));
                seed.clear();
            }
            count = Some(rest.trim().parse().expect("invalid count"));
            continue;
        }
        if let Some(rest) = line.strip_prefix("seed = ") {
            seed = rest.trim().to_string();
        }
    }
    if let Some(c) = count {
        records.push((c, hex_to_bytes(&seed)));
    }
    records
}

/// Maintainer-only: regenerate `.rsp` from bundled `.req` (not the CI gate source).
fn write_official_rsp_file<P: HqcParams>(rsp_path: &Path, req_path: &Path) {
    let records = parse_req_seeds(req_path);
    assert!(
        records.len() >= 2,
        "need at least two seeds for encaps salt chaining"
    );
    let kem = HqcKem::<P>::new().expect("HqcKem::new");
    let mut out = String::from(
        "# HQC KEM KAT responses (Oct 2024 parameter set; SHAKE/XOF KEM flow)\n\
         # Generated once from NIST .req seeds — see kats/official/PROVENANCE.md\n\n",
    );
    for i in 0..records.len() - 1 {
        let (count, seed) = &records[i];
        let (_, next_seed) = &records[i + 1];
        let mut seed48 = [0u8; 48];
        seed48.copy_from_slice(&seed[..48]);
        let (pk, sk) = kem.keygen_with_seed(&seed48).expect("keygen");
        let m = kat_message_from_seed(&seed48);
        let salt = kat_salt_from_next_seed(next_seed);
        let (ct, ss) = kem.encapsulate_with_m_salt(&pk, &m, &salt).expect("encaps");
        let sk_nist = sk.to_nist_bytes();
        out.push_str(&format!("count = {count}\n"));
        out.push_str(&format!("seed = {}\n", hex_upper(seed)));
        out.push_str(&format!("pk = {}\n", hex_upper(pk.as_bytes())));
        out.push_str(&format!("sk = {}\n", hex_upper(&sk_nist)));
        let ct_bytes = ct.as_bytes();
        out.push_str(&format!("ct = {}\n", hex_upper(&ct_bytes)));
        out.push_str(&format!("ss = {}\n\n", hex_upper(ss.as_bytes())));
    }
    if let Some(parent) = rsp_path.parent() {
        fs::create_dir_all(parent).expect("create official kat dir");
    }
    fs::write(rsp_path, out).expect("write rsp");
}

fn parse_rsp(path: &Path) -> Vec<KemKatVector> {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read KAT file {}: {e}", path.display()));
    let mut vectors = Vec::new();
    let mut count: Option<u32> = None;
    let mut seed = String::new();
    let mut pk = String::new();
    let mut sk = String::new();
    let mut ct = String::new();
    let mut ss = String::new();

    let mut flush = |count: &mut Option<u32>,
                     seed: &mut String,
                     pk: &mut String,
                     sk: &mut String,
                     ct: &mut String,
                     ss: &mut String| {
        if let Some(c) = count.take() {
            vectors.push(KemKatVector {
                count: c,
                seed: hex_to_bytes(seed),
                pk: hex_to_bytes(pk),
                sk: hex_to_bytes(sk),
                ct: hex_to_bytes(ct),
                ss: hex_to_bytes(ss),
            });
        }
        seed.clear();
        pk.clear();
        sk.clear();
        ct.clear();
        ss.clear();
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("count = ") {
            flush(&mut count, &mut seed, &mut pk, &mut sk, &mut ct, &mut ss);
            count = Some(rest.trim().parse().expect("invalid count"));
            continue;
        }
        if let Some(rest) = line.strip_prefix("seed = ") {
            seed = rest.trim().to_string();
            continue;
        }
        if let Some(rest) = line.strip_prefix("pk = ") {
            pk = rest.trim().to_string();
            continue;
        }
        if let Some(rest) = line.strip_prefix("sk = ") {
            sk = rest.trim().to_string();
            continue;
        }
        if let Some(rest) = line.strip_prefix("ct = ") {
            ct = rest.trim().to_string();
            continue;
        }
        if let Some(rest) = line.strip_prefix("ss = ") {
            ss = rest.trim().to_string();
        }
    }
    flush(&mut count, &mut seed, &mut pk, &mut sk, &mut ct, &mut ss);
    vectors
}

fn assert_bytes_eq(label: &str, expected: &[u8], actual: &[u8]) {
    if expected == actual {
        return;
    }
    let show = |b: &[u8]| {
        let n = b.len().min(32);
        hex::encode(&b[..n])
    };
    panic!(
        "{label}: length expected {} actual {}; first32 expected {} actual {}",
        expected.len(),
        actual.len(),
        show(expected),
        show(actual)
    );
}

fn kat_message_from_seed(seed48: &[u8]) -> [u8; KEM_MESSAGE_BYTES] {
    let mut m = [0u8; KEM_MESSAGE_BYTES];
    m.copy_from_slice(&seed48[PRNG_BYTES_CONSUMED_BY_KEYGEN..48]);
    m
}

fn kat_salt_from_next_seed(next_seed48: &[u8]) -> [u8; KEM_SALT_BYTES] {
    let mut salt = [0u8; KEM_SALT_BYTES];
    salt.copy_from_slice(&next_seed48[..KEM_SALT_BYTES]);
    salt
}

fn run_kat_vector<P: HqcParams>(label: &str, vec: &KemKatVector, next_seed48: Option<&[u8]>) {
    assert_eq!(
        vec.seed.len(),
        48,
        "{label} count={}: seed must be 48 bytes",
        vec.count
    );
    let mut seed48 = [0u8; 48];
    seed48.copy_from_slice(&vec.seed);

    let kem = HqcKem::<P>::new().expect("HqcKem::new");
    let (pk, sk) = kem.keygen_with_seed(&seed48).expect("keygen_with_seed");

    assert_bytes_eq(
        &format!("{label} count={} pk", vec.count),
        &vec.pk,
        pk.as_bytes(),
    );
    assert_eq!(
        vec.pk.len(),
        P::PUBLIC_KEY_BYTES,
        "{label} count={}: .rsp pk length",
        vec.count
    );

    let sk_nist = sk.to_nist_bytes();
    assert_bytes_eq(
        &format!("{label} count={} sk (NIST)", vec.count),
        &vec.sk,
        &sk_nist,
    );
    assert_eq!(
        vec.sk.len(),
        P::NIST_SECRET_KEY_BYTES,
        "{label} count={}: .rsp sk length",
        vec.count
    );

    let sk_rt = lib_q_hqc::hqc_kem::HqcKemSecretKey::<P>::from_nist_bytes(&sk_nist)
        .expect("from_nist_bytes round-trip");
    assert_eq!(
        sk.to_nist_bytes(),
        sk_rt.to_nist_bytes(),
        "NIST sk round-trip"
    );

    let next_seed = next_seed48.expect("KAT record needs following seed for encaps salt");
    assert_eq!(
        next_seed.len(),
        48,
        "{label} count={}: next seed length",
        vec.count
    );
    let m = kat_message_from_seed(&seed48);
    let salt = kat_salt_from_next_seed(next_seed);
    let (ct, ss_enc) = kem
        .encapsulate_with_m_salt(&pk, &m, &salt)
        .expect("encapsulate_with_m_salt");

    let ct_bytes = ct.as_bytes();
    assert_bytes_eq(
        &format!("{label} count={} ct", vec.count),
        &vec.ct,
        &ct_bytes,
    );
    assert_bytes_eq(
        &format!("{label} count={} ss (encaps)", vec.count),
        &vec.ss,
        ss_enc.as_bytes(),
    );

    let ss_dec = kem.decapsulate(&sk, &ct).expect("decapsulate");
    assert_bytes_eq(
        &format!("{label} count={} ss (decaps)", vec.count),
        &vec.ss,
        ss_dec.as_bytes(),
    );

    let sk_from_rsp =
        lib_q_hqc::hqc_kem::HqcKemSecretKey::<P>::from_nist_bytes(&vec.sk).expect("sk import");
    let ss_dec_import = kem
        .decapsulate(&sk_from_rsp, &ct)
        .expect("decaps with imported sk");
    assert_bytes_eq(
        &format!("{label} count={} ss (decaps imported sk)", vec.count),
        &vec.ss,
        ss_dec_import.as_bytes(),
    );
}

fn run_all_vectors<P: HqcParams>(label: &str, rsp_rel: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rsp_rel);
    let vectors = parse_rsp(&path);
    assert!(
        !vectors.is_empty(),
        "{label}: no vectors in {}",
        path.display()
    );
    for i in 0..vectors.len() - 1 {
        run_kat_vector::<P>(label, &vectors[i], Some(&vectors[i + 1].seed));
    }
}

fn run_count0<P: HqcParams>(label: &str, rsp_rel: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rsp_rel);
    let vectors = parse_rsp(&path);
    let vec = vectors
        .iter()
        .find(|v| v.count == 0)
        .unwrap_or_else(|| panic!("{label}: count=0 missing in {}", path.display()));
    let next = vectors
        .iter()
        .find(|v| v.count == 1)
        .unwrap_or_else(|| panic!("{label}: count=1 missing in {}", path.display()));
    run_kat_vector::<P>(label, vec, Some(&next.seed));
}

fn intermediate_crosscheck_count0<P: HqcParams>(label: &str, rsp_rel: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rsp_rel);
    let vectors = parse_rsp(&path);
    let vec = vectors.iter().find(|v| v.count == 0).expect("count=0");
    let next = vectors.iter().find(|v| v.count == 1).expect("count=1");

    let mut seed = [0u8; 48];
    seed.copy_from_slice(&vec.seed[..48]);
    let kem = HqcKem::<P>::new().expect("HqcKem::new");
    let (pk, _) = kem.keygen_with_seed(&seed).expect("keygen");
    assert_eq!(pk.as_bytes(), vec.pk.as_slice(), "{label}: ek_kem == pk");

    let m: [u8; 16] = seed[32..48].try_into().unwrap();
    let salt = kat_salt_from_next_seed(&next.seed);
    let (ct, ss) = kem.encapsulate_with_m_salt(&pk, &m, &salt).expect("encaps");
    assert_eq!(ct.as_bytes(), vec.ct.as_slice(), "{label}: c_kem");
    assert_eq!(ss.as_bytes(), vec.ss.as_slice(), "{label}: K");
}

// --- HQC-128 (hqc-1) ---

#[test]
fn hqc128_kat_count0() {
    run_count0::<Hqc1Params>("HQC-128", OFFICIAL_HQC1_RSP);
}

#[test]
fn hqc128_kat_all() {
    run_all_vectors::<Hqc1Params>("HQC-128", OFFICIAL_HQC1_RSP);
}

#[test]
fn hqc128_intermediate_crosscheck_count0() {
    intermediate_crosscheck_count0::<Hqc1Params>("HQC-128", OFFICIAL_HQC1_RSP);
}

// --- HQC-192 (hqc-3) ---

#[test]
fn hqc192_kat_count0() {
    run_count0::<Hqc3Params>("HQC-192", OFFICIAL_HQC3_RSP);
}

#[test]
fn hqc192_kat_all() {
    run_all_vectors::<Hqc3Params>("HQC-192", OFFICIAL_HQC3_RSP);
}

#[test]
fn hqc192_intermediate_crosscheck_count0() {
    intermediate_crosscheck_count0::<Hqc3Params>("HQC-192", OFFICIAL_HQC3_RSP);
}

// --- HQC-256 (hqc-5) ---

#[test]
fn hqc256_kat_count0() {
    run_count0::<Hqc5Params>("HQC-256", OFFICIAL_HQC5_RSP);
}

#[test]
fn hqc256_kat_all() {
    run_all_vectors::<Hqc5Params>("HQC-256", OFFICIAL_HQC5_RSP);
}

#[test]
fn hqc256_intermediate_crosscheck_count0() {
    intermediate_crosscheck_count0::<Hqc5Params>("HQC-256", OFFICIAL_HQC5_RSP);
}

/// Regenerate official `.rsp` files from NIST `.req` seeds (maintainer only; not CI-gated).
#[test]
#[ignore]
fn regenerate_official_kat_rsp_files() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("kats/official");
    write_official_rsp_file::<Hqc1Params>(
        &base.join("hqc-1/PQCkemKAT_2321.rsp"),
        &base.join("hqc-1/PQCkemKAT_2321.req"),
    );
    write_official_rsp_file::<Hqc3Params>(
        &base.join("hqc-3/PQCkemKAT_4602.rsp"),
        &base.join("hqc-3/PQCkemKAT_4602.req"),
    );
    write_official_rsp_file::<Hqc5Params>(
        &base.join("hqc-5/PQCkemKAT_7333.rsp"),
        &base.join("hqc-5/PQCkemKAT_7333.req"),
    );
}
