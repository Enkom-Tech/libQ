//! NIST-style Classic McEliece KAT (Known Answer Test) harness.
//!
//! ## Provenance note (read before trusting this file)
//!
//! Genuine, byte-exact official Classic McEliece KAT `.rsp` answer files are **not**
//! distributed as downloadable artifacts by the scheme's own site
//! (`https://classic.mceliece.org/nist/mceliece-20221023.tar.gz`) or by NIST. That
//! submission package ships only the *generator* C source
//! (`Reference_Implementation/kem/<variant>/nist/kat_kem.c` + `nist/rng.c`, the
//! canonical `PQCgenKAT_kem.c` + AES256-CTR-DRBG `rng.c` pair) — not precomputed
//! answer files. Producing genuine vectors independent of this Rust implementation
//! requires compiling that official C reference code (it links OpenSSL's
//! `libcrypto` for AES) and running its `kat_kem` binary. That toolchain
//! (OpenSSL dev headers) was not available in the environment this harness was
//! authored in, so no independently-sourced vector file is checked into this
//! crate. See `CBKEM348864_KAT_RSP` below for how to plug one in once obtained.
//!
//! ## What this harness actually verifies today
//!
//! `self_consistency_roundtrip_348864` below drives `lib_q_cb_kem`'s own
//! `AesState` NIST SP 800-90A CTR_DRBG (`nist-aes-rng` feature) through the same
//! seed-derivation structure as the official `PQCgenKAT_kem.c`
//! (per-testcase 48-byte seed -> re-seed a fresh DRBG -> keypair/encaps/decaps),
//! writes a `.req`/`.rsp` pair to a temp dir in the official text format, and
//! checks the run is internally deterministic (same seeds byte-exact reproduce
//! the same file) and that encaps/decaps agree. This is a self-consistency
//! check, NOT a comparison against an external, independently-generated
//! oracle — do not read a pass here as "matches NIST's published vectors".
//!
//! `official_kat_348864` is the harness that *would* do the real check: it
//! looks for a genuine vector file named by the `CBKEM348864_KAT_RSP` env var
//! (or `data/kat/cbkem348864.rsp` by default) and FAILS LOUDLY with instructions
//! if it is absent, rather than silently skipping or fabricating a result.

#![cfg(all(feature = "cbkem348864", feature = "nist-aes-rng", feature = "alloc"))]

use std::fs;
use std::io::{
    BufRead,
    BufReader,
    Write,
};
use std::path::Path;

use lib_q_cb_kem::{
    AesState,
    CRYPTO_BYTES,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    decapsulate,
    encapsulate,
    keypair,
};

const SEEDLEN: usize = 48;
/// Official submissions use KATNUM = 100. We keep it small here because Classic
/// McEliece keygen is slow and this runs in CI on every push; the harness logic
/// itself does not depend on the count.
const KATNUM: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Testcase {
    count: usize,
    seed: [u8; SEEDLEN],
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn write_testcase(fd: &mut fs::File, tc: &Testcase) -> std::io::Result<()> {
    writeln!(fd, "count = {}", tc.count)?;
    writeln!(fd, "seed = {}", hex_upper(&tc.seed))?;
    writeln!(fd, "pk = {}", hex_upper(&tc.pk))?;
    writeln!(fd, "sk = {}", hex_upper(&tc.sk))?;
    writeln!(fd, "ct = {}", hex_upper(&tc.ct))?;
    writeln!(fd, "ss = {}", hex_upper(&tc.ss))?;
    writeln!(fd)
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn read_rsp(path: &Path) -> Vec<Testcase> {
    let fd = fs::File::open(path).unwrap_or_else(|e| panic!("open {path:?}: {e}"));
    let reader = BufReader::new(fd);
    let mut out = Vec::new();
    let mut cur: Option<Testcase> = None;
    for line in reader.lines() {
        let line = line.unwrap();
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, '=');
        let key = parts.next().unwrap().trim();
        let val = parts.next().unwrap_or("").trim();
        match key {
            "count" => {
                if let Some(tc) = cur.take() {
                    out.push(tc);
                }
                cur = Some(Testcase {
                    count: val.parse().unwrap(),
                    seed: [0u8; SEEDLEN],
                    pk: Vec::new(),
                    sk: Vec::new(),
                    ct: Vec::new(),
                    ss: Vec::new(),
                });
            }
            "seed" => cur.as_mut().unwrap().seed.copy_from_slice(&hex_decode(val)),
            "pk" => cur.as_mut().unwrap().pk = hex_decode(val),
            "sk" => cur.as_mut().unwrap().sk = hex_decode(val),
            "ct" => cur.as_mut().unwrap().ct = hex_decode(val),
            "ss" => cur.as_mut().unwrap().ss = hex_decode(val),
            _ => {}
        }
    }
    if let Some(tc) = cur.take() {
        out.push(tc);
    }
    out
}

/// Generates KATNUM testcases using the NIST CTR_DRBG seed schedule and this
/// crate's own keypair/encapsulate/decapsulate. Used both by the self-consistency
/// test and by the (currently unreachable without genuine vectors) official-KAT
/// comparison path.
fn generate_testcases() -> Vec<Testcase> {
    let mut entropy = [0u8; SEEDLEN];
    for (i, e) in entropy.iter_mut().enumerate() {
        *e = i as u8;
    }
    let mut seed_rng = AesState::new();
    seed_rng.randombytes_init(entropy);

    let mut cases = Vec::with_capacity(KATNUM);
    for count in 0..KATNUM {
        let mut seed = [0u8; SEEDLEN];
        rand_core::TryRng::try_fill_bytes(&mut seed_rng, &mut seed).expect("drbg generate");

        let mut tc_rng = AesState::new();
        tc_rng.randombytes_init(seed);

        let mut pk_buf = vec![0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk_buf = vec![0u8; CRYPTO_SECRETKEYBYTES];
        let pk_arr = <&mut [u8; CRYPTO_PUBLICKEYBYTES]>::try_from(pk_buf.as_mut_slice()).unwrap();
        let sk_arr = <&mut [u8; CRYPTO_SECRETKEYBYTES]>::try_from(sk_buf.as_mut_slice()).unwrap();
        let (pk, sk) = keypair(pk_arr, sk_arr, &mut tc_rng);

        let mut ss1 = [0u8; CRYPTO_BYTES];
        let (ct, ss) = encapsulate(&pk, &mut ss1, &mut tc_rng);
        let mut ss2 = [0u8; CRYPTO_BYTES];
        let ss_dec = decapsulate(&ct, &sk, &mut ss2);
        assert_eq!(
            ss.as_ref(),
            ss_dec.as_ref(),
            "encaps/decaps shared secret mismatch for testcase {count}"
        );

        cases.push(Testcase {
            count,
            seed,
            pk: pk.as_array().to_vec(),
            sk: sk.as_array().to_vec(),
            ct: ct.as_ref().to_vec(),
            ss: ss.as_ref().to_vec(),
        });
    }
    cases
}

/// Self-consistency KAT: NOT an external oracle. See module docs.
#[test]
fn self_consistency_roundtrip_348864() {
    let dir = std::env::temp_dir().join(format!(
        "lib-q-cb-kem-katkem-selfcheck-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let rsp_path = dir.join("cbkem348864.rsp");

    let cases = generate_testcases();
    {
        let mut fd = fs::File::create(&rsp_path).unwrap();
        writeln!(fd, "# kem/cbkem348864\n").unwrap();
        for tc in &cases {
            write_testcase(&mut fd, tc).unwrap();
        }
    }

    // Re-derive from the same seeds and confirm byte-exact reproduction
    // (this is the load-bearing determinism property KATs rely on).
    let reproduced = generate_testcases();
    assert_eq!(
        cases, reproduced,
        "regenerating from identical seeds produced different output; \
         the DRBG-driven keygen/encaps/decaps path is not deterministic"
    );

    // And confirm the file on disk parses back to the same testcases.
    let parsed = read_rsp(&rsp_path);
    assert_eq!(parsed, cases, "on-disk .rsp round-trip mismatch");

    let _ = fs::remove_dir_all(&dir);
}

/// The harness that would perform a genuine, externally-sourced KAT check.
/// FAILS LOUDLY (does not skip, does not fabricate) when no real vector file
/// is present, per this crate's KAT-provenance policy.
#[test]
#[ignore = "requires an externally-sourced NIST KAT vector file (CBKEM348864_KAT_RSP); \
            not available in this environment, see module docs — run explicitly with \
            `cargo test --release --features cbkem348864,nist-aes-rng,alloc,std --test katkem -- --ignored official_kat_348864`"]
fn official_kat_348864() {
    #[allow(clippy::disallowed_methods, reason = "test-only opt-in vector path")]
    let path = std::env::var("CBKEM348864_KAT_RSP")
        .unwrap_or_else(|_| "data/kat/cbkem348864.rsp".to_string());
    let path = Path::new(&path);

    if !path.exists() {
        panic!(
            "\n\n\
            No genuine Classic McEliece mceliece348864 KAT vector file found at {path:?}.\n\
            This crate refuses to fabricate vectors from the implementation under test.\n\n\
            To obtain a genuine, independently-generated vector file:\n\
              1. Download the official NIST submission package: \n\
                 https://classic.mceliece.org/nist/mceliece-20221023.tar.gz\n\
              2. Build Reference_Implementation/kem/mceliece348864 (links OpenSSL libcrypto\n\
                 for nist/rng.c's AES256_ECB — install OpenSSL dev headers/libs first).\n\
              3. Run its 'kat' target (see the Makefile) to produce PQCkemKAT_*.rsp,\n\
                 OR use a third-party build of the same official C reference code.\n\
              4. Point this test at it: set CBKEM348864_KAT_RSP=<path to .rsp>,\n\
                 or copy it to lib-q-cb-kem/data/kat/cbkem348864.rsp.\n\n\
            Until then, only self-consistency is checked (see \
            self_consistency_roundtrip_348864) — that is NOT equivalent to this check.\n"
        );
    }

    let expected = read_rsp(path);
    assert!(
        !expected.is_empty(),
        "vector file {path:?} parsed to zero testcases"
    );

    // Re-derive our implementation's output for the same seeds found in the
    // vector file and compare byte-for-byte against the external file.
    let mut actual = Vec::with_capacity(expected.len());
    for exp in &expected {
        let mut tc_rng = AesState::new();
        tc_rng.randombytes_init(exp.seed);

        let mut pk_buf = vec![0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk_buf = vec![0u8; CRYPTO_SECRETKEYBYTES];
        let pk_arr = <&mut [u8; CRYPTO_PUBLICKEYBYTES]>::try_from(pk_buf.as_mut_slice()).unwrap();
        let sk_arr = <&mut [u8; CRYPTO_SECRETKEYBYTES]>::try_from(sk_buf.as_mut_slice()).unwrap();
        let (pk, sk) = keypair(pk_arr, sk_arr, &mut tc_rng);

        let mut ss1 = [0u8; CRYPTO_BYTES];
        let (ct, ss) = encapsulate(&pk, &mut ss1, &mut tc_rng);
        let mut ss2 = [0u8; CRYPTO_BYTES];
        let ss_dec = decapsulate(&ct, &sk, &mut ss2);
        assert_eq!(ss.as_ref(), ss_dec.as_ref());

        actual.push(Testcase {
            count: exp.count,
            seed: exp.seed,
            pk: pk.as_array().to_vec(),
            sk: sk.as_array().to_vec(),
            ct: ct.as_ref().to_vec(),
            ss: ss.as_ref().to_vec(),
        });
    }

    for (e, a) in expected.iter().zip(actual.iter()) {
        assert_eq!(e.seed, a.seed, "testcase {}: seed mismatch", e.count);
        assert_eq!(e.pk, a.pk, "testcase {}: public key mismatch", e.count);
        assert_eq!(e.sk, a.sk, "testcase {}: secret key mismatch", e.count);
        assert_eq!(e.ct, a.ct, "testcase {}: ciphertext mismatch", e.count);
        assert_eq!(e.ss, a.ss, "testcase {}: shared secret mismatch", e.count);
    }
    println!(
        "verification successful against {path:?} ({} testcases).",
        expected.len()
    );
}
