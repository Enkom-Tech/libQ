//! BLNS presentation L4, first slice: the Rust port of LaZer's public-parameter expansion must equal
//! LaZer's own output byte for byte.
//!
//! Oracle: `tests/vectors/lazer_anon_cred_pp_v0.txt`, printed by LaZer's unmodified C code at
//! commit 10eafeca (see the file header and `tests/lazer-ref/gen_anon_cred_pp_kat.sh`).

use lib_q_lattice_zkp::lazer::{LazerPolyMat, LazerRng, anon_cred_public_params};

const KAT: &str = include_str!("vectors/lazer_anon_cred_pp_v0.txt");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

struct Kat {
    seed: [u8; 32],
    rng: Vec<u8>,
    polys: Vec<(String, usize, usize, Vec<i64>)>,
}

fn parse() -> Kat {
    let mut seed = None;
    let mut rng = None;
    let mut polys = Vec::new();
    for line in KAT.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let mut f = line.split_whitespace();
        match f.next() {
            Some("seed") => seed = Some(unhex(f.next().expect("seed hex"))),
            Some("rng") => rng = Some(unhex(f.next().expect("rng hex"))),
            Some("poly") => {
                let name = f.next().expect("name").to_owned();
                let i = f.next().expect("i").parse().expect("i");
                let j = f.next().expect("j").parse().expect("j");
                let c: Vec<i64> = f.map(|x| x.parse().expect("coeff")).collect();
                assert_eq!(c.len(), 64);
                polys.push((name, i, j, c));
            }
            other => panic!("unexpected KAT line kind {other:?}"),
        }
    }
    Kat {
        seed: seed.expect("seed line").try_into().expect("32-byte seed"),
        rng: rng.expect("rng line"),
        polys,
    }
}

#[test]
fn rng_stream_equals_lazer() {
    let kat = parse();
    let mut out = vec![0u8; kat.rng.len()];
    LazerRng::new(&kat.seed, 1u64 << 32).fill(&mut out);
    assert_eq!(out, kat.rng);
}

#[test]
fn public_params_equal_lazer() {
    let kat = parse();
    let pp = anon_cred_public_params().expect("anon_cred modulus is supported");
    assert_eq!(
        pp.blindsig_seed, kat.seed,
        "BLINDSIGPP = SHAKE128(0x00)[..32]"
    );
    let mat = |name: &str| -> &LazerPolyMat {
        match name {
            "AR" => &pp.ar,
            "AM" => &pp.am,
            "ATAU" => &pp.atau,
            other => panic!("unknown matrix {other}"),
        }
    };
    let mut seen = [0usize; 3];
    for (name, i, j, coeffs) in &kat.polys {
        assert_eq!(&mat(name).get(*i, *j)[..], &coeffs[..], "{name}[{i}][{j}]");
        seen[["AR", "AM", "ATAU"]
            .iter()
            .position(|n| n == name)
            .expect("name")] += 1;
    }
    // every element of every matrix is covered by the oracle, none skipped
    assert_eq!(seen, [8 * 16, 8 * 8, 8 * 8]);
    assert_eq!((pp.ar.rows, pp.ar.cols), (8, 16));
    assert_eq!((pp.am.rows, pp.am.cols), (8, 8));
    assert_eq!((pp.atau.rows, pp.atau.cols), (8, 8));
}
