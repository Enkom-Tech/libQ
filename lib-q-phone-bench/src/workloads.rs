//! Workloads measured by the harness. Each returns raw per-iteration timings and the proof size
//! as it would be serialised on the wire. Add a new credential workload by appending to
//! [`ALL`]; nothing else in the harness changes.

use std::time::Instant;

use lib_q_lattice_zkp::{
    AjtaiCommitmentKey, AjtaiOpening, LatticeZkpProfileV0, MerklePath, commit,
    decode_opening_proof_v0, encode_opening_proof_v0, encode_private_membership_proof_v0,
    encode_pvtn_leaf, leaf_hash, node_hash, prove_opening, prove_private_membership,
    verify_opening, verify_private_membership, wire_byte_len,
};
use lib_q_random::new_deterministic_rng;
use lib_q_ring::{ModuleVec, Poly};
use lib_q_stark_baby_bear::BabyBear;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::air::unlinkable_membership_baby_bear::{
    CTX_ELEMS as BB_CTX_ELEMS, SECRET_T_ELEMS as BB_SECRET_T_ELEMS, membership_leaf_bb,
};
use lib_q_zkp::air::wide_merkle_path_baby_bear::WideDigestBb;
use lib_q_zkp::air::{CTX_ELEMS, SECRET_T_ELEMS, WideDigest, membership_leaf};
use lib_q_zkp::membership::{
    MembershipWitness, encode_membership_envelope, prove_unlinkable_membership_zk_auto,
    public_statement_bytes, verify_membership_envelope,
};
use lib_q_zkp::merkle::wide_node_hash;
use lib_q_zkp::merkle_baby_bear::wide_node_hash_bb;
use lib_q_zkp::stark_baby_bear::{
    default_zk_config_bb, prove_membership_bb_zk, verify_membership_bb_zk,
};

/// Raw result of one workload run.
pub struct Measure {
    pub prove_ns: Vec<u128>,
    pub verify_ns: Vec<u128>,
    pub wire_bytes: usize,
}

/// Which credential track a workload belongs to (selects the decision-rule thresholds).
#[derive(Clone, Copy)]
pub enum Track {
    /// Lattice track, step L5.
    Lattice,
    /// STARK track, step S3.
    Stark,
}

impl Track {
    pub fn as_str(self) -> &'static str {
        match self {
            Track::Lattice => "lattice",
            Track::Stark => "stark",
        }
    }
}

pub struct Workload {
    pub name: &'static str,
    pub track: Track,
    /// `true` while the workload is a stand-in for the real credential statement. The compare
    /// script refuses to give a pass/fail verdict from a stand-in.
    pub standin: bool,
    pub desc: &'static str,
    pub run: fn(iters: usize, depth: usize) -> Result<Measure, String>,
}

pub const ALL: &[Workload] = &[
    Workload {
        name: "lattice.private_membership",
        track: Track::Lattice,
        standin: true,
        desc: "lib-q-lattice-zkp private membership proof (PVTN profile). STAND-IN for the BLNS \
               L3-profile presentation (L4), which is not implemented yet.",
        run: lattice_private_membership,
    },
    Workload {
        name: "lattice.opening",
        track: Track::Lattice,
        standin: true,
        desc: "lib-q-lattice-zkp Ajtai opening proof (token-spend profile). STAND-IN, see above.",
        run: lattice_opening,
    },
    Workload {
        name: "stark.membership_bb_zk",
        track: Track::Stark,
        standin: true,
        desc: "Arm B (BabyBear/Poseidon2, 128-bit PQ) hiding membership proof, the arm whose size \
               the research note quotes (0.95-1.21 MB). --depth is rounded up to a power of two, min 8. \
               Size = postcard(StarkProof). STAND-IN for the narrow-trace AIR (S1/S2).",
        run: stark_membership_bb_zk,
    },
    Workload {
        name: "stark.membership_zk",
        track: Track::Stark,
        standin: true,
        desc: "Arm A (Complex<Mersenne31>/Poseidon256) hiding proof at --depth (default 20), \
               verified from the frozen wire envelope. About 17 MB: a different arm from the one \
               the research note quotes. Kept as the frozen-wire reference. STAND-IN (S1/S2).",
        run: stark_membership_zk,
    },
];

fn time<T>(f: impl FnOnce() -> T) -> (T, u128) {
    let t = Instant::now();
    let v = f();
    (v, t.elapsed().as_nanos())
}

const SEED: [u8; 32] = [0x47u8; 32];

fn lattice_private_membership(iters: usize, _depth: usize) -> Result<Measure, String> {
    let profile = LatticeZkpProfileV0::pvtn_membership_v0();
    let key = AjtaiCommitmentKey {
        seed: SEED,
        params: profile.ajtai.clone(),
    };
    let opening = AjtaiOpening {
        message: ModuleVec(vec![Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let com = commit(&key, &opening);
    let role = [0x5Au8; 16];
    let leaf_payload = encode_pvtn_leaf(8, &role, &[0u8; 32]);
    let l0 = leaf_hash(b"bench-0");
    let l1 = leaf_hash(&leaf_payload);
    let root = node_hash(&l0, &l1);

    let mut m = Measure {
        prove_ns: vec![],
        verify_ns: vec![],
        wire_bytes: 0,
    };
    for _ in 0..iters {
        let mut rng = new_deterministic_rng(SEED);
        let path = MerklePath {
            path_index: 1,
            siblings: vec![l0],
        };
        let (proof, ns) = time(|| {
            prove_private_membership(
                &mut rng,
                &key,
                &opening,
                &com,
                leaf_payload.clone(),
                path,
                &root,
                3,
                b"phone-bench",
                profile.tau,
                profile.z_inf_bound,
                profile.max_prove_attempts,
            )
        });
        let proof = proof.map_err(|e| format!("prove: {e:?}"))?;
        m.prove_ns.push(ns);
        let wire = encode_private_membership_proof_v0(&profile, &proof, &root, 3)
            .map_err(|e| format!("encode: {e:?}"))?;
        m.wire_bytes = wire_byte_len(&wire);
        let (r, ns) = time(|| {
            verify_private_membership(
                &key,
                &proof,
                &root,
                3,
                b"phone-bench",
                profile.tau,
                profile.z_inf_bound,
            )
        });
        r.map_err(|e| format!("verify: {e:?}"))?;
        m.verify_ns.push(ns);
    }
    Ok(m)
}

fn lattice_opening(iters: usize, _depth: usize) -> Result<Measure, String> {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let key = AjtaiCommitmentKey {
        seed: SEED,
        params: profile.ajtai.clone(),
    };
    let opening = AjtaiOpening {
        message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let com = commit(&key, &opening);
    let mut m = Measure {
        prove_ns: vec![],
        verify_ns: vec![],
        wire_bytes: 0,
    };
    for _ in 0..iters {
        let mut rng = new_deterministic_rng(SEED);
        let (proof, ns) = time(|| {
            prove_opening(
                &mut rng,
                &key,
                &opening,
                &com,
                b"phone-bench",
                profile.tau,
                profile.z_inf_bound,
                profile.max_prove_attempts,
            )
        });
        let proof = proof.map_err(|e| format!("prove: {e:?}"))?;
        m.prove_ns.push(ns);
        let wire =
            encode_opening_proof_v0(&profile, &proof).map_err(|e| format!("encode: {e:?}"))?;
        m.wire_bytes = wire_byte_len(&wire);
        let (r, ns) = time(|| {
            decode_opening_proof_v0(&wire)
                .map_err(|e| format!("decode: {e:?}"))
                .and_then(|(p, _)| {
                    verify_opening(
                        &key,
                        &com,
                        &p,
                        b"phone-bench",
                        profile.tau,
                        profile.z_inf_bound,
                    )
                    .map_err(|e| format!("verify: {e:?}"))
                })
        });
        r?;
        m.verify_ns.push(ns);
    }
    Ok(m)
}

fn fe(x: u64) -> Complex<Mersenne31> {
    // Mersenne31 modulus is 2^31 - 1; keep values canonical.
    Complex::<Mersenne31>::from(Mersenne31::new((x % 0x7FFF_FFFF) as u32))
}

/// Cheap deterministic stream (splitmix64): fixture data only, never key material.
fn stream(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn stark_membership_zk(iters: usize, depth: usize) -> Result<Measure, String> {
    // A real depth-D tree is not needed: fold the leaf along random siblings to get a root.
    // This is the same relation the verifier checks, at any depth, without building 2^D leaves.
    let mut st = 0x00C0_FFEE_u64;
    let t: [_; SECRET_T_ELEMS] = core::array::from_fn(|_| fe(stream(&mut st)));
    let ctx: [_; CTX_ELEMS] = core::array::from_fn(|_| fe(stream(&mut st)));
    let siblings: Vec<WideDigest> = (0..depth)
        .map(|_| core::array::from_fn(|_| fe(stream(&mut st))))
        .collect();
    let path_bits: Vec<bool> = (0..depth).map(|_| stream(&mut st) & 1 == 1).collect();
    let mut root = membership_leaf(&t);
    for (bit, sib) in path_bits.iter().zip(&siblings) {
        root = if *bit {
            wide_node_hash(sib, &root)
        } else {
            wide_node_hash(&root, sib)
        };
    }
    let witness = MembershipWitness {
        t,
        ctx,
        path_bits,
        siblings,
    };

    let mut m = Measure {
        prove_ns: vec![],
        verify_ns: vec![],
        wire_bytes: 0,
    };
    for _ in 0..iters {
        let (r, ns) = time(|| prove_unlinkable_membership_zk_auto(&witness));
        let (nullifier, proof) = r.map_err(|e| format!("prove: {e:?}"))?;
        m.prove_ns.push(ns);
        let envelope = encode_membership_envelope(&proof).map_err(|e| format!("encode: {e:?}"))?;
        m.wire_bytes = envelope.len();
        let stmt = public_statement_bytes(&root, &witness.ctx, &nullifier);
        let (ok, ns) = time(|| verify_membership_envelope(&stmt, &envelope));
        if !ok {
            return Err("membership envelope failed to verify".into());
        }
        m.verify_ns.push(ns);
    }
    Ok(m)
}

fn bb(x: u64) -> BabyBear {
    // BabyBear p = 0x7800_0001; keep values canonical.
    BabyBear::new((x % 0x7800_0001) as u32)
}

fn stark_membership_bb_zk(iters: usize, depth: usize) -> Result<Measure, String> {
    // The BabyBear trace height is the depth and must be a power of two >= MIN_ZK_DEPTH.
    let depth = depth.next_power_of_two().max(8);
    let mut st = 0xBABE_BEA2u64;
    let t: [BabyBear; BB_SECRET_T_ELEMS] = core::array::from_fn(|_| bb(stream(&mut st)));
    let ctx: [BabyBear; BB_CTX_ELEMS] = core::array::from_fn(|_| bb(stream(&mut st)));
    let siblings: Vec<WideDigestBb> = (0..depth)
        .map(|_| core::array::from_fn(|_| bb(stream(&mut st))))
        .collect();
    let path_bits: Vec<bool> = (0..depth).map(|_| stream(&mut st) & 1 == 1).collect();
    let mut root = membership_leaf_bb(&t);
    for (bit, sib) in path_bits.iter().zip(&siblings) {
        root = if *bit {
            wide_node_hash_bb(sib, &root)
        } else {
            wide_node_hash_bb(&root, sib)
        };
    }
    let mut m = Measure {
        prove_ns: vec![],
        verify_ns: vec![],
        wire_bytes: 0,
    };
    for i in 0..iters {
        // Fresh blinding seeds per proof, as a production prover would use. Seeds only vary the
        // randomness; timings do not depend on their values.
        let mut v = [0u8; 32];
        let mut p = [0u8; 32];
        let mut s2 = st ^ (i as u64).wrapping_mul(0x1234_5678_9ABC_DEF1);
        for c in v.chunks_mut(8).chain(p.chunks_mut(8)) {
            c.copy_from_slice(&stream(&mut s2).to_le_bytes());
        }
        let config = default_zk_config_bb(v, p);
        let (r, ns) =
            time(|| prove_membership_bb_zk(&config, &t, &ctx, &path_bits, &siblings, &root));
        let (nullifier, proof) = r.map_err(|e| format!("prove: {e:?}"))?;
        m.prove_ns.push(ns);
        m.wire_bytes = postcard::to_allocvec(&proof)
            .map_err(|e| format!("encode: {e:?}"))?
            .len();
        let (ok, ns) = time(|| verify_membership_bb_zk(&config, &proof, &root, &ctx, &nullifier));
        if !ok {
            return Err("arm B membership proof failed to verify".into());
        }
        m.verify_ns.push(ns);
    }
    Ok(m)
}
