//! Production entry-point assembly for the **byte-provenance** encryption proof (task #26): the
//! composition that binds the ciphertext's witness `e` to the deterministic FO expansion
//! `e = XOF(DOM_FO_SEED ‖ pk_digest ‖ μ)` AND proves `e` ternary, then feeds those *bound* `e_r`
//! folds into the R3b relation `v = Σ_r t0_r·e_r + g + encode(μ)`. This is the layer that makes the
//! partial-decap gate ([`crate::gate`]) non-vacuous for the `e`-probe class: a witness `e` that is not
//! the genuine SHAKE output (or not ternary) cannot produce a verifying proof, because the join
//! balances / sampler range constraints reject it.
//!
//! ## Relationship to [`crate::prove`]
//! [`crate::prove::prove_relation_layer`] proves ONLY the R3 linear relations over **free**
//! `(e, f, g)` — it has no sponge/sampler/joins, so it is vacuous as a malformed-ciphertext closure
//! (see the `# WARNING` in [`crate::gate`]). This module adds the sponge (`ShakeSpongeAir`), the
//! squeeze-byte bridge (`SqueezeByteAir`), and the ternary sampler (`TernarySamplerAir`), wired by the
//! three LogUp joins (SQUEEZE_LIMB → XOF_STREAM → COEFF_E → FOLD_E), so the `e_r` folds the R3b
//! relation consumes are provably the XOF-derived, ternary `e`. It is the `#[cfg(test)]` vertical slice
//! `compose::tests::compose_r3b_e_provenance_real_ciphertext` promoted to real, callable API.
//!
//! ## Config-agnostic, like [`crate::prove`]
//! `lib_q_plonky_batch_stark::prove_batch<SC, A>` is bounded by a folder type the batch crate does not
//! re-export, and the FRI/MMCS/challenger crates are dev-dependencies, so this module cannot construct
//! the config or name the `prove_batch` bound. It therefore exposes the (config-independent) assembly:
//! [`assemble_e_provenance_prover`] (needs the witness) and [`assemble_e_provenance_verifier`] (public
//! inputs + the [`EncProofShape`] only). The caller runs `build_preprocessed` + `prove_batch` /
//! `verify_batch` with the config it chose (test or **production** FRI params — see the module tests for
//! both, and the gate-wiring test that turns this into a sound `proof_verifies` closure).
//!
//! ## Honest scope (what this binds — and does NOT yet)
//! * **Binds:** `e` (all `MU·N` coefficients) to the genuine SHAKE-256 output AND to `{-1,0,+1}`
//!   (the ternary sampler AIR), and proves the R3b `v`-equation over those bound `e_r`.
//! * **Does NOT yet bind:** `f` (the R3a `p`-equations' errors) or `g`'s byte-provenance — those folds
//!   are fed directly here. The classic `f = δ·unitₖ` R3a spike therefore needs the `f`-sampler
//!   extension (bounded sampler at the XOF byte-offset after `e`), tracked as the remaining #26 work;
//!   the `e`-provenance closed here is the same machinery applied to a heavier (~90 KB) sponge.
//! * **Single Fiat–Shamir challenge.** One `ζ = derive_zetas(ct)[0]`. Multi-challenge soundness
//!   amplification requires per-challenge COEFF/FOLD buses (or send-multiplicity = #challenges) so the
//!   one sampler's coefficient Sends are not double-Received — a straightforward but not-yet-wired
//!   extension; a single challenge over the `Complex<Mersenne31>` (~2^62) field already gives
//!   soundness error ≈ deg/|F| ≈ 2^-52 for the degree-`N` relation.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use lib_q_dkg::lattice::bdlop::MU;
use lib_q_dkg::lattice::ring::{
    N,
    Rq,
};
use lib_q_plonky_keccak_air::{
    NUM_KECCAK_COLS,
    NUM_ROUNDS,
};
use lib_q_plonky_lookup::Lookup;
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_threshold_kem_lattice::kem::{
    Ciphertext,
    encapsulate_derand,
    encode_msg,
    fo_expand_witness,
};
use lib_q_zkp::stark::ConfigVal;

use crate::compose::EncProofAir;
use crate::error::EncProofError;
use crate::logup_join::{
    COEFF_E_BUS,
    FOLD_E_BUS,
    fc,
};
use crate::relation_assembly::{
    derive_zetas,
    r3b_public_coeffs,
    r3b_quotient_poly,
    rq_coeffs_zq,
};
use crate::sampler::{
    SAMPLER_WIDTH,
    TernarySamplerAir,
    generate_ternary_trace,
    ternary_coeff_send_lookups_at,
    ternary_public_values,
    ternary_receive_lookup,
};
use crate::sponge::RATE_BYTES;
use crate::sponge_air::{
    ShakeSpongeAir,
    encap_preimage,
    generate_provable_sponge_trace,
    sponge_limb_send_lookups,
    sponge_public_values,
};
use crate::squeeze_byte::{
    SqueezeByteAir,
    generate_squeeze_byte_trace_partial,
    squeeze_byte_limb_receive_lookup,
    squeeze_byte_send_lookup,
};
use crate::zq::{
    EncodeMuFoldAir,
    HornerFoldAir,
    RelationCheckAir,
    encode_mu_public_values,
    generate_encode_mu_trace,
    generate_horner_trace,
    generate_relation_trace,
    horner_coeff_receive_lookups_at,
    horner_e_send_lookups_at,
    horner_public_values,
};

/// The **public** shape parameters of a byte-provenance proof: the sizes the prover chose (sponge
/// height / squeeze coverage / consumed-byte count) that the verifier must rebuild the AIRs and
/// lookups against. These are NOT secret — they are a function of `e`'s XOF rejection-sampling byte
/// consumption (a mild `μ`-dependent leak addressed by the hiding-FRI ZK path, task #32, not a
/// soundness issue: the joins enforce that the sponge covers every consumed byte regardless of the
/// declared sizes). Communicated alongside the proof; the verifier feeds them to
/// [`assemble_e_provenance_verifier`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncProofShape {
    /// Row count of the sponge trace (a power of two ≥ the squeeze coverage of `e`'s bytes).
    pub sponge_height: usize,
    /// Ternary sampler coefficient count (`MU · N`).
    pub num_e_coeffs: usize,
    /// The number of 16-bit limbs the squeeze-byte table covers (the sponge's full squeeze).
    pub sponge_full_limbs: usize,
    /// The number of XOF bytes the `e`-sampler consumed (the byte prefix forwarded to it).
    pub consumed_bytes: usize,
}

/// The assembled instances of the byte-provenance ⇒ R3b layer (prover side): parallel vectors indexed
/// by batch instance. Build `StarkInstance`s by zipping these (the traces are owned here and borrowed
/// by the instances), then call `prove_batch`.
pub struct EncProvenanceProver {
    /// One enum-wrapped AIR per instance.
    pub airs: Vec<EncProofAir>,
    /// The witness trace for each instance (borrowed by the `StarkInstance`s).
    pub traces: Vec<RowMajorMatrix<ConfigVal>>,
    /// Public values per instance.
    pub public_values: Vec<Vec<ConfigVal>>,
    /// Global-bus lookups per instance (also the verifier-trusted `CommonData` lookups).
    pub lookups: Vec<Vec<Lookup<ConfigVal>>>,
}

/// The assembled instances (verifier side): no traces; the sponge public values are rebuilt from
/// `ct.pk_digest` (the load-bearing pk binding) and the relation public coefficients from
/// `(t0, ct, ζ)`. Feed to `verify_batch`.
pub struct EncProvenanceVerifier {
    /// One enum-wrapped AIR per instance (same order as the prover).
    pub airs: Vec<EncProofAir>,
    /// Public values per instance.
    pub public_values: Vec<Vec<ConfigVal>>,
    /// Global-bus lookups per instance (the verifier-trusted `CommonData` lookups).
    pub lookups: Vec<Vec<Lookup<ConfigVal>>>,
}

/// The relation-instance public values (`a_j` limbs low-to-high, then `c` limbs) — the verifier
/// rebuild of what `generate_relation_trace` returns, from the recomputed public coefficients. (Same
/// layout as [`crate::prove`]'s private helper; kept local so the two entry points stay independent.)
fn relation_public_values(a: &[u64], c: u64) -> Vec<ConfigVal> {
    let mut pubs = Vec::with_capacity((a.len() + 1) * 4);
    for &x in a {
        for limb in 0..4 {
            pubs.push(fc((x >> (12 * limb)) & 0xFFF));
        }
    }
    for limb in 0..4 {
        pubs.push(fc((c >> (12 * limb)) & 0xFFF));
    }
    pubs
}

/// Pad a height-2 relation trace to 64 rows by repeating the `is_first = 0` replica row (matches the
/// composition tests' relation height).
const RELATION_HEIGHT: usize = 64;
fn pad_relation(rm: &RowMajorMatrix<ConfigVal>) -> RowMajorMatrix<ConfigVal> {
    let w = rm.width;
    let mut vals = Vec::with_capacity(RELATION_HEIGHT * w);
    vals.extend_from_slice(&rm.values[0..w]);
    for _ in 0..RELATION_HEIGHT - 1 {
        vals.extend_from_slice(&rm.values[w..2 * w]);
    }
    RowMajorMatrix::new(vals, w)
}

/// Count active (real, non-padding) rows of a sampler trace (column 0 = the active flag).
fn active_rows(trace: &RowMajorMatrix<ConfigVal>, width: usize) -> usize {
    (0..trace.values.len() / width)
        .filter(|&r| trace.values[r * width] == ConfigVal::ONE)
        .count()
}

/// **Prover** assembly of the `e`-byte-provenance ⇒ R3b layer for `(t0, μ)`.
///
/// Derives the ciphertext + witness (`encapsulate_derand` / `fo_expand_witness`), builds the SHAKE
/// sponge over the real FO preimage covering `e`'s consumed bytes, the squeeze-byte bridge, the ternary
/// `e`-sampler (`MU·N` coeffs), the `MU` `e_r` folds (byte-bound via join 2 at per-ring-element bases),
/// the `g`/`encode(μ)`/quotient folds (fed directly), and the R3b relation receiving all `MU+3` folds
/// (join 3). Returns the ciphertext, the [`EncProofShape`] the verifier needs, and the assembled
/// instances. The Fiat–Shamir challenge is `ζ = derive_zetas(ct)[0]` — verifier-recomputable, never
/// prover-supplied.
///
/// # Errors
/// [`EncProofError::TraceGeneration`] if a trace generator rejects its inputs (e.g. the R3b numerator
/// is not divisible by `X^N+1` — impossible for a well-formed witness).
pub fn assemble_e_provenance_prover(
    t0: &[Rq],
    mu: &[u8; 32],
) -> Result<(Ciphertext, EncProofShape, EncProvenanceProver), EncProofError> {
    let ct = encapsulate_derand(t0, mu);
    let w = fo_expand_witness(t0, mu);
    let input = encap_preimage(&w.pk_digest, mu);

    // e-sampler over the real XOF (MU·N ternary coeffs); sponge covers e's consumed bytes.
    let num_e = MU * N;
    let bytes = shake256_xof(&input, num_e * 2 + 4096);
    let e_sampler = generate_ternary_trace(&bytes, num_e)?;
    let consumed = active_rows(&e_sampler, SAMPLER_WIDTH);
    let sponge = generate_provable_sponge_trace(&input, consumed + RATE_BYTES);
    let height = sponge.values.len() / NUM_KECCAK_COLS;
    let blocks = sponge_squeeze_blocks(height);
    let full_limbs = blocks * (RATE_BYTES / 2);
    let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, consumed);

    let zeta = derive_zetas(&ct.to_bytes(), 1)[0];

    // R3b public coefficients + quotient (over the real witness).
    let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
    let e_lifts: Vec<Vec<u64>> = w.e.iter().map(rq_coeffs_zq).collect();
    let e_ref: Vec<&[u64]> = e_lifts.iter().map(|v| v.as_slice()).collect();
    let v_z = rq_coeffs_zq(&ct.v);
    let g_z = rq_coeffs_zq(&w.g);
    let encode_z = rq_coeffs_zq(&encode_msg(mu));
    let (a, c) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
    let hb = r3b_quotient_poly(&t0_cols, &e_ref, &g_z, &encode_z, &v_z, N)
        .ok_or(EncProofError::TraceGeneration("R3b numerator not divisible"))?;

    // Folds: MU byte-bound e_r folds, then g / encode / hb fed directly.
    let mut e_fold_traces = Vec::with_capacity(MU);
    let mut w_terms = Vec::with_capacity(MU + 3);
    for e in &e_lifts {
        let (t, ev) = generate_horner_trace(e, zeta)?;
        e_fold_traces.push(t);
        w_terms.push(ev);
    }
    let (g_trace, g_ev) = generate_horner_trace(&g_z, zeta)?;
    let (enc_trace, enc_ev) = generate_encode_mu_trace(mu, zeta)?;
    let (hb_trace, hb_ev) = generate_horner_trace(&hb, zeta)?;
    w_terms.push(g_ev);
    w_terms.push(enc_ev);
    w_terms.push(hb_ev);
    let l = MU + 3;

    let rc = RelationCheckAir { num_terms: l };
    let (rm, rel_pubs) = generate_relation_trace(&a, &w_terms, c)?;
    let relation = pad_relation(&rm);

    // AIRs.
    let mut airs = Vec::from([
        EncProofAir::Sponge(ShakeSpongeAir { height }),
        EncProofAir::SqueezeByte(SqueezeByteAir),
        EncProofAir::Ternary(TernarySamplerAir { num_coeffs: num_e }),
    ]);
    for _ in 0..MU {
        airs.push(EncProofAir::HornerFold(HornerFoldAir));
    }
    airs.push(EncProofAir::HornerFold(HornerFoldAir)); // g
    airs.push(EncProofAir::EncodeMuFold(EncodeMuFoldAir)); // encode
    airs.push(EncProofAir::HornerFold(HornerFoldAir)); // hb
    airs.push(EncProofAir::RelationCheck(rc.clone()));

    // Lookups (identical construction on the verifier side — no witness).
    let lookups = e_provenance_lookups(&rc);

    // Traces.
    let mut traces: Vec<RowMajorMatrix<ConfigVal>> = Vec::from([sponge, squeeze, e_sampler]);
    traces.extend(e_fold_traces);
    traces.push(g_trace);
    traces.push(enc_trace);
    traces.push(hb_trace);
    traces.push(relation);

    // Public values.
    let public_values = e_provenance_public_values(&w.pk_digest, num_e, zeta, &a, c, &rel_pubs);

    let shape = EncProofShape {
        sponge_height: height,
        num_e_coeffs: num_e,
        sponge_full_limbs: full_limbs,
        consumed_bytes: consumed,
    };
    Ok((
        ct,
        shape,
        EncProvenanceProver {
            airs,
            traces,
            public_values,
            lookups,
        },
    ))
}

/// **Verifier** assembly for `(t0, ct, shape)`: recomputes `ζ = derive_zetas(ct)[0]`, rebuilds every
/// AIR from the public [`EncProofShape`], the sponge public values from `ct.pk_digest` (the
/// load-bearing pk binding — NEVER prover-supplied), and the relation public coefficients from
/// `(t0, ct, ζ)`. Rebuilds the lookups (deterministic, witness-free) in the SAME order as
/// [`assemble_e_provenance_prover`]. Feed to `verify_batch`.
pub fn assemble_e_provenance_verifier(
    t0: &[Rq],
    ct: &Ciphertext,
    shape: EncProofShape,
) -> EncProvenanceVerifier {
    let zeta = derive_zetas(&ct.to_bytes(), 1)[0];
    let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
    let v_z = rq_coeffs_zq(&ct.v);
    let (a, c) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
    let l = MU + 3;
    let rc = RelationCheckAir { num_terms: l };

    let mut airs = Vec::from([
        EncProofAir::Sponge(ShakeSpongeAir {
            height: shape.sponge_height,
        }),
        EncProofAir::SqueezeByte(SqueezeByteAir),
        EncProofAir::Ternary(TernarySamplerAir {
            num_coeffs: shape.num_e_coeffs,
        }),
    ]);
    for _ in 0..MU {
        airs.push(EncProofAir::HornerFold(HornerFoldAir));
    }
    airs.push(EncProofAir::HornerFold(HornerFoldAir)); // g
    airs.push(EncProofAir::EncodeMuFold(EncodeMuFoldAir)); // encode
    airs.push(EncProofAir::HornerFold(HornerFoldAir)); // hb
    airs.push(EncProofAir::RelationCheck(rc.clone()));

    let lookups = e_provenance_lookups(&rc);
    // pk_digest is rebuilt from `t0` — the verifier does NOT trust a prover-supplied value
    // (adversarial-review 2026-07-11: the single most important obligation). `ct` is bound because ζ,
    // v_z and the relation coefficients are all recomputed from it above.
    let pk_digest = lib_q_threshold_kem_lattice::kem::pk_digest_of(t0);
    let rel_pubs = relation_public_values(&a, c);
    let public_values =
        e_provenance_public_values(&pk_digest, shape.num_e_coeffs, zeta, &a, c, &rel_pubs);

    EncProvenanceVerifier {
        airs,
        public_values,
        lookups,
    }
}

/// The per-instance lookup lists (identical for prover and verifier — no witness data). Order matches
/// the AIR order: sponge (limb Sends), squeeze (limb Receive + byte Send), e-sampler (byte Receive +
/// coeff Send), `MU` e_r folds (coeff Receive at base `r·N·4` + `E`-Send to R3b term `r`), g/encode/hb
/// folds (`E`-Send to terms `MU`/`MU+1`/`MU+2`), R3b relation (`w`-Receive of all terms).
fn e_provenance_lookups(rc: &RelationCheckAir) -> Vec<Vec<Lookup<ConfigVal>>> {
    let mut lookups: Vec<Vec<Lookup<ConfigVal>>> = Vec::new();
    lookups.push(sponge_limb_send_lookups());
    lookups.push(Vec::from([
        squeeze_byte_send_lookup(),
        squeeze_byte_limb_receive_lookup(),
    ]));
    let mut e_samp = Vec::from([ternary_receive_lookup()]); // byte Receive (aux col 0)
    e_samp.extend(ternary_coeff_send_lookups_at(0, 1)); // coeff Send (aux cols 1..5)
    lookups.push(e_samp);
    for r in 0..MU {
        // e_r fold: join-2 receive at base r·N·4 (cols 0..4) + join-3 send to R3b term r (cols 4..8).
        let mut fl = horner_coeff_receive_lookups_at(COEFF_E_BUS, (r as u64) * (N as u64) * 4);
        fl.extend(horner_e_send_lookups_at(FOLD_E_BUS, 0, r, 4));
        lookups.push(fl);
    }
    lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, 0, MU, 0)); // g → term MU
    lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, 0, MU + 1, 0)); // encode → term MU+1
    lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, 0, MU + 2, 0)); // hb → term MU+2
    lookups.push(rc.relation_w_receive_lookups_at(FOLD_E_BUS, 0));
    lookups
}

/// The per-instance public values, in AIR order. `pk_digest` pins the sponge (ciphertext binding);
/// `zeta` pins every fold; `(a, c)`/`rel_pubs` pin the relation.
fn e_provenance_public_values(
    pk_digest: &[u8; 32],
    num_e: usize,
    zeta: u64,
    _a: &[u64],
    _c: u64,
    rel_pubs: &[ConfigVal],
) -> Vec<Vec<ConfigVal>> {
    let zeta_pubs = horner_public_values(zeta);
    let mut pubs: Vec<Vec<ConfigVal>> = Vec::from([
        sponge_public_values(pk_digest),
        Vec::new(),
        ternary_public_values(num_e),
    ]);
    for _ in 0..MU {
        pubs.push(zeta_pubs.clone());
    }
    pubs.push(zeta_pubs.clone()); // g
    pubs.push(encode_mu_public_values(zeta)); // encode
    pubs.push(zeta_pubs); // hb
    pubs.push(rel_pubs.to_vec()); // relation
    pubs
}

/// Reference SHAKE-256 XOF of `input` (`n` bytes) — the ground-truth squeeze stream the sampler and
/// squeeze-byte table consume.
fn shake256_xof(input: &[u8], n: usize) -> Vec<u8> {
    use lib_q_sha3::{
        ExtendableOutput,
        Update,
        XofReader,
    };
    let mut h = lib_q_sha3::Shake256::default();
    h.update(input);
    let mut rd = h.finalize_xof();
    #[cfg(not(feature = "std"))]
    let mut out = alloc::vec![0u8; n];
    #[cfg(feature = "std")]
    let mut out = vec![0u8; n];
    rd.read(&mut out);
    out
}

/// Number of squeeze blocks (final-step rows) in a sponge trace of `height` rows.
fn sponge_squeeze_blocks(height: usize) -> usize {
    (0..height).filter(|r| r % NUM_ROUNDS == NUM_ROUNDS - 1).count()
}

#[cfg(test)]
mod tests {
    use lib_q_plonky_batch_stark::{
        CommonData,
        ProverData,
        ProverOnlyData,
        StarkInstance,
        prove_batch,
        verify_batch,
    };
    use lib_q_plonky_uni_stark::StarkConfig;
    use lib_q_stark_challenger::{
        ComplexFieldChallenger,
        Shake256Challenger32,
    };
    use lib_q_stark_fri::{
        FriParameters,
        create_test_fri_params,
    };
    use lib_q_stark_mersenne31::Mersenne31;
    use lib_q_stark_shake256::Shake256Hash;
    use lib_q_zkp::stark::{
        ConfigDft,
        DefaultChallengeMmcs,
        DefaultPcs,
        DefaultValMmcs,
    };

    use super::*;

    type TestChallenger = ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>;
    type Cfg = StarkConfig<DefaultPcs, ConfigVal, TestChallenger>;

    /// Assemble a `StarkConfig` from a set of FRI parameters (shared plumbing for the test and
    /// production configs).
    fn config_from_fri(
        fri_params: FriParameters<DefaultChallengeMmcs>,
        val_mmcs: DefaultValMmcs,
    ) -> Cfg {
        let dft = ConfigDft::default();
        let pcs = DefaultPcs::new(dft, val_mmcs, fri_params);
        let base = Shake256Challenger32::<Mersenne31>::from_hasher(Vec::new(), Shake256Hash);
        StarkConfig::new(pcs, ComplexFieldChallenger::new(base))
    }

    fn mmcs_pair() -> (DefaultValMmcs, DefaultChallengeMmcs) {
        let shake = Shake256Hash {};
        let hash = lib_q_stark_symmetric::SerializingHasher::<Shake256Hash>::new(shake);
        let compress =
            lib_q_stark_symmetric::CompressionFunctionFromHasher::<Shake256Hash, 2, 32>::new(shake);
        let val_mmcs = DefaultValMmcs::new(hash, compress);
        let challenge_mmcs = DefaultChallengeMmcs::new(val_mmcs.clone());
        (val_mmcs, challenge_mmcs)
    }

    /// **Test** FRI params (2 queries, 1 PoW bit) — fast, NOT production-sound.
    fn test_batch_config() -> Cfg {
        let (val_mmcs, challenge_mmcs) = mmcs_pair();
        config_from_fri(create_test_fri_params(challenge_mmcs, 2), val_mmcs)
    }

    /// **Production-grade** FRI params. `log_blowup = 2` (rate 1/4) with `num_queries = 64` gives a
    /// conjectured FRI soundness of ≈ `num_queries · log_blowup = 128` bits (list-decoding-regime
    /// caveats apply — this is the standard STARK conjecture, not a proven bound), plus a 16-bit
    /// grinding (`proof_of_work_bits`) factor against query-grinding. These are the parameters the
    /// composed encryption proof must remain sound at; the round-trip and spike-rejection tests below
    /// run against this config (behind `#[ignore]` only for wall-clock, not soundness, reasons).
    fn production_batch_config() -> Cfg {
        let (val_mmcs, challenge_mmcs) = mmcs_pair();
        let fri_params = FriParameters {
            log_blowup: 2,
            log_final_poly_len: 0,
            num_queries: 64,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        };
        config_from_fri(fri_params, val_mmcs)
    }

    /// Hand-assemble the batch prover's committed preprocessed data (the batch API provides no
    /// builder). For each AIR that returns a `preprocessed_trace()`, commit its matrix through the
    /// config's PCS; AIRs without one get a `None` slot. (Lifted verbatim from `compose::tests`.)
    fn build_preprocessed<SC, A>(
        config: &SC,
        airs: &[A],
    ) -> (
        Option<lib_q_plonky_batch_stark::common::GlobalPreprocessed<SC>>,
        ProverOnlyData<SC>,
    )
    where
        SC: lib_q_plonky_uni_stark::StarkGenericConfig,
        A: BaseAir<lib_q_plonky_uni_stark::Val<SC>>,
    {
        use lib_q_plonky_batch_stark::common::{
            GlobalPreprocessed,
            PreprocessedInstanceMeta,
        };
        use lib_q_stark_commit::Pcs;

        let pcs = config.pcs();
        let is_zk = config.is_zk();
        let mut inputs = Vec::new();
        let mut instances = Vec::with_capacity(airs.len());
        let mut matrix_to_instance = Vec::new();
        for (i, air) in airs.iter().enumerate() {
            match air.preprocessed_trace() {
                Some(mat) => {
                    let width = mat.width;
                    let height = mat.values.len() / width;
                    let degree_bits = height.trailing_zeros() as usize;
                    let ext_db = degree_bits + is_zk;
                    let domain = pcs.natural_domain_for_degree(1usize << ext_db);
                    let matrix_index = inputs.len();
                    inputs.push((domain, mat));
                    instances.push(Some(PreprocessedInstanceMeta {
                        matrix_index,
                        width,
                        degree_bits: ext_db,
                    }));
                    matrix_to_instance.push(i);
                }
                None => instances.push(None),
            }
        }
        if inputs.is_empty() {
            return (None, ProverOnlyData::empty());
        }
        let (commitment, prover_data) = pcs.commit(inputs);
        (
            Some(GlobalPreprocessed {
                commitment,
                instances,
                matrix_to_instance,
            }),
            ProverOnlyData {
                preprocessed_prover_data: Some(prover_data),
            },
        )
    }

    use lib_q_stark_air::BaseAir;

    /// A small, structured `t0` public key for deterministic tests.
    fn test_t0() -> Vec<Rq> {
        (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = (i as i64 * 31 + r as i64 * 7) % lib_q_dkg::lattice::ring::Q;
                }
                Rq::from_coeffs(c)
            })
            .collect()
    }

    /// Build the prover `StarkInstance`s from an assembled prover layer + preprocessed data.
    fn prover_instances<'a>(
        prover: &'a EncProvenanceProver,
    ) -> Vec<StarkInstance<'a, Cfg, EncProofAir>> {
        prover
            .airs
            .iter()
            .zip(prover.traces.iter())
            .zip(prover.public_values.iter())
            .zip(prover.lookups.iter())
            .map(|(((air, trace), pv), lk)| StarkInstance {
                air,
                trace,
                public_values: pv.clone(),
                lookups: lk.clone(),
            })
            .collect()
    }

    /// Prove + verify the composed byte-provenance proof for `(t0, μ)` under `config`, rebuilding the
    /// verifier side from public inputs only. Returns whether `verify_batch` accepted. Panics on a
    /// prove error (a well-formed witness must always prove).
    fn prove_and_verify(config: &Cfg, t0: &[Rq], mu: &[u8; 32]) -> bool {
        let (ct, shape, prover) =
            assemble_e_provenance_prover(t0, mu).expect("prover assembly for a well-formed witness");
        let (global, prover_only) = build_preprocessed(config, &prover.airs);
        let common = CommonData::new(global, prover.lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only,
        };
        let instances = prover_instances(&prover);
        let proof = prove_batch(config, &instances, &prover_data).expect("prove_batch");

        // Verifier: rebuild entirely from public inputs (t0, ct, shape) — no witness, no prover data.
        let verifier = assemble_e_provenance_verifier(t0, &ct, shape);
        let (vglobal, _) = build_preprocessed(config, &verifier.airs);
        let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
        verify_batch(
            config,
            &verifier.airs,
            &proof,
            &verifier.public_values,
            &vcommon,
        )
        .is_ok()
    }

    /// **Round-trip through the real library API (task #26).** A genuine ciphertext's `e`
    /// byte-provenance ⇒ R3b proof, assembled via [`assemble_e_provenance_prover`], proven, and verified
    /// via the verifier side rebuilt from public inputs by [`assemble_e_provenance_verifier`] — the
    /// composition lifted out of `#[cfg(test)]` into callable API, at test FRI params.
    #[test]
    fn e_provenance_round_trip_test_params() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        assert!(
            prove_and_verify(&test_batch_config(), &t0, &mu),
            "honest e-provenance proof must verify at test params"
        );
    }

    /// **Same proof at PRODUCTION FRI params** (128-bit-conjectured soundness, 16-bit grinding). Closes
    /// the "test params only" gap: the byte-provenance composition is sound at production parameters,
    /// not merely at the 2-query test config. `#[ignore]` for wall-clock only — run with
    /// `cargo test --release -- --ignored e_provenance_round_trip_production_params`.
    #[test]
    #[ignore = "heavy: production FRI params over the full N=1024 e-provenance batch"]
    fn e_provenance_round_trip_production_params() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        assert!(
            prove_and_verify(&production_batch_config(), &t0, &mu),
            "honest e-provenance proof must verify at production params"
        );
    }

    /// **Spike / tampered-witness rejection — the non-vacuousness proof (closes the C1 vacuous-gate
    /// finding for the `e`-probe class).** Assemble an honest proof, then tamper ONE `e_r` fold's
    /// coefficient so the folded witness no longer equals the XOF-derived `e` the sampler emitted. The
    /// byte-provenance binding must reject it: either the fold's internal Horner constraint fails at
    /// prove time (a `check_constraints` panic — caught here), or the COEFF_E_BUS join-2 unbalances and
    /// `verify_batch` rejects. Contrast with [`crate::prove::prove_relation_layer`], over which the same
    /// tamper would still verify (free `(e,f,g)`). This is what makes the gate non-vacuous: a prover
    /// cannot substitute a witness that deviates from `XOF(pk ‖ μ)`.
    #[test]
    fn spike_tampered_e_witness_rejected() {
        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        let config = test_batch_config();

        let (ct, shape, mut prover) =
            assemble_e_provenance_prover(&t0, &mu).expect("prover assembly");

        // Sanity: the honest proof verifies (guards against a false-positive rejection below).
        {
            let (global, prover_only) = build_preprocessed(&config, &prover.airs);
            let common = CommonData::new(global, prover.lookups.clone());
            let prover_data = ProverData {
                common,
                prover_only,
            };
            let instances = prover_instances(&prover);
            let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch honest");
            let verifier = assemble_e_provenance_verifier(&t0, &ct, shape);
            let (vglobal, _) = build_preprocessed(&config, &verifier.airs);
            let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
            assert!(
                verify_batch(
                    &config,
                    &verifier.airs,
                    &proof,
                    &verifier.public_values,
                    &vcommon
                )
                .is_ok(),
                "control: honest proof must verify before we tamper"
            );
        }

        // Tamper: corrupt the first e_r fold trace (instance index 3 = first HornerFold; indices
        // 0=sponge, 1=squeeze, 2=e-sampler). Bump a `w`-limb cell so the folded coefficient differs
        // from the sampler's XOF-derived Send. This breaks the fold's own Horner recurrence and/or the
        // COEFF_E_BUS multiset balance.
        let e0_fold = &mut prover.traces[3];
        e0_fold.values[0] += ConfigVal::ONE;

        // The tampered proof must NOT verify. A `check_constraints` panic inside `prove_batch` (debug)
        // counts as rejection, so catch it; in release, `prove_batch` succeeds but `verify_batch` must
        // reject (unbalanced join / failed relation).
        let tampered_ok = {
            let prev = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let (global, prover_only) = build_preprocessed(&config, &prover.airs);
                let common = CommonData::new(global, prover.lookups.clone());
                let prover_data = ProverData {
                    common,
                    prover_only,
                };
                let instances = prover_instances(&prover);
                let proof = prove_batch(&config, &instances, &prover_data).ok()?;
                let verifier = assemble_e_provenance_verifier(&t0, &ct, shape);
                let (vglobal, _) = build_preprocessed(&config, &verifier.airs);
                let vcommon = CommonData::new(vglobal, verifier.lookups.clone());
                verify_batch(
                    &config,
                    &verifier.airs,
                    &proof,
                    &verifier.public_values,
                    &vcommon,
                )
                .ok()
            }));
            std::panic::set_hook(prev);
            matches!(r, Ok(Some(())))
        };
        assert!(
            !tampered_ok,
            "a witness that deviates from XOF(pk‖μ) must NOT produce a verifying byte-provenance proof"
        );
    }

    /// **Gate wired to the sound closure (task #33 closure for the `e`-probe class).** The partial-decap
    /// gate ([`crate::gate::gated_partial_decap_masked`]) is driven by a `proof_verifies` closure that
    /// runs the COMPOSED byte-provenance `verify_batch` (not the vacuous relation-only path). A proof
    /// built for `ct` verifies for `ct` (gate forwards); a proof verified against a DIFFERENT ciphertext
    /// fails ⇒ the gate refuses with `ProofRejected` before the share is read. This demonstrates the
    /// gate is non-vacuous when handed the sound closure this module provides.
    #[test]
    fn gate_uses_composed_byte_provenance_closure() {
        use lib_q_random::new_deterministic_rng;
        use lib_q_threshold_kem_lattice::threshold::ZeroShareSeeds;
        use lib_q_threshold_kem_lattice::SecretShare;
        use zeroize::Zeroizing;

        use crate::gate::gated_partial_decap_masked;

        let t0 = test_t0();
        let mu = [0x6Bu8; 32];
        let config = test_batch_config();

        let (ct, shape, prover) =
            assemble_e_provenance_prover(&t0, &mu).expect("prover assembly");
        let (global, prover_only) = build_preprocessed(&config, &prover.airs);
        let common = CommonData::new(global, prover.lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only,
        };
        let instances = prover_instances(&prover);
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");

        // The sound closure: rebuild the verifier from public inputs for `ct_for_verify` and run the
        // composed verify_batch. Binds the proof to a specific ciphertext (ζ, v, pk_digest all from it).
        let verify_against = |ct_for_verify: &Ciphertext| -> bool {
            let v = assemble_e_provenance_verifier(&t0, ct_for_verify, shape);
            let (vglobal, _) = build_preprocessed(&config, &v.airs);
            let vcommon = CommonData::new(vglobal, v.lookups.clone());
            verify_batch(&config, &v.airs, &proof, &v.public_values, &vcommon).is_ok()
        };

        // A placeholder share (a full DKG share is exercised by the KEM's own tests); we only assert
        // the gate's ACCEPT/REJECT decision, which happens before the share is read.
        let share = SecretShare {
            index: 1,
            threshold: 1,
            share_bytes: Zeroizing::new(vec![0u8; 1]),
        };
        let seeds = ZeroShareSeeds::from_pairwise(Vec::new()).expect("empty seed set is canonical");

        // Accept path: proof verifies for `ct` ⇒ gate forwards past verification (then errors on the
        // placeholder share) ⇒ NOT ProofRejected.
        let mut rng = new_deterministic_rng([7u8; 32]);
        let forwarded = gated_partial_decap_masked(
            || verify_against(&ct),
            &share,
            &[1u8],
            &ct,
            &seeds,
            &mut rng,
        );
        assert!(
            !matches!(forwarded, Err(EncProofError::ProofRejected)),
            "a composed proof that verifies for this ciphertext must forward past the gate"
        );

        // Reject path: verify the SAME proof against a DIFFERENT ciphertext ⇒ fails ⇒ ProofRejected
        // before the share is touched.
        let other_ct = encapsulate_derand(&t0, &[0xD9u8; 32]);
        let mut rng2 = new_deterministic_rng([9u8; 32]);
        let refused = gated_partial_decap_masked(
            || verify_against(&other_ct),
            &share,
            &[1u8],
            &ct,
            &seeds,
            &mut rng2,
        );
        assert!(
            matches!(refused, Err(EncProofError::ProofRejected)),
            "a composed proof that does not verify for this ciphertext must be refused by the gate"
        );
    }
}
