//! Production entry-point assembly for the encryption proof (task #26): build the full **relation
//! layer** — all R3a columns (`p_k = Σ_r B0_{r,k}·e_r + f_k`) and R3b (`v = Σ_r t0_r·e_r + g +
//! encode(μ)`) — for a real ciphertext, as the instance/trace/public-value/lookup lists a single
//! `prove_batch` / `verify_batch` call consumes.
//!
//! ## Why assembly functions rather than a generic `prove_encryption`
//! `lib_q_plonky_batch_stark::prove_batch<SC, A>` is bounded by `A: for<'a> Air<ProverConstraint
//! FolderWithLookups<'a, SC>>` — a folder type the batch crate does **not** re-export, so a
//! config-generic wrapper cannot name the bound from here. Instead this module exposes the (config-
//! independent) assembly: [`prove_relation_layer`] (prover side, needs the witness) and
//! [`verify_relation_layer`] (verifier side, public inputs only). The caller then runs the two-line
//! `prove_batch(config, &instances, &prover_data)` / `verify_batch(config, &airs, &proof, &pubs,
//! &common)` with the config it chose (the hiding-FRI ZK config for zero-knowledge). See the module
//! test for the exact orchestration.
//!
//! ## What this proves (and the remaining composition)
//! Each relation is the scalar `Σ_j a_j·w_j + c ≡ 0 (mod q)` over the fold evaluations `E_r = e_r(ζ)`
//! etc., with `a`,`c` the **public** coefficients ([`crate::relation_assembly`]) and the `(X^N+1)`
//! reduction witnessed by quotient folds. Each witness fold Sends its result `E` on the fold-E bus and
//! the relation Receives it (**join 3**), so `verify_batch` accepts iff every fold-E bus balances AND
//! every relation holds — a proof of knowledge of `(e, f, g)` satisfying the lattice relations of the
//! ciphertext at the Fiat-Shamir challenges `ζ = SHAKE256(DOM_ZETA ‖ ct)`. **Composition obligation:**
//! binding those `(e, f, g)` to be the deterministic FO expansion of `μ` (so a *malformed* ciphertext
//! is rejected) is the **byte-provenance** layer (join 1 sponge⇒squeeze⇒samplers + join 2
//! samplers⇒folds). For the `e` component this is now DONE and lifted into real API —
//! [`crate::encryption_proof`] composes sponge⇒squeeze⇒ternary-sampler⇒`e_r` folds⇒R3b into one batch
//! at production FRI params (superseding this relation-only path for the `e`-probe class; `f`/`g`
//! byte-provenance binding remains). `ζ` is verifier-recomputed from the ciphertext — never
//! prover-supplied.
//!
//! Per-relation instances get **disjoint fold-E bus bases** so their joins don't alias (each relation
//! `j` uses `[base_j, base_j + 4·L)` with `base_j = j·RELATION_BASE_SPAN`); each fold Sends to exactly
//! one relation (fold instances are not shared across relations here — simpler wiring at the cost of
//! duplicated `e_r` folds; the shared-fold fan-out is a later size optimisation).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use lib_q_dkg::lattice::bdlop::{
    KAPPA,
    MU,
    key,
};
use lib_q_dkg::lattice::ring::{
    N,
    Rq,
};
use lib_q_plonky_lookup::Lookup;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_threshold_kem_lattice::kem::{
    Ciphertext,
    encapsulate_derand,
    encode_msg,
    fo_expand_witness,
};
use lib_q_zkp::stark::ConfigVal;
use zeroize::Zeroizing;

use crate::compose::EncProofAir;
use crate::error::EncProofError;
use crate::logup_join::FOLD_E_BUS;
use crate::relation_assembly::{
    derive_zetas,
    r3a_public_coeffs,
    r3a_quotient_poly,
    r3b_public_coeffs,
    r3b_quotient_poly,
    rq_coeffs_zq,
};
use crate::zq::{
    EncodeMuFoldAir,
    HornerFoldAir,
    RelationCheckAir,
    encode_mu_public_values,
    generate_encode_mu_trace,
    generate_horner_trace,
    generate_relation_trace,
    horner_e_send_lookups_at,
    horner_public_values,
};

/// Fold-E bus base spacing per relation instance: `(MU + 3)` max terms × 4 limbs, rounded up. Distinct
/// relations use `[j·SPAN, j·SPAN + 4·L)`, which are disjoint since `4·L ≤ SPAN`.
pub const RELATION_BASE_SPAN: u64 = ((MU + 3) as u64) * 4;
/// Padded height of each (height-2) relation trace — a power of two above the test FRI minimum.
const RELATION_HEIGHT: usize = 64;

/// One fold term of a relation, prover side (carries the witness coefficients).
enum FoldSpec {
    /// A generic Horner fold over these `Z_q` coefficients (low-order first).
    Horner(Vec<u64>),
    /// The `encode(μ)` fold (boolean-μ binding) for this message.
    Encode([u8; 32]),
}

/// The assembled instances of the whole relation layer (prover side): parallel vectors indexed by
/// batch instance. Build `StarkInstance`s by zipping these, then call `prove_batch`.
pub struct ProverRelationLayer {
    /// One enum-wrapped AIR per instance.
    pub airs: Vec<EncProofAir>,
    /// The witness trace for each instance (borrowed by the `StarkInstance`s).
    pub traces: Vec<RowMajorMatrix<ConfigVal>>,
    /// Public values per instance.
    pub public_values: Vec<Vec<ConfigVal>>,
    /// Global-bus lookups per instance (also the verifier-trusted `CommonData` lookups).
    pub lookups: Vec<Vec<Lookup<ConfigVal>>>,
}

/// The assembled instances of the whole relation layer (verifier side): no traces, public coefficients
/// recomputed from `(B0, t0, ct, ζ)`. Feed to `verify_batch`.
pub struct VerifierRelationLayer {
    /// One enum-wrapped AIR per instance (same order as the prover).
    pub airs: Vec<EncProofAir>,
    /// Public values per instance (fold `ζ` limbs + relation `a`,`c` limbs).
    pub public_values: Vec<Vec<ConfigVal>>,
    /// Global-bus lookups per instance (the verifier-trusted `CommonData` lookups).
    pub lookups: Vec<Vec<Lookup<ConfigVal>>>,
}

/// Pad a height-2 relation trace to [`RELATION_HEIGHT`] by repeating the `is_first = 0` replica row.
fn pad_relation(rm: &RowMajorMatrix<ConfigVal>) -> RowMajorMatrix<ConfigVal> {
    let w = rm.width;
    let mut vals = Vec::with_capacity(RELATION_HEIGHT * w);
    vals.extend_from_slice(&rm.values[0..w]); // row 0 (is_first = 1)
    for _ in 0..RELATION_HEIGHT - 1 {
        vals.extend_from_slice(&rm.values[w..2 * w]); // is_first = 0 replicas
    }
    RowMajorMatrix::new(vals, w)
}

/// Assemble one relation (prover side): a fold instance per term (each Sending its `E` at `base + 4·t`)
/// plus the relation instance (Receiving all terms at `base`). `a`/`c` are the public coefficients;
/// `folds` the per-term witness fold specs, in the same order as `a`'s witness terms.
fn assemble_relation_prover(
    a: &[u64],
    c: u64,
    folds: &[FoldSpec],
    zeta: u64,
    base: u64,
    out: &mut ProverRelationLayer,
) -> Result<(), EncProofError> {
    let l = folds.len();
    let mut w = Vec::with_capacity(l);
    for (term, spec) in folds.iter().enumerate() {
        let (trace, e, air, pv) = match spec {
            FoldSpec::Horner(coeffs) => {
                let (t, e) = generate_horner_trace(coeffs, zeta)?;
                (
                    t,
                    e,
                    EncProofAir::HornerFold(HornerFoldAir),
                    horner_public_values(zeta),
                )
            }
            FoldSpec::Encode(mu) => {
                let (t, e) = generate_encode_mu_trace(mu, zeta)?;
                (
                    t,
                    e,
                    EncProofAir::EncodeMuFold(EncodeMuFoldAir),
                    encode_mu_public_values(zeta),
                )
            }
        };
        w.push(e);
        out.airs.push(air);
        out.traces.push(trace);
        out.public_values.push(pv);
        out.lookups
            .push(horner_e_send_lookups_at(FOLD_E_BUS, base, term, 0));
    }
    let rc = RelationCheckAir { num_terms: l };
    let (rm, rel_pubs) = generate_relation_trace(a, &w, c)?;
    out.airs.push(EncProofAir::RelationCheck(rc.clone()));
    out.traces.push(pad_relation(&rm));
    out.public_values.push(rel_pubs);
    out.lookups
        .push(rc.relation_w_receive_lookups_at(FOLD_E_BUS, base));
    Ok(())
}

/// Assemble one relation (verifier side): `l_horner` Horner folds + (`has_encode` ? 1 EncodeMuFold at
/// index `encode_index`) + the relation, all keyed to `base`. `a`/`c` are recomputed by the caller.
fn assemble_relation_verifier(
    a: &[u64],
    c: u64,
    l: usize,
    encode_index: Option<usize>,
    zeta: u64,
    base: u64,
    out: &mut VerifierRelationLayer,
) {
    for term in 0..l {
        let (air, pv) = if Some(term) == encode_index {
            (
                EncProofAir::EncodeMuFold(EncodeMuFoldAir),
                encode_mu_public_values(zeta),
            )
        } else {
            (
                EncProofAir::HornerFold(HornerFoldAir),
                horner_public_values(zeta),
            )
        };
        out.airs.push(air);
        out.public_values.push(pv);
        out.lookups
            .push(horner_e_send_lookups_at(FOLD_E_BUS, base, term, 0));
    }
    let rc = RelationCheckAir { num_terms: l };
    // Relation public values = a's limbs then c's limbs (same layout generate_relation_trace emits).
    out.public_values.push(relation_public_values(a, c));
    out.lookups
        .push(rc.relation_w_receive_lookups_at(FOLD_E_BUS, base));
    out.airs.push(EncProofAir::RelationCheck(rc));
}

/// The relation-instance public values (`a_j` limbs low-to-high, then `c` limbs) — the verifier rebuild
/// of what `generate_relation_trace` returns, from the recomputed public coefficients.
fn relation_public_values(a: &[u64], c: u64) -> Vec<ConfigVal> {
    let mut pubs = Vec::with_capacity((a.len() + 1) * 4);
    for &x in a {
        for limb in 0..4 {
            pubs.push(crate::logup_join::fc((x >> (12 * limb)) & 0xFFF));
        }
    }
    for limb in 0..4 {
        pubs.push(crate::logup_join::fc((c >> (12 * limb)) & 0xFFF));
    }
    pubs
}

/// **Prover** assembly of the relation layer for `(t0, μ)`: derives the ciphertext + witness, computes
/// the Fiat-Shamir challenges `ζ = derive_zetas(ct)`, and builds every requested R3a column + R3b at
/// every `ζ`. `r3a_columns` selects which `p`-columns to prove (`0..KAPPA` for the full proof; a subset
/// keeps a test tractable). Returns the ciphertext and the assembled instances (feed to `prove_batch`).
pub fn prove_relation_layer(
    t0: &[Rq],
    mu: &[u8; 32],
    num_challenges: usize,
    r3a_columns: &[usize],
) -> Result<(Ciphertext, ProverRelationLayer), EncProofError> {
    // SECURITY: the local secret-witness copies below (`e_lifts`, `f_k`, `g_z`, `encode_z`, and the
    // local μ copy) are wrapped in `Zeroizing` so they are wiped on drop. NOTE: the returned
    // `ProverRelationLayer.traces` still hold witness-derived field elements (they are returned to the
    // caller by design); full trace zeroization is a larger, separate change tracked as a follow-up.
    let ct = encapsulate_derand(t0, mu);
    let w = fo_expand_witness(t0, mu);
    let b0 = key().b0();
    let zetas = derive_zetas(&ct.to_bytes(), num_challenges);

    let e_lifts: Zeroizing<Vec<Vec<u64>>> =
        Zeroizing::new(w.e.iter().map(rq_coeffs_zq).collect());
    let e_ref: Vec<&[u64]> = e_lifts.iter().map(|v| v.as_slice()).collect();
    let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();

    let mut out = ProverRelationLayer {
        airs: Vec::new(),
        traces: Vec::new(),
        public_values: Vec::new(),
        lookups: Vec::new(),
    };
    let mut ordinal: u64 = 0;

    for &zeta in &zetas {
        // R3a for each requested column.
        for &k in r3a_columns {
            let b0_cols_owned: Vec<Vec<u64>> =
                (0..MU).map(|r| rq_coeffs_zq(&b0[r * KAPPA + k])).collect();
            let b0_cols: Vec<&[u64]> = b0_cols_owned.iter().map(|v| v.as_slice()).collect();
            let p_k = rq_coeffs_zq(&ct.p[k]);
            let f_k: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&w.f[k]));
            let (a, c) = r3a_public_coeffs(&b0_cols, &p_k, zeta, N);
            let hq = r3a_quotient_poly(&b0_cols, &e_ref, &f_k, &p_k, N).ok_or(
                EncProofError::TraceGeneration("R3a numerator not divisible"),
            )?;
            let mut folds: Vec<FoldSpec> = e_lifts.iter().cloned().map(FoldSpec::Horner).collect();
            folds.push(FoldSpec::Horner((*f_k).clone()));
            folds.push(FoldSpec::Horner(hq));
            assemble_relation_prover(&a, c, &folds, zeta, ordinal * RELATION_BASE_SPAN, &mut out)?;
            ordinal += 1;
        }

        // R3b.
        let v_z = rq_coeffs_zq(&ct.v);
        let g_z: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&w.g));
        let encode_z: Zeroizing<Vec<u64>> = Zeroizing::new(rq_coeffs_zq(&encode_msg(mu)));
        let (a, c) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
        let hb = r3b_quotient_poly(&t0_cols, &e_ref, &g_z, &encode_z, &v_z, N).ok_or(
            EncProofError::TraceGeneration("R3b numerator not divisible"),
        )?;
        let mut folds: Vec<FoldSpec> = e_lifts.iter().cloned().map(FoldSpec::Horner).collect();
        folds.push(FoldSpec::Horner((*g_z).clone()));
        // Local μ copy kept in `Zeroizing` so it is wiped on drop; `FoldSpec::Encode` still copies the
        // raw bytes into the trace generator (returned-trace zeroization is the tracked follow-up).
        let mu_local = Zeroizing::new(*mu);
        folds.push(FoldSpec::Encode(*mu_local));
        folds.push(FoldSpec::Horner(hb));
        assemble_relation_prover(&a, c, &folds, zeta, ordinal * RELATION_BASE_SPAN, &mut out)?;
        ordinal += 1;
    }
    Ok((ct, out))
}

/// **Verifier** assembly for `(t0, ct)`: recomputes `ζ = derive_zetas(ct)` (never trusting the prover),
/// recomputes every relation's public coefficients from `(B0, t0, ct, ζ)`, and rebuilds the AIRs /
/// public values / lookups in the SAME order as [`prove_relation_layer`]. Feed to `verify_batch`; if it
/// accepts, the ciphertext's lattice relations hold at the challenges bound to the ciphertext.
pub fn verify_relation_layer(
    t0: &[Rq],
    ct: &Ciphertext,
    num_challenges: usize,
    r3a_columns: &[usize],
) -> VerifierRelationLayer {
    let b0 = key().b0();
    let zetas = derive_zetas(&ct.to_bytes(), num_challenges);
    let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
    let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();

    let mut out = VerifierRelationLayer {
        airs: Vec::new(),
        public_values: Vec::new(),
        lookups: Vec::new(),
    };
    let mut ordinal: u64 = 0;

    for &zeta in &zetas {
        for &k in r3a_columns {
            let b0_cols_owned: Vec<Vec<u64>> =
                (0..MU).map(|r| rq_coeffs_zq(&b0[r * KAPPA + k])).collect();
            let b0_cols: Vec<&[u64]> = b0_cols_owned.iter().map(|v| v.as_slice()).collect();
            let p_k = rq_coeffs_zq(&ct.p[k]);
            let (a, c) = r3a_public_coeffs(&b0_cols, &p_k, zeta, N);
            // R3a terms: MU e-folds + F_k + HK_k = MU + 2, all Horner.
            assemble_relation_verifier(
                &a,
                c,
                MU + 2,
                None,
                zeta,
                ordinal * RELATION_BASE_SPAN,
                &mut out,
            );
            ordinal += 1;
        }
        let v_z = rq_coeffs_zq(&ct.v);
        let (a, c) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
        // R3b terms: MU e-folds + G + E_encode(idx MU+1) + HK_b = MU + 3.
        assemble_relation_verifier(
            &a,
            c,
            MU + 3,
            Some(MU + 1),
            zeta,
            ordinal * RELATION_BASE_SPAN,
            &mut out,
        );
        ordinal += 1;
    }
    out
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
    use lib_q_stark_fri::create_test_fri_params;
    use lib_q_stark_mersenne31::Mersenne31;
    use lib_q_stark_shake256::Shake256Hash;
    use lib_q_zkp::stark::{
        ConfigDft,
        DefaultChallengeMmcs,
        DefaultPcs,
        DefaultValMmcs,
    };

    use super::*;

    type TestConfig = StarkConfig<
        DefaultPcs,
        ConfigVal,
        ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>,
    >;

    /// A batch-stack STARK config at test FRI params (mirrors `compose`'s helper).
    fn test_batch_config() -> TestConfig {
        let shake = Shake256Hash {};
        let hash = lib_q_stark_symmetric::SerializingHasher::<Shake256Hash>::new(shake);
        let compress =
            lib_q_stark_symmetric::CompressionFunctionFromHasher::<Shake256Hash, 2, 32>::new(shake);
        let val_mmcs = DefaultValMmcs::new(hash, compress);
        let challenge_mmcs = DefaultChallengeMmcs::new(val_mmcs.clone());
        let dft = ConfigDft::default();
        let fri_params = create_test_fri_params(challenge_mmcs, 2);
        let pcs = DefaultPcs::new(dft, val_mmcs, fri_params);
        let base = Shake256Challenger32::<Mersenne31>::from_hasher(Vec::new(), Shake256Hash);
        let challenger = ComplexFieldChallenger::new(base);
        StarkConfig::new(pcs, challenger)
    }

    /// **End-to-end relation-layer prove + verify on a real ciphertext (task #26).** Assemble the
    /// prover side for a genuine `encapsulate_derand` ciphertext (R3a column 0 + R3b at one FS ζ),
    /// `prove_batch`, then reassemble the VERIFIER side from public data only (recomputing ζ + the
    /// public coefficients) and `verify_batch`. Accepts iff the lattice relations hold at the
    /// ciphertext-bound challenge — the relation half of the proof, driven through the real entry
    /// points. (One column keeps the test fast; `prove_relation_layer(.., 0..KAPPA)` proves them all.)
    #[test]
    fn prove_verify_relation_layer_real_ciphertext() {
        let t0: Vec<Rq> = (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = (i as i64 * 23 + r as i64 * 9) % lib_q_dkg::lattice::ring::Q;
                }
                Rq::from_coeffs(c)
            })
            .collect();
        let mu = [0xA7u8; 32];
        let cols = [0usize];

        let (ct, prover) = prove_relation_layer(&t0, &mu, 1, &cols).expect("prover assembly");

        let config = test_batch_config();
        let common = CommonData::new(None, prover.lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };
        let instances: Vec<StarkInstance<'_, _, EncProofAir>> = prover
            .airs
            .iter()
            .zip(prover.traces.iter())
            .zip(prover.public_values.iter())
            .zip(prover.lookups.iter())
            .map(|(((air, trace), pv), lookups)| StarkInstance {
                air,
                trace,
                public_values: pv.clone(),
                lookups: lookups.clone(),
            })
            .collect();
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");

        // Verifier: rebuild from public data only (no witness), recompute ζ + coefficients.
        let verifier = verify_relation_layer(&t0, &ct, 1, &cols);
        let vcommon = CommonData::new(None, verifier.lookups.clone());
        verify_batch(
            &config,
            &verifier.airs,
            &proof,
            &verifier.public_values,
            &vcommon,
        )
        .expect("the ciphertext's lattice relations must verify from public inputs");
    }

    /// **Gate MECHANISM/wiring exercise (#33) — NOT a sound malformed-ciphertext closure.** A full
    /// trusted-dealer keygen, a real `encapsulate_derand` ciphertext, a relation-layer proof
    /// (`prove_relation_layer` + `prove_batch`), then — for a threshold subset —
    /// [`crate::gate::gated_partial_decap_masked`] with a closure that verifies the relation-layer proof
    /// (`verify_relation_layer` + `verify_batch`) before each masked partial decap. It shows the gated
    /// partials `combine` to the same secret as the reference decap, and that a proof verified against a
    /// *different* ciphertext makes the gate refuse (`ProofRejected`).
    ///
    /// **This does NOT prove the malformed-ciphertext closure.** The relation layer proves only the R3
    /// linear relations over free, prover-chosen `(e, f, g)`; the sponge/sampler byte-provenance binding
    /// (`(e, f, g) = XOF(pk ‖ μ)`, `e` ternary, `f, g` bounded) is NOT composed into this proof. A
    /// malformed-but-structurally-valid ciphertext (e.g. the `f = δ·unitₖ` spike) would ALSO pass this
    /// closure and be admitted by the gate. This test therefore exercises the gate's wiring/ordering
    /// only, not its soundness.
    #[test]
    fn gated_decap_flow_wiring_only_not_a_sound_closure() {
        use lib_q_random::new_deterministic_rng;
        use lib_q_threshold_kem_lattice::kem::encapsulate_derand;
        use lib_q_threshold_kem_lattice::threshold::ZeroShareSeeds;
        use lib_q_threshold_kem_lattice::{
            combine,
            decapsulate_reference,
            keygen_shares,
            setup,
        };

        use crate::gate::gated_partial_decap_masked;

        const THRESHOLD: u8 = 2;
        const PARTIES: u8 = 3;

        let profile = setup();
        let mut rng = new_deterministic_rng([0x42u8; 32]);
        let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
        let t0 = keygen.public_key.t0().expect("t0");
        let mu = [0xC7u8; 32];
        let ct = encapsulate_derand(&t0, &mu);

        let cols = [0usize];
        let (_ct, prover) = prove_relation_layer(&t0, &mu, 1, &cols).expect("prover assembly");
        let config = test_batch_config();
        let common = CommonData::new(None, prover.lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };
        let instances: Vec<StarkInstance<'_, _, EncProofAir>> = prover
            .airs
            .iter()
            .zip(prover.traces.iter())
            .zip(prover.public_values.iter())
            .zip(prover.lookups.iter())
            .map(|(((air, trace), pv), lookups)| StarkInstance {
                air,
                trace,
                public_values: pv.clone(),
                lookups: lookups.clone(),
            })
            .collect();
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");

        // The gate's verification: rebuild the verifier side from public inputs and verify_batch.
        // `ct_for_verify` lets the negative case verify against a *different* ciphertext (mismatch).
        let verify_against = |ct_for_verify: &Ciphertext| -> bool {
            let v = verify_relation_layer(&t0, ct_for_verify, 1, &cols);
            let vcommon = CommonData::new(None, v.lookups.clone());
            verify_batch(&config, &v.airs, &proof, &v.public_values, &vcommon).is_ok()
        };

        let seeds = ZeroShareSeeds::setup(PARTIES, &mut rng);
        let chosen = &keygen.secret_shares[..usize::from(THRESHOLD)];
        let subset: Vec<u8> = chosen.iter().map(|s| s.index).collect();

        // Gated masked partials (each verifies the proof first), then combine to the shared secret.
        let partials: Vec<_> = chosen
            .iter()
            .map(|s| {
                gated_partial_decap_masked(
                    || verify_against(&ct),
                    s,
                    &subset,
                    &ct,
                    &seeds,
                    &mut rng,
                )
                .expect("valid proof ⇒ gated partial decap")
            })
            .collect();
        let ss_gated = combine(&keygen.public_key, &partials, &ct).expect("combine");
        let ss_ref =
            decapsulate_reference(&keygen.public_key, chosen, &ct).expect("reference decap");
        assert_eq!(
            ss_gated, ss_ref,
            "the GATED masked decapsulation must recover the same secret as the reference decap"
        );

        // Negative: the proof is for `ct`, so verifying it against a DIFFERENT ciphertext fails ⇒ the
        // gate must refuse before touching the share (no partial produced).
        let other_ct = encapsulate_derand(&t0, &[0xD9u8; 32]);
        let refused = gated_partial_decap_masked(
            || verify_against(&other_ct),
            &chosen[0],
            &subset,
            &ct,
            &seeds,
            &mut rng,
        );
        assert!(
            matches!(refused, Err(EncProofError::ProofRejected)),
            "a proof that does not verify for this ciphertext must be refused by the gate"
        );
    }
}
