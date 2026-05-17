use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;

use lib_q_plonky_lookup::AirWithLookups;
use lib_q_plonky_lookup::logup::LogUpGadget;
use lib_q_plonky_lookup::lookup_traits::{
    Lookup,
    LookupGadget,
};
use lib_q_plonky_uni_stark::{
    PcsError,
    SymbolicAirBuilder,
    Val,
    VerificationError,
    VerifierConstraintFolder,
    recompose_quotient_from_chunks,
};
use lib_q_stark_air::{
    Air,
    RowWindow,
};
use lib_q_stark_challenger::{
    CanObserve,
    FieldChallenger,
};
use lib_q_stark_commit::{
    Pcs,
    PolynomialSpace,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrixView;
use lib_q_stark_matrix::stack::VerticalPair;
use tracing::{
    info_span,
    instrument,
};

use crate::common::{
    CommonData,
    get_perm_challenges,
};
use crate::config::{
    Challenge,
    Domain,
    StarkGenericConfig as SGC,
    observe_instance_binding,
};
use crate::folder::VerifierConstraintFolderWithLookups;
use crate::proof::BatchProof;
use crate::symbolic::get_log_num_quotient_chunks;

#[instrument(skip_all)]
pub fn verify_batch<SC, A>(
    config: &SC,
    airs: &[A],
    proof: &BatchProof<SC>,
    public_values: &[Vec<Val<SC>>],
    common: &CommonData<SC>,
) -> Result<(), VerificationError<PcsError<SC>>>
where
    SC: SGC,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<VerifierConstraintFolderWithLookups<'a, SC>>,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
{
    let lookup_gadget = LogUpGadget::new();

    let BatchProof {
        commitments,
        opened_values,
        opening_proof,
        global_lookup_data,
        degree_bits,
    } = proof;

    let all_lookups = &common.lookups;

    let pcs = config.pcs();
    let mut challenger = config.initialise_challenger();

    let n_instances = airs.len();
    if n_instances != opened_values.instances.len() ||
        n_instances != public_values.len() ||
        n_instances != degree_bits.len() ||
        n_instances != global_lookup_data.len()
    {
        return Err(VerificationError::InvalidProofShape);
    }

    if opened_values
        .instances
        .iter()
        .any(|ov| ov.base_opened_values.random.is_some() != SC::Pcs::ZK) ||
        commitments.random.is_some() != SC::Pcs::ZK
    {
        return Err(VerificationError::RandomizationError);
    }

    challenger.observe_base_as_algebra_element::<Challenge<SC>>(Val::<SC>::from_usize(n_instances));

    let mut preprocessed_widths = Vec::with_capacity(n_instances);
    let mut log_num_quotient_chunks_vec = Vec::with_capacity(n_instances);
    let mut num_quotient_chunks = Vec::with_capacity(n_instances);

    for (i, air) in airs.iter().enumerate() {
        let pre_w = common
            .preprocessed
            .as_ref()
            .and_then(|g| g.instances[i].as_ref().map(|m| m.width))
            .unwrap_or(0);
        preprocessed_widths.push(pre_w);

        let layout = lib_q_plonky_uni_stark::AirLayout {
            preprocessed_width: pre_w,
            main_width: air.width(),
            num_public_values: air.num_public_values(),
        };
        let log_num_chunks =
            info_span!("infer log of constraint degree", air_idx = i).in_scope(|| {
                get_log_num_quotient_chunks::<Val<SC>, A, LogUpGadget>(
                    air,
                    layout,
                    &all_lookups[i],
                    config.is_zk(),
                    &lookup_gadget,
                )
            });
        log_num_quotient_chunks_vec.push(log_num_chunks);

        let n_chunks = 1 << (log_num_chunks + config.is_zk());
        num_quotient_chunks.push(n_chunks);
    }

    for (i, air) in airs.iter().enumerate() {
        let air_width = air.width();
        let inst_opened_vals = &opened_values.instances[i];
        let inst_base = &inst_opened_vals.base_opened_values;

        if inst_base.trace_local.len() != air_width {
            return Err(VerificationError::InvalidProofShape);
        }
        if !airs[i].main_next_row_columns().is_empty() {
            if inst_base
                .trace_next
                .as_ref()
                .is_none_or(|v| v.len() != air_width)
            {
                return Err(VerificationError::InvalidProofShape);
            }
        } else if inst_base.trace_next.is_some() {
            return Err(VerificationError::InvalidProofShape);
        }

        let n_chunks = num_quotient_chunks[i];
        if inst_base.quotient_chunks.len() != n_chunks {
            return Err(VerificationError::InvalidProofShape);
        }

        for chunk in &inst_base.quotient_chunks {
            if chunk.len() != Challenge::<SC>::DIMENSION {
                return Err(VerificationError::InvalidProofShape);
            }
        }

        if inst_base
            .random
            .as_ref()
            .is_some_and(|r| r.len() != SC::Challenge::DIMENSION)
        {
            return Err(VerificationError::RandomizationError);
        }

        let pre_w = preprocessed_widths[i];
        let pre_local_len = inst_base.preprocessed_local.as_ref().map_or(0, |v| v.len());
        let pre_next_len = inst_base.preprocessed_next.as_ref().map_or(0, |v| v.len());
        if pre_w == 0 {
            if pre_local_len != 0 || pre_next_len != 0 {
                return Err(VerificationError::InvalidProofShape);
            }
        } else if !airs[i].preprocessed_next_row_columns().is_empty() {
            if pre_local_len != pre_w || pre_next_len != pre_w {
                return Err(VerificationError::InvalidProofShape);
            }
        } else if pre_local_len != pre_w || pre_next_len != 0 {
            return Err(VerificationError::InvalidProofShape);
        }

        let ext_db = degree_bits[i];
        let base_db = ext_db - config.is_zk();
        let width = air.width();
        observe_instance_binding::<SC>(&mut challenger, ext_db, base_db, width, n_chunks);
    }

    challenger.observe(commitments.main.clone());
    for pv in public_values {
        challenger.observe_slice(pv);
    }

    for &pre_w in preprocessed_widths.iter() {
        challenger.observe_base_as_algebra_element::<Challenge<SC>>(Val::<SC>::from_usize(pre_w));
    }
    if let Some(global) = &common.preprocessed {
        challenger.observe(global.commitment.clone());
    }

    let is_lookup = commitments.permutation.is_some();
    if is_lookup != all_lookups.iter().any(|c| !c.is_empty()) {
        return Err(VerificationError::InvalidProofShape);
    }

    let challenges_per_instance =
        get_perm_challenges::<SC, LogUpGadget>(&mut challenger, all_lookups, &lookup_gadget);

    if is_lookup {
        if let Some(perm) = commitments.permutation.clone() {
            challenger.observe(perm);
        }
        for data in global_lookup_data.iter().flatten() {
            challenger.observe_algebra_element(data.expected_cumulated);
        }
    }

    let alpha: Challenge<SC> = challenger.sample_algebra_element();
    challenger.observe(commitments.quotient_chunks.clone());

    if let Some(r_commit) = commitments.random.clone() {
        challenger.observe(r_commit);
    }

    let zeta: Challenge<SC> = challenger.sample_algebra_element();

    let mut coms_to_verify = vec![];

    let (trace_domains, ext_trace_domains): (Vec<Domain<SC>>, Vec<Domain<SC>>) = degree_bits
        .iter()
        .map(|&ext_db| {
            let base_db = ext_db - config.is_zk();
            (
                pcs.natural_domain_for_degree(1 << base_db),
                pcs.natural_domain_for_degree(1 << ext_db),
            )
        })
        .unzip();

    if let Some(random_commit) = &commitments.random {
        let random_round: Vec<_> = ext_trace_domains
            .iter()
            .zip(opened_values.instances.iter())
            .map(|(domain, inst_ov)| {
                let random_vals = inst_ov
                    .base_opened_values
                    .random
                    .as_ref()
                    .ok_or(VerificationError::InvalidProofShape)?;
                Ok((*domain, vec![(zeta, random_vals.clone())]))
            })
            .collect::<Result<Vec<_>, _>>()?;
        coms_to_verify.push((random_commit.clone(), random_round));
    }

    let trace_round: Vec<_> = ext_trace_domains
        .iter()
        .zip(opened_values.instances.iter())
        .enumerate()
        .map(|(i, (ext_dom, inst_ov))| {
            let mut points = vec![(zeta, inst_ov.base_opened_values.trace_local.clone())];
            if !airs[i].main_next_row_columns().is_empty() {
                let zeta_next = trace_domains[i]
                    .next_point(zeta)
                    .ok_or(VerificationError::NextPointUnavailable)?;
                points.push((
                    zeta_next,
                    inst_ov
                        .base_opened_values
                        .trace_next
                        .clone()
                        .ok_or(VerificationError::InvalidProofShape)?,
                ));
            }
            Ok((*ext_dom, points))
        })
        .collect::<Result<Vec<_>, VerificationError<PcsError<SC>>>>()?;
    coms_to_verify.push((commitments.main.clone(), trace_round));

    let quotient_domains: Vec<Vec<Domain<SC>>> = (0..degree_bits.len())
        .map(|i| {
            let ext_db = degree_bits[i];
            let log_num_chunks = log_num_quotient_chunks_vec[i];
            let n_chunks = num_quotient_chunks[i];
            let ext_dom = ext_trace_domains[i];
            let qdom = ext_dom.create_disjoint_domain(1 << (ext_db + log_num_chunks));
            qdom.split_domains(n_chunks)
        })
        .collect();

    let randomized_quotient_chunks_domains = quotient_domains
        .iter()
        .map(|doms| {
            doms.iter()
                .map(|dom| pcs.natural_domain_for_degree(dom.size() << config.is_zk()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let mut qc_round = Vec::new();
    for (i, domains) in randomized_quotient_chunks_domains.iter().enumerate() {
        let inst_qcs = &opened_values.instances[i]
            .base_opened_values
            .quotient_chunks;
        if inst_qcs.len() != domains.len() {
            return Err(VerificationError::InvalidProofShape);
        }
        for (d, vals) in domains.iter().zip(inst_qcs.iter()) {
            qc_round.push((*d, vec![(zeta, vals.clone())]));
        }
    }
    coms_to_verify.push((commitments.quotient_chunks.clone(), qc_round));

    if let Some(global) = &common.preprocessed {
        let mut pre_round = Vec::new();

        for (matrix_index, &inst_idx) in global.matrix_to_instance.iter().enumerate() {
            let pre_w = preprocessed_widths[inst_idx];
            if pre_w == 0 {
                return Err(VerificationError::InvalidProofShape);
            }

            let inst = &opened_values.instances[inst_idx];
            let local = inst
                .base_opened_values
                .preprocessed_local
                .as_ref()
                .ok_or(VerificationError::InvalidProofShape)?;

            let ext_db = degree_bits[inst_idx];
            let meta = global.instances[inst_idx]
                .as_ref()
                .ok_or(VerificationError::InvalidProofShape)?;
            if meta.matrix_index != matrix_index || meta.degree_bits != ext_db {
                return Err(VerificationError::InvalidProofShape);
            }

            let meta_db = meta.degree_bits;
            let pre_domain = pcs.natural_domain_for_degree(1 << meta_db);
            if !airs[inst_idx].preprocessed_next_row_columns().is_empty() {
                let next = inst
                    .base_opened_values
                    .preprocessed_next
                    .as_ref()
                    .ok_or(VerificationError::InvalidProofShape)?;
                let zeta_next_i = trace_domains[inst_idx]
                    .next_point(zeta)
                    .ok_or(VerificationError::NextPointUnavailable)?;

                pre_round.push((
                    pre_domain,
                    vec![(zeta, local.clone()), (zeta_next_i, next.clone())],
                ));
            } else {
                pre_round.push((pre_domain, vec![(zeta, local.clone())]));
            }
        }

        coms_to_verify.push((global.commitment.clone(), pre_round));
    }

    if is_lookup {
        let permutation_commit = commitments
            .permutation
            .clone()
            .ok_or(VerificationError::InvalidProofShape)?;
        let mut permutation_round = Vec::new();
        for (i, (ext_dom, inst_ov)) in ext_trace_domains
            .iter()
            .zip(opened_values.instances.iter())
            .enumerate()
        {
            if inst_ov.permutation_local.len() != inst_ov.permutation_next.len() {
                return Err(VerificationError::InvalidProofShape);
            }
            if !inst_ov.permutation_local.is_empty() {
                let zeta_next = trace_domains[i]
                    .next_point(zeta)
                    .ok_or(VerificationError::NextPointUnavailable)?;
                permutation_round.push((
                    *ext_dom,
                    vec![
                        (zeta, inst_ov.permutation_local.clone()),
                        (zeta_next, inst_ov.permutation_next.clone()),
                    ],
                ));
            }
        }
        coms_to_verify.push((permutation_commit, permutation_round));
    }

    pcs.verify(coms_to_verify, opening_proof, &mut challenger)
        .map_err(VerificationError::InvalidOpeningArgument)?;

    for (i, air) in airs.iter().enumerate() {
        let _air_span = info_span!("verify constraints", air_idx = i).entered();

        let qc_domains = &quotient_domains[i];

        let quotient = recompose_quotient_from_chunks::<SC, PcsError<SC>>(
            qc_domains,
            &opened_values.instances[i]
                .base_opened_values
                .quotient_chunks,
            zeta,
        )?;

        let aux_width = all_lookups[i]
            .iter()
            .flat_map(|ctx| ctx.columns.iter().cloned())
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);

        let recompose = |flat: &[Challenge<SC>]| -> Result<Vec<Challenge<SC>>, VerificationError<PcsError<SC>>> {
            if aux_width == 0 {
                return Ok(vec![]);
            }
            let ext_degree = Challenge::<SC>::DIMENSION;
            if flat.len() != aux_width * ext_degree {
                return Err(VerificationError::InvalidProofShape);
            }
            flat.chunks_exact(ext_degree)
                .map(|coeffs| {
                    coeffs
                        .iter()
                        .enumerate()
                        .map(|(j, &coeff)| {
                            Challenge::<SC>::ith_basis_element(j)
                                .ok_or(VerificationError::InvalidProofShape)
                                .map(|b| coeff * b)
                        })
                        .sum::<Result<Challenge<SC>, _>>()
                })
                .collect()
        };

        let perm_local_ext = recompose(&opened_values.instances[i].permutation_local)?;
        let perm_next_ext = recompose(&opened_values.instances[i].permutation_next)?;

        let init_trace_domain = trace_domains[i];
        let trace_next_zeros;
        let trace_next_ref = match &opened_values.instances[i].base_opened_values.trace_next {
            Some(v) => v.as_slice(),
            None => {
                trace_next_zeros = vec![SC::Challenge::ZERO; air.width()];
                &trace_next_zeros
            }
        };
        let pre_next_zeros;
        let pre_next_ref = match &opened_values.instances[i]
            .base_opened_values
            .preprocessed_next
        {
            Some(v) => v.as_slice(),
            None => {
                pre_next_zeros = vec![SC::Challenge::ZERO; preprocessed_widths[i]];
                &pre_next_zeros
            }
        };
        let perm_vals: Vec<SC::Challenge> = global_lookup_data[i]
            .iter()
            .map(|ld| ld.expected_cumulated)
            .collect();
        let verifier_data = VerifierData {
            trace_local: &opened_values.instances[i].base_opened_values.trace_local,
            trace_next: trace_next_ref,
            preprocessed_local: opened_values.instances[i]
                .base_opened_values
                .preprocessed_local
                .as_ref()
                .map_or(&[], |v| v),
            preprocessed_next: pre_next_ref,
            permutation_local: &perm_local_ext,
            permutation_next: &perm_next_ext,
            permutation_challenges: &challenges_per_instance[i],
            permutation_values: &perm_vals,
            lookups: &all_lookups[i],
            public_values: &public_values[i],
            trace_domain: init_trace_domain,
            zeta,
            alpha,
            quotient,
        };

        verify_constraints_with_lookups::<SC, A, LogUpGadget, PcsError<SC>>(
            air,
            &verifier_data,
            &lookup_gadget,
        )
        .map_err(|e| match e {
            VerificationError::OodEvaluationMismatch { .. } => {
                VerificationError::OodEvaluationMismatch { index: Some(i) }
            }
            other => other,
        })?;
    }

    let mut global_cumulative = BTreeMap::<&String, Vec<_>>::new();
    for data in global_lookup_data.iter().flatten() {
        global_cumulative
            .entry(&data.name)
            .or_default()
            .push(data.expected_cumulated);
    }

    for (name, all_expected_cumulative) in global_cumulative {
        lookup_gadget
            .verify_global_final_value(&all_expected_cumulative)
            .map_err(|e| VerificationError::LookupError(alloc::format!("{e:?}: {name}")))?;
    }

    Ok(())
}

pub struct VerifierData<'a, SC: SGC> {
    zeta: SC::Challenge,
    alpha: SC::Challenge,
    trace_local: &'a [SC::Challenge],
    trace_next: &'a [SC::Challenge],
    preprocessed_local: &'a [SC::Challenge],
    preprocessed_next: &'a [SC::Challenge],
    permutation_local: &'a [SC::Challenge],
    permutation_next: &'a [SC::Challenge],
    permutation_challenges: &'a [SC::Challenge],
    permutation_values: &'a [SC::Challenge],
    lookups: &'a [Lookup<Val<SC>>],
    public_values: &'a [Val<SC>],
    trace_domain: Domain<SC>,
    quotient: SC::Challenge,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_constraints_with_lookups<'a, SC, A, LG: LookupGadget, PcsErr: Debug>(
    air: &A,
    verifier_data: &VerifierData<'a, SC>,
    lookup_gadget: &LG,
) -> Result<(), VerificationError<PcsErr>>
where
    SC: SGC,
    A: for<'b> Air<VerifierConstraintFolderWithLookups<'b, SC>>,
{
    let VerifierData {
        trace_local,
        trace_next,
        preprocessed_local,
        preprocessed_next,
        permutation_local,
        permutation_next,
        permutation_challenges,
        permutation_values,
        lookups,
        public_values,
        trace_domain,
        zeta,
        alpha,
        quotient,
    } = verifier_data;

    let sels = trace_domain.selectors_at_point(*zeta);

    let main = VerticalPair::new(
        RowMajorMatrixView::new_row(trace_local),
        RowMajorMatrixView::new_row(trace_next),
    );

    let preprocessed = VerticalPair::new(
        RowMajorMatrixView::new_row(preprocessed_local),
        RowMajorMatrixView::new_row(preprocessed_next),
    );

    let preprocessed_window =
        RowWindow::from_two_rows(preprocessed.top.values, preprocessed.bottom.values);
    let inner_folder = VerifierConstraintFolder {
        main,
        preprocessed,
        preprocessed_window,
        public_values,
        is_first_row: sels.is_first_row,
        is_last_row: sels.is_last_row,
        is_transition: sels.is_transition,
        alpha: *alpha,
        accumulator: SC::Challenge::ZERO,
    };
    let mut folder = VerifierConstraintFolderWithLookups {
        inner: inner_folder,
        permutation: VerticalPair::new(
            RowMajorMatrixView::new_row(permutation_local),
            RowMajorMatrixView::new_row(permutation_next),
        ),
        permutation_challenges,
        permutation_values,
    };
    air.eval_with_lookups(&mut folder, lookups, lookup_gadget)
        .map_err(|_| VerificationError::InvalidProofShape)?;
    let folded_constraints = folder.inner.accumulator;

    if folded_constraints * sels.inv_vanishing != *quotient {
        return Err(VerificationError::OodEvaluationMismatch { index: None });
    }

    Ok(())
}
