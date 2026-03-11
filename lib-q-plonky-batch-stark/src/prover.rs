use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;

use lib_q_plonky_lookup::AirWithLookups;
use lib_q_plonky_lookup::logup::LogUpGadget;
use lib_q_plonky_lookup::lookup_traits::{
    Lookup,
    LookupGadget,
};
use lib_q_plonky_uni_stark::{
    AirLayout,
    Domain,
    OpenedValues,
    ProverConstraintFolder,
    ProverError,
    SymbolicAirBuilder,
    Val,
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
    PackedValue,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::{
    RowMajorMatrix,
    RowMajorMatrixView,
};
use lib_q_stark_util::log2_strict_usize;
use tracing::{
    debug_span,
    info_span,
    instrument,
};

use crate::common::{
    CommonData,
    ProverData,
    get_perm_challenges,
};
use crate::config::{
    Challenge,
    StarkGenericConfig as SGC,
    observe_instance_binding,
};
use crate::folder::ProverConstraintFolderWithLookups;
use crate::proof::{
    BatchCommitments,
    BatchOpenedValues,
    BatchProof,
    OpenedValuesWithLookups,
};
use crate::symbolic::{
    get_constraint_layout,
    get_log_num_quotient_chunks,
};

#[derive(Debug)]
pub struct StarkInstance<'a, SC: SGC, A> {
    pub air: &'a A,
    pub trace: &'a RowMajorMatrix<Val<SC>>,
    pub public_values: Vec<Val<SC>>,
    pub lookups: Vec<Lookup<Val<SC>>>,
}

impl<'a, SC: SGC, A> StarkInstance<'a, SC, A> {
    pub fn new_multiple(
        airs: &'a [A],
        traces: &'a [&'a RowMajorMatrix<Val<SC>>],
        public_values: &[Vec<Val<SC>>],
        common_data: &CommonData<SC>,
    ) -> Vec<Self> {
        airs.iter()
            .zip(traces.iter())
            .zip(public_values.iter())
            .zip(common_data.lookups.iter())
            .map(|(((air, trace), public_values), lookups)| Self {
                air,
                trace,
                public_values: public_values.clone(),
                lookups: lookups.clone(),
            })
            .collect()
    }
}

/// Quotient polynomial values over the quotient domain for one instance, with lookups.
#[instrument(skip_all, level = "debug")]
#[allow(clippy::too_many_arguments)]
fn quotient_values_with_lookups<SC, A, Mat, LG>(
    air: &A,
    public_values: &[Val<SC>],
    layout: AirLayout,
    trace_domain: Domain<SC>,
    quotient_domain: Domain<SC>,
    trace_on_quotient_domain: &Mat,
    opt_permutation_on_quotient_domain: Option<&Mat>,
    lookups: &[Lookup<Val<SC>>],
    permutation_vals: &[SC::Challenge],
    lookup_gadget: &LG,
    permutation_challenges: &[SC::Challenge],
    preprocessed_on_quotient_domain: Option<&Mat>,
    alpha: SC::Challenge,
) -> Vec<SC::Challenge>
where
    SC: SGC,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>,
    Mat: Matrix<Val<SC>> + Sync,
    LG: LookupGadget,
{
    use crate::config::{
        PackedChallenge,
        PackedVal,
    };

    let quotient_size = quotient_domain.size();
    let main_width = trace_on_quotient_domain.width();
    let (perm_width, perm_height) = opt_permutation_on_quotient_domain
        .as_ref()
        .map_or((0, 0), |m| (m.width(), m.height()));
    let ext_degree = SC::Challenge::DIMENSION;

    let mut sels = debug_span!("compute selectors")
        .in_scope(|| trace_domain.selectors_on_coset(quotient_domain));

    let qdb = log2_strict_usize(quotient_domain.size()) - log2_strict_usize(trace_domain.size());
    let next_step = 1 << qdb;

    let pack_width = PackedVal::<SC>::WIDTH;
    for _ in quotient_size..pack_width {
        sels.is_first_row.push(Val::<SC>::default());
        sels.is_last_row.push(Val::<SC>::default());
        sels.is_transition.push(Val::<SC>::default());
        sels.inv_vanishing.push(Val::<SC>::default());
    }

    let constraint_layout = get_constraint_layout(air, layout, lookups, lookup_gadget);
    let (base_alpha_powers, ext_alpha_powers) = constraint_layout.decompose_alpha(alpha);

    let packed_perm_challenges: Vec<PackedChallenge<SC>> = permutation_challenges
        .iter()
        .map(|&c| PackedChallenge::<SC>::from(c))
        .collect();
    let permutation_vals_packed: Vec<PackedChallenge<SC>> = permutation_vals
        .iter()
        .map(|&v| PackedChallenge::<SC>::from(v))
        .collect();

    (0..quotient_size)
        .step_by(pack_width)
        .flat_map(|i_start| {
            let i_range = i_start..i_start + pack_width;

            let is_first_row = *PackedVal::<SC>::from_slice(&sels.is_first_row[i_range.clone()]);
            let is_last_row = *PackedVal::<SC>::from_slice(&sels.is_last_row[i_range.clone()]);
            let is_transition = *PackedVal::<SC>::from_slice(&sels.is_transition[i_range.clone()]);
            let inv_vanishing = *PackedVal::<SC>::from_slice(&sels.inv_vanishing[i_range]);

            let main = RowMajorMatrix::new(
                trace_on_quotient_domain.vertically_packed_row_pair(i_start, next_step),
                main_width,
            );

            let preprocessed = preprocessed_on_quotient_domain.map(|preprocessed| {
                let w = preprocessed.width();
                RowMajorMatrix::new(
                    preprocessed.vertically_packed_row_pair(i_start, next_step),
                    w,
                )
            });
            let preprocessed_view = preprocessed
                .as_ref()
                .map_or_else(|| RowMajorMatrixView::new(&[], 0), |m| m.as_view());
            let preprocessed_window = RowWindow::from_view(&preprocessed_view);

            let permutation = opt_permutation_on_quotient_domain.as_ref().map_or_else(
                || RowMajorMatrix::new(vec![], 0),
                |perm_mat| {
                    let perms = (0..perm_width)
                        .step_by(ext_degree)
                        .map(|col| {
                            PackedChallenge::<SC>::from_basis_coefficients_fn(|i| {
                                PackedVal::<SC>::from_fn(|offset| {
                                    perm_mat
                                        .get((i_start + offset) % perm_height, col + i)
                                        .unwrap()
                                })
                            })
                        })
                        .chain((0..perm_width).step_by(ext_degree).map(|col| {
                            PackedChallenge::<SC>::from_basis_coefficients_fn(|i| {
                                PackedVal::<SC>::from_fn(|offset| {
                                    perm_mat
                                        .get((i_start + next_step + offset) % perm_height, col + i)
                                        .unwrap()
                                })
                            })
                        }));
                    RowMajorMatrix::new(perms.collect::<Vec<_>>(), perm_width / ext_degree)
                },
            );

            let inner_folder = ProverConstraintFolder {
                main: main.as_view(),
                preprocessed: preprocessed_view,
                preprocessed_window,
                public_values,
                is_first_row,
                is_last_row,
                is_transition,
                base_alpha_powers: &base_alpha_powers,
                ext_alpha_powers: &ext_alpha_powers,
                base_constraints: Vec::with_capacity(constraint_layout.base_indices.len()),
                ext_constraints: Vec::with_capacity(constraint_layout.ext_indices.len()),
                constraint_index: 0,
                constraint_count: constraint_layout.total_constraints(),
            };

            let mut folder = ProverConstraintFolderWithLookups {
                inner: inner_folder,
                permutation: permutation.as_view(),
                permutation_challenges: &packed_perm_challenges,
                permutation_values: &permutation_vals_packed,
            };
            let _ = air.eval_with_lookups(&mut folder, lookups, lookup_gadget);

            let quotient = folder.inner.finalize_constraints() * inv_vanishing;

            (0..min(quotient_size, pack_width)).map(move |idx_in_packing| {
                SC::Challenge::from_basis_coefficients_fn(|d| {
                    quotient.as_basis_coefficients_slice()[d].as_slice()[idx_in_packing]
                })
            })
        })
        .collect()
}

/// Proves multiple AIR instances in a single batch proof.
///
/// For zeroization of sensitive trace data, wrap each instance's trace in a type that zeroizes
/// on drop before calling. When using `lib-q-stark`, use [`lib_q_stark::secret::SecretWitness`]:
///
/// ```ignore
/// use lib_q_stark::secret::SecretWitness;
/// let secret_trace = SecretWitness::new(trace);
/// let instance = StarkInstance { air, trace: secret_trace.trace(), ... };
/// let proof = prove_batch(config, &[instance], prover_data);
/// ```
#[instrument(skip_all)]
pub fn prove_batch<SC, A>(
    config: &SC,
    instances: &[StarkInstance<'_, SC, A>],
    prover_data: &ProverData<SC>,
) -> Result<BatchProof<SC>, ProverError>
where
    SC: SGC,
    A: Air<SymbolicAirBuilder<Val<SC>>>
        + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
        + Clone,
{
    let common = &prover_data.common;
    let lookup_gadget = LogUpGadget::new();
    let pcs = config.pcs();
    let mut challenger = config.initialise_challenger();

    let degrees: Vec<usize> = instances.iter().map(|i| i.trace.height()).collect();
    let log_degrees: Vec<usize> = degrees.iter().copied().map(log2_strict_usize).collect();
    let log_ext_degrees: Vec<usize> = log_degrees.iter().map(|&d| d + config.is_zk()).collect();

    let (all_lookups, mut lookup_data): (
        Vec<Vec<Lookup<Val<SC>>>>,
        Vec<Vec<lib_q_plonky_lookup::LookupData<SC::Challenge>>>,
    ) = instances
        .iter()
        .map(|inst| {
            (
                inst.lookups.clone(),
                inst.lookups
                    .iter()
                    .filter_map(|lookup| match &lookup.kind {
                        lib_q_plonky_lookup::lookup_traits::Kind::Global(name) => {
                            Some(lib_q_plonky_lookup::LookupData {
                                name: name.clone(),
                                aux_idx: lookup.columns[0],
                                expected_cumulated: SC::Challenge::ZERO,
                            })
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .unzip();

    let (trace_domains, ext_trace_domains): (Vec<Domain<SC>>, Vec<Domain<SC>>) = degrees
        .iter()
        .map(|&deg| {
            (
                pcs.natural_domain_for_degree(deg),
                pcs.natural_domain_for_degree(deg * (config.is_zk() + 1)),
            )
        })
        .unzip();

    let airs: Vec<&A> = instances.iter().map(|i| i.air).collect();
    let pub_vals: Vec<Vec<Val<SC>>> = instances.iter().map(|i| i.public_values.clone()).collect();

    let mut preprocessed_widths = Vec::with_capacity(airs.len());
    let (log_num_quotient_chunks, num_quotient_chunks): (Vec<usize>, Vec<usize>) = airs
        .iter()
        .zip(pub_vals.iter())
        .enumerate()
        .map(|(i, (air, _))| {
            let pre_w = common
                .preprocessed
                .as_ref()
                .and_then(|g| g.instances.get(i).and_then(|o| o.as_ref()).map(|m| m.width))
                .unwrap_or(0);
            preprocessed_widths.push(pre_w);
            let layout = AirLayout {
                preprocessed_width: pre_w,
                main_width: air.width(),
                num_public_values: air.num_public_values(),
            };
            let lq = get_log_num_quotient_chunks::<Val<SC>, A, LogUpGadget>(
                airs[i],
                layout,
                &all_lookups[i],
                config.is_zk(),
                &lookup_gadget,
            );
            let n_chunks = 1 << (lq + config.is_zk());
            (lq, n_chunks)
        })
        .unzip();

    let n_instances = airs.len();
    challenger.observe_base_as_algebra_element::<Challenge<SC>>(Val::<SC>::from_usize(n_instances));

    for i in 0..n_instances {
        observe_instance_binding::<SC>(
            &mut challenger,
            log_ext_degrees[i],
            log_degrees[i],
            airs[i].width(),
            num_quotient_chunks[i],
        );
    }

    let main_commit_inputs: Vec<_> = instances
        .iter()
        .zip(ext_trace_domains.iter().cloned())
        .map(|(inst, dom)| (dom, inst.trace.clone()))
        .collect();
    let (main_commit, main_data) = pcs.commit(main_commit_inputs);

    challenger.observe(main_commit.clone());
    for pv in &pub_vals {
        challenger.observe_slice(pv);
    }
    for &pre_w in &preprocessed_widths {
        challenger.observe_base_as_algebra_element::<Challenge<SC>>(Val::<SC>::from_usize(pre_w));
    }
    if let Some(global) = &common.preprocessed {
        challenger.observe(global.commitment.clone());
    }

    let challenges_per_instance =
        get_perm_challenges::<SC, LogUpGadget>(&mut challenger, &all_lookups, &lookup_gadget);

    let mut permutation_commit_inputs = Vec::new();
    for (i, inst) in instances.iter().enumerate() {
        if all_lookups[i].is_empty() {
            continue;
        }
        let preprocessed_trace = inst.air.preprocessed_trace();
        let generated_perm = lookup_gadget.generate_permutation(
            inst.trace,
            &preprocessed_trace,
            &inst.public_values,
            &all_lookups[i],
            &mut lookup_data[i],
            &challenges_per_instance[i],
        );
        let ext_dom = ext_trace_domains[i].clone();
        permutation_commit_inputs.push((ext_dom, generated_perm.flatten_to_base()));
    }

    let permutation_commit_and_data = if permutation_commit_inputs.is_empty() {
        None
    } else {
        let (commit, data) = pcs.commit(permutation_commit_inputs);
        challenger.observe(commit.clone());
        for data_list in &lookup_data {
            for ld in data_list {
                challenger.observe_algebra_element(ld.expected_cumulated);
            }
        }
        Some((commit, data))
    };

    let alpha: SC::Challenge = challenger.sample_algebra_element();

    let mut quotient_chunk_domains: Vec<Domain<SC>> = Vec::new();
    let mut quotient_chunk_mats: Vec<RowMajorMatrix<Val<SC>>> = Vec::new();
    let mut quotient_chunk_ranges: Vec<(usize, usize)> = Vec::with_capacity(n_instances);

    let mut perm_counter = 0usize;
    for (i, trace_domain) in trace_domains.iter().enumerate() {
        let _span = info_span!("compute quotient", air_idx = i).entered();

        let log_chunks = log_num_quotient_chunks[i];
        let n_chunks = num_quotient_chunks[i];
        let quotient_domain =
            ext_trace_domains[i].create_disjoint_domain(1 << (log_ext_degrees[i] + log_chunks));

        let layout = AirLayout {
            preprocessed_width: preprocessed_widths[i],
            main_width: airs[i].width(),
            num_public_values: airs[i].num_public_values(),
        };

        let trace_on_quotient_domain =
            pcs.get_evaluations_on_domain(&main_data, i, quotient_domain.clone());

        let permutation_on_quotient_domain = permutation_commit_and_data
            .as_ref()
            .filter(|_| !all_lookups[i].is_empty())
            .map(|(_, perm_data)| {
                let evals =
                    pcs.get_evaluations_on_domain(perm_data, perm_counter, quotient_domain.clone());
                perm_counter += 1;
                evals
            });

        let preprocessed_on_quotient_domain = common
            .preprocessed
            .as_ref()
            .and_then(|g| g.instances.get(i).and_then(|o| o.as_ref()))
            .map(|meta| {
                let preprocessed_prover_data = prover_data
                    .prover_only
                    .preprocessed_prover_data
                    .as_ref()
                    .expect("preprocessed_prover_data when preprocessed columns exist");
                pcs.get_evaluations_on_domain_no_random(
                    preprocessed_prover_data,
                    meta.matrix_index,
                    quotient_domain.clone(),
                )
            });

        let perm_vals: Vec<SC::Challenge> = lookup_data[i]
            .iter()
            .map(|ld| ld.expected_cumulated)
            .collect();

        let q_values = quotient_values_with_lookups(
            airs[i],
            &pub_vals[i],
            layout,
            *trace_domain,
            quotient_domain.clone(),
            &trace_on_quotient_domain,
            permutation_on_quotient_domain.as_ref(),
            &all_lookups[i],
            &perm_vals,
            &lookup_gadget,
            &challenges_per_instance[i],
            preprocessed_on_quotient_domain.as_ref(),
            alpha,
        );

        let q_flat = RowMajorMatrix::new_col(q_values).flatten_to_base();
        let chunk_mats = quotient_domain.split_evals(n_chunks, q_flat);
        let chunk_domains = quotient_domain.split_domains(n_chunks);

        let start = quotient_chunk_domains.len();
        quotient_chunk_domains.extend(chunk_domains.clone());
        let end = quotient_chunk_domains.len();

        let evals = chunk_domains.into_iter().zip(chunk_mats);
        let ldes = pcs.get_quotient_ldes(evals, n_chunks);
        quotient_chunk_mats.extend(ldes);
        quotient_chunk_ranges.push((start, end));
    }

    let (quotient_commit, quotient_data) = pcs.commit_ldes(quotient_chunk_mats);
    challenger.observe(quotient_commit.clone());

    let (opt_r_commit, opt_r_data) = if SC::Pcs::ZK {
        let (r_commit, r_data) = pcs
            .get_opt_randomization_poly_commitment(ext_trace_domains.iter().cloned())
            .ok_or(ProverError::MissingRandomizationCommitment)?;
        (Some(r_commit), Some(r_data))
    } else {
        (None, None)
    };

    if let Some(r_commit) = &opt_r_commit {
        challenger.observe(r_commit.clone());
    }

    let zeta: SC::Challenge = challenger.sample_algebra_element();

    let mut rounds: Vec<(
        &<SC::Pcs as Pcs<Challenge<SC>, SC::Challenger>>::ProverData,
        Vec<Vec<SC::Challenge>>,
    )> = Vec::new();

    if let Some(r_data) = &opt_r_data {
        let round0_points = trace_domains.iter().map(|_| vec![zeta]).collect::<Vec<_>>();
        rounds.push((r_data, round0_points));
    }

    let round1_points: Vec<Vec<SC::Challenge>> = trace_domains
        .iter()
        .enumerate()
        .map(|(i, dom)| {
            if airs[i].main_next_row_columns().is_empty() {
                Ok(vec![zeta])
            } else {
                dom.next_point(zeta)
                    .ok_or(ProverError::NextPointUnavailable)
                    .map(|znext| vec![zeta, znext])
            }
        })
        .collect::<Result<Vec<_>, ProverError>>()?;
    rounds.push((&main_data, round1_points));

    let round2_points: Vec<Vec<SC::Challenge>> = quotient_chunk_ranges
        .iter()
        .copied()
        .flat_map(|(s, e)| (s..e).map(|_| vec![zeta]))
        .collect();
    rounds.push((&quotient_data, round2_points));

    if let Some(global) = &common.preprocessed {
        let preprocessed_prover_data = prover_data
            .prover_only
            .preprocessed_prover_data
            .as_ref()
            .expect("preprocessed when common.preprocessed is some");
        let pre_points: Vec<Vec<SC::Challenge>> = global
            .matrix_to_instance
            .iter()
            .map(|&inst_idx| {
                if airs[inst_idx].preprocessed_next_row_columns().is_empty() {
                    Ok(vec![zeta])
                } else {
                    trace_domains[inst_idx]
                        .next_point(zeta)
                        .ok_or(ProverError::NextPointUnavailable)
                        .map(|znext| vec![zeta, znext])
                }
            })
            .collect::<Result<Vec<_>, ProverError>>()?;
        rounds.push((preprocessed_prover_data, pre_points));
    }

    let lookup_points: Vec<Vec<SC::Challenge>> = trace_domains
        .iter()
        .zip(&all_lookups)
        .filter(|(_, lookups)| !lookups.is_empty())
        .map(|(dom, _)| {
            dom.next_point(zeta)
                .ok_or(ProverError::NextPointUnavailable)
                .map(|znext| vec![zeta, znext])
        })
        .collect::<Result<Vec<_>, ProverError>>()?;

    if let Some((_, perm_data)) = &permutation_commit_and_data {
        rounds.push((perm_data, lookup_points));
    }

    let (opened_values, opening_proof) =
        pcs.open_with_preprocessing(rounds, &mut challenger, common.preprocessed.is_some());

    let trace_idx = SC::Pcs::TRACE_IDX;
    let quotient_idx = SC::Pcs::QUOTIENT_IDX;
    let preprocessed_idx = SC::Pcs::PREPROCESSED_TRACE_IDX;
    let permutation_idx = if common.preprocessed.is_some() {
        preprocessed_idx + 1
    } else {
        preprocessed_idx
    };

    let trace_values_for_mats = &opened_values[trace_idx];
    let preprocessed_openings = common
        .preprocessed
        .as_ref()
        .map(|_| &opened_values[preprocessed_idx]);

    let empty_perm: Vec<Vec<Vec<SC::Challenge>>> = vec![];
    let permutation_values_for_mats = if permutation_commit_and_data.is_some() {
        &opened_values[permutation_idx]
    } else {
        &empty_perm
    };
    let mut permutation_values_iter = permutation_values_for_mats.iter();

    let mut quotient_openings_iter = opened_values[quotient_idx].iter();

    let mut per_instance: Vec<OpenedValuesWithLookups<SC::Challenge>> =
        Vec::with_capacity(n_instances);

    for (i, (s, e)) in quotient_chunk_ranges.iter().copied().enumerate() {
        let random = opt_r_data.as_ref().map(|_| opened_values[0][i][0].clone());

        let tv = &trace_values_for_mats[i];
        let trace_local = tv[0].clone();
        let trace_next = if airs[i].main_next_row_columns().is_empty() {
            None
        } else {
            Some(tv[1].clone())
        };

        let mut qcs = Vec::new();
        for _ in s..e {
            let mat_vals = quotient_openings_iter
                .next()
                .expect("quotient chunk in bounds");
            qcs.push(mat_vals[0].clone());
        }

        let (preprocessed_local, preprocessed_next) =
            match (&common.preprocessed, preprocessed_openings) {
                (Some(global), Some(pre_round)) => global
                    .instances
                    .get(i)
                    .and_then(|o| o.as_ref())
                    .map_or((None, None), |meta| {
                        let vals = &pre_round[meta.matrix_index];
                        if airs[i].preprocessed_next_row_columns().is_empty() {
                            (Some(vals[0].clone()), None)
                        } else {
                            (Some(vals[0].clone()), Some(vals[1].clone()))
                        }
                    }),
                _ => (None, None),
            };

        let (permutation_local, permutation_next) = if all_lookups[i].is_empty() {
            (vec![], vec![])
        } else {
            let perm_v = permutation_values_iter
                .next()
                .expect("permutation openings");
            (perm_v[0].clone(), perm_v[1].clone())
        };

        let base_opened = OpenedValues {
            trace_local,
            trace_next,
            preprocessed_local,
            preprocessed_next,
            quotient_chunks: qcs,
            random,
        };

        per_instance.push(OpenedValuesWithLookups {
            base_opened_values: base_opened,
            permutation_local,
            permutation_next,
        });
    }

    let permutation = permutation_commit_and_data.as_ref().map(|(c, _)| c.clone());

    Ok(BatchProof {
        commitments: BatchCommitments {
            main: main_commit,
            quotient_chunks: quotient_commit,
            random: opt_r_commit,
            permutation,
        },
        opened_values: BatchOpenedValues {
            instances: per_instance,
        },
        opening_proof,
        global_lookup_data: lookup_data,
        degree_bits: log_ext_degrees,
    })
}
