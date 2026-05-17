use alloc::vec::Vec;

use lib_q_plonky_lookup::lookup_traits::{
    Kind,
    Lookup,
    LookupGadget,
};
use lib_q_plonky_uni_stark::{
    AirLayout,
    ConstraintLayout,
    SymbolicAirBuilder,
    get_constraint_layout as base_get_constraint_layout,
    get_symbolic_constraints as base_get_symbolic_constraints,
};
use lib_q_stark_air::Air;
use lib_q_stark_field::Field;
use lib_q_stark_util::log2_ceil_usize;
use tracing::instrument;

fn count_lookup_ext_constraints<F: Field>(lookups: &[Lookup<F>]) -> usize {
    lookups
        .iter()
        .map(|ctx| match &ctx.kind {
            Kind::Local => 2,
            Kind::Global(_) => 3,
        })
        .sum()
}

#[instrument(
    name = "compute constraint layout with lookups",
    skip_all,
    level = "debug"
)]
pub fn get_constraint_layout<F, A, LG>(
    air: &A,
    layout: AirLayout,
    lookups: &[Lookup<F>],
    _lookup_gadget: &LG,
) -> ConstraintLayout
where
    F: Field,
    A: Air<SymbolicAirBuilder<F>>,
    LG: LookupGadget,
{
    let base_layout = base_get_constraint_layout(air, layout);
    let n_base_constraints = base_layout.total_constraints();
    let n_lookup_ext = count_lookup_ext_constraints(lookups);

    let ext_lookup_indices: Vec<usize> =
        (n_base_constraints..n_base_constraints + n_lookup_ext).collect();

    let mut combined_ext = base_layout.ext_indices;
    combined_ext.extend(ext_lookup_indices);

    ConstraintLayout {
        base_indices: base_layout.base_indices,
        ext_indices: combined_ext,
    }
}

pub fn get_log_num_quotient_chunks<F, A, LG>(
    air: &A,
    layout: AirLayout,
    lookups: &[Lookup<F>],
    is_zk: usize,
    lookup_gadget: &LG,
) -> usize
where
    F: Field,
    A: Air<SymbolicAirBuilder<F>>,
    LG: LookupGadget,
{
    assert!(is_zk <= 1, "is_zk must be either 0 or 1");

    let lookup_degree = lookups
        .iter()
        .map(|ctx| lookup_gadget.constraint_degree(ctx))
        .max()
        .unwrap_or(0);

    if let Some(degree_hint) = air.max_constraint_degree() {
        let max_degree = degree_hint.max(lookup_degree);
        let constraint_degree = (max_degree + is_zk).max(2);
        let result = log2_ceil_usize(constraint_degree - 1);

        debug_assert!({
            let actual = get_max_constraint_degree(air, layout, lookups, lookup_gadget);
            max_degree >= actual
        });

        return result;
    }

    let air_degree = get_max_air_constraint_degree(air, layout);
    let max_degree = air_degree.max(lookup_degree);
    let constraint_degree = (max_degree + is_zk).max(2);
    log2_ceil_usize(constraint_degree - 1)
}

#[instrument(name = "infer constraint degree", skip_all, level = "debug")]
pub fn get_max_constraint_degree<F, A, LG>(
    air: &A,
    layout: AirLayout,
    lookups: &[Lookup<F>],
    lookup_gadget: &LG,
) -> usize
where
    F: Field,
    A: Air<SymbolicAirBuilder<F>>,
    LG: LookupGadget,
{
    let air_degree = get_max_air_constraint_degree(air, layout);
    let lookup_degree = lookups
        .iter()
        .map(|ctx| lookup_gadget.constraint_degree(ctx))
        .max()
        .unwrap_or(0);
    air_degree.max(lookup_degree)
}

fn get_max_air_constraint_degree<F, A>(air: &A, layout: AirLayout) -> usize
where
    F: Field,
    A: Air<SymbolicAirBuilder<F>>,
{
    let constraints = base_get_symbolic_constraints(air, layout);
    constraints
        .iter()
        .map(|c| c.degree_multiple())
        .max()
        .unwrap_or(0)
}

#[instrument(name = "evaluate constraints symbolically", skip_all, level = "debug")]
pub fn get_symbolic_constraints<F, A>(
    air: &A,
    layout: AirLayout,
) -> Vec<lib_q_stark_air::symbolic::SymbolicExpression<F>>
where
    F: Field,
    A: Air<SymbolicAirBuilder<F>>,
{
    base_get_symbolic_constraints(air, layout)
}
