use alloc::vec::Vec;

use itertools::Itertools;
use lib_q_stark_field::coset::TwoAdicMultiplicativeCoset;
use lib_q_stark_field::{
    ExtensionField,
    Field,
    TwoAdicField,
    batch_multiplicative_inverse,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_util::{
    log2_ceil_usize,
    log2_strict_usize,
};

/// Given a `PolynomialSpace`, `S`, and a subset `R`, a Lagrange selector `P_R` is
/// a polynomial which is not equal to `0` for every element in `R` but is equal
/// to `0` for every element of `S` not in `R`.
///
/// This struct contains evaluations of several Lagrange selectors for a fixed
/// `PolynomialSpace` over some collection of points disjoint from that
/// `PolynomialSpace`.
///
/// The Lagrange selector is normalized if it is equal to `1` for every element in `R`.
/// The LagrangeSelectors given here are not normalized.
#[derive(Debug)]
pub struct LagrangeSelectors<T> {
    /// A Lagrange selector corresponding to the first point in the space.
    pub is_first_row: T,
    /// A Lagrange selector corresponding to the last point in the space.
    pub is_last_row: T,
    /// A Lagrange selector corresponding the subset of all but the last point.
    pub is_transition: T,
    /// The inverse of the vanishing polynomial which is a Lagrange selector corresponding to the empty set
    pub inv_vanishing: T,
}

/// Fixing a field, `F`, `PolynomialSpace<Val = F>` denotes an indexed subset of `F^n`
/// with some additional algebraic structure.
///
/// We do not expect `PolynomialSpace` to store this subset, instead it usually contains
/// some associated data which allows it to generate the subset or pieces of it.
///
/// Each `PolynomialSpace` should be part of a family of similar spaces for some
/// collection of sizes (usually powers of two). Any space other than at the smallest size
/// should be decomposable into a disjoint collection of smaller spaces. Additionally, the
/// set of all `PolynomialSpace` of a given size should form a disjoint partition of some
/// subset of `F^n` which supports a group structure.
///
/// The canonical example of a `PolynomialSpace` is a coset `gH` of
/// a two-adic subgroup `H` of the multiplicative group `F*`. This satisfies the properties
/// above as cosets partition the group and decompose as `gH = g(H^2) u gh(H^2)` for `h` any
/// generator of `H`.
///
/// The other example in this code base is twin cosets which are sets of the form `gH u g^{-1}H`.
/// The decomposition above extends easily to this case as `h` is a generator if and only if `h^{-1}`
/// is and so `gH u g^{-1}H = (g(H^2) u g^{-1}(H^2)) u (gh(H^2) u (gh)^{-1}(H^2))`.
pub trait PolynomialSpace: Copy {
    /// The base field `F`.
    type Val: Field;

    /// The number of elements of the space.
    fn size(&self) -> usize;

    /// The first point in the space.
    fn first_point(&self) -> Self::Val;

    /// An algebraic function which takes the i'th element of the space and returns
    /// the (i+1)'th evaluated on the given point.
    ///
    /// When `PolynomialSpace` corresponds to a coset, `gH` this
    /// function is multiplication by `h` for a chosen generator `h` of `H`.
    ///
    /// This function may not exist for other classes of `PolynomialSpace` in which
    /// case this will return `None`.
    fn next_point<Ext: ExtensionField<Self::Val>>(&self, x: Ext) -> Option<Ext>;

    /// Return another `PolynomialSpace` with size at least `min_size` disjoint from this space.
    ///
    /// When working with spaces of power of two size, this will return a space of size `2^ceil(log_2(min_size))`.
    /// This will fail if `min_size` is too large. In particular, `log_2(min_size)` should be
    /// smaller than the `2`-adicity of the field.
    ///
    /// This fixes a canonical choice for prover/verifier determinism and LDE caching.
    ///
    /// # Panics
    /// Implementations backed by a two-adic domain (the only kind in this workspace today) will
    /// panic if `min_size` exceeds `1 << Val::TWO_ADICITY`. Callers that process
    /// untrusted/adversarial `min_size` values (e.g. a proof verifier deriving it from a claimed
    /// degree) MUST validate it themselves before calling this, or use
    /// [`try_create_disjoint_domain`](Self::try_create_disjoint_domain) instead.
    fn create_disjoint_domain(&self, min_size: usize) -> Self;

    /// Fallible sibling of [`create_disjoint_domain`](Self::create_disjoint_domain), for callers
    /// (such as proof verifiers) that must reject an out-of-range `min_size` instead of panicking.
    /// Returns `None` exactly under the conditions documented on `create_disjoint_domain`'s
    /// `# Panics` section.
    ///
    /// The default implementation simply delegates to the infallible method, so it is only
    /// non-panicking for implementations that override it; `TwoAdicMultiplicativeCoset` (the only
    /// implementation in this workspace) overrides it with a genuinely non-panicking check.
    fn try_create_disjoint_domain(&self, min_size: usize) -> Option<Self> {
        Some(self.create_disjoint_domain(min_size))
    }

    /// Split the `PolynomialSpace` into `num_chunks` smaller `PolynomialSpaces` of equal size.
    ///
    /// `num_chunks` must divide `self.size()` (which usually forces it to be a power of 2.) or
    /// this function will panic.
    fn split_domains(&self, num_chunks: usize) -> Vec<Self>;

    /// Split a set of polynomial evaluations over this `PolynomialSpace` into a vector
    /// of polynomial evaluations over each `PolynomialSpace` generated from `split_domains`.
    ///
    /// `evals.height()` must equal `self.size()` and `num_chunks` must divide `self.size()`.
    /// `evals` are assumed to be in standard (not bit-reversed) order.
    fn split_evals(
        &self,
        num_chunks: usize,
        evals: RowMajorMatrix<Self::Val>,
    ) -> Vec<RowMajorMatrix<Self::Val>>;

    /// Compute the vanishing polynomial of the space, evaluated at the given point.
    ///
    /// This is a polynomial which evaluates to `0` on every point of the
    /// space `self` and has degree equal to `self.size()`. In other words it is
    /// a choice of element of the defining ideal of the given set with this extra
    /// degree property.
    ///
    /// In the univariate case, it is equal, up to a linear factor, to the product over
    /// all elements `x`, of `(X - x)`. In particular this implies it will not evaluate
    /// to `0` at any point not in `self`.
    fn vanishing_poly_at_point<Ext: ExtensionField<Self::Val>>(&self, point: Ext) -> Ext;

    /// Compute several Lagrange selectors at a given point.
    /// - The Lagrange selector of the first point.
    /// - The Lagrange selector of the last point.
    /// - The Lagrange selector of everything but the last point.
    /// - The inverse of the vanishing polynomial.
    ///
    /// Note that these may not be normalized.
    fn selectors_at_point<Ext: ExtensionField<Self::Val>>(
        &self,
        point: Ext,
    ) -> LagrangeSelectors<Ext>;

    /// Compute several Lagrange selectors at all points of the given disjoint `PolynomialSpace`.
    /// - The Lagrange selector of the first point.
    /// - The Lagrange selector of the last point.
    /// - The Lagrange selector of everything but the last point.
    /// - The inverse of the vanishing polynomial.
    ///
    /// Note that these may not be normalized.
    fn selectors_on_coset(&self, coset: Self) -> LagrangeSelectors<Vec<Self::Val>>;
}

impl<Val: TwoAdicField> PolynomialSpace for TwoAdicMultiplicativeCoset<Val> {
    type Val = Val;

    fn size(&self) -> usize {
        self.size()
    }

    fn first_point(&self) -> Self::Val {
        self.shift()
    }

    /// Getting the next point corresponds to multiplication by the generator.
    fn next_point<Ext: ExtensionField<Val>>(&self, x: Ext) -> Option<Ext> {
        Some(x * self.subgroup_generator())
    }

    /// Given the coset `gH`, return the disjoint coset `gfK` where `f`
    /// is a fixed generator of `F^*` and `K` is the unique two-adic subgroup
    /// of with size `2^(ceil(log_2(min_size)))`.
    ///
    /// # Panics
    ///
    /// This will panic if `min_size` > `1 << Val::TWO_ADICITY`.
    fn create_disjoint_domain(&self, min_size: usize) -> Self {
        // We provide a short proof that these cosets are always disjoint:
        //
        // Assume without loss of generality that `|H| <= min_size <= |K|`.
        // Then we know that `gH` is entirely contained in `gK`. As cosets are
        // either equal or disjoint, this means that `gH` is disjoint from `g'K`
        // for every `g'` not contained in `gK`. As `f` is a generator of `F^*`
        // it does not lie in `K` and so `gf` cannot lie in `gK`.
        //
        // Thus `gH` and `gfK` are disjoint.
        self.try_create_disjoint_domain(min_size)
            .unwrap_or_else(|| {
                panic!(
                    "create_disjoint_domain: min_size {min_size} exceeds 1 << Val::TWO_ADICITY \
                 ({}); use try_create_disjoint_domain to handle this without panicking",
                    Val::TWO_ADICITY
                )
            })
    }

    /// See [`PolynomialSpace::try_create_disjoint_domain`]. Never panics; returns `None` exactly
    /// when `log2_ceil_usize(min_size) > Val::TWO_ADICITY` (the same condition under which
    /// `create_disjoint_domain` would panic).
    fn try_create_disjoint_domain(&self, min_size: usize) -> Option<Self> {
        Self::new(self.shift() * Val::GENERATOR, log2_ceil_usize(min_size))
    }

    /// Given the coset `gH` and generator `h` of `H`, let `K = H^{num_chunks}`
    /// be the unique group of order `|H|/num_chunks`.
    ///
    /// Then we decompose `gH` into `gK, ghK, gh^2K, ..., gh^{num_chunks}K`.
    fn split_domains(&self, num_chunks: usize) -> Vec<Self> {
        let log_chunks = log2_strict_usize(num_chunks);
        debug_assert!(log_chunks <= self.log_size());
        (0..num_chunks)
            .map(|i| {
                Self::new(
                    self.shift() * self.subgroup_generator().exp_u64(i as u64),
                    self.log_size() - log_chunks,
                )
                .unwrap() // This won't panic as `self.log_size() - log_chunks < self.log_size() < Val::TWO_ADICITY`
            })
            .collect()
    }

    fn split_evals(
        &self,
        num_chunks: usize,
        evals: RowMajorMatrix<Self::Val>,
    ) -> Vec<RowMajorMatrix<Self::Val>> {
        debug_assert_eq!(evals.height(), self.size());
        debug_assert!(log2_strict_usize(num_chunks) <= self.log_size());
        let height = evals.height();
        let width = evals.width();
        let rows_per_chunk = height / num_chunks;

        // Preallocate zeroed buffers per chunk; often faster for field elements.
        let mut values: Vec<Vec<Self::Val>> = (0..num_chunks)
            .map(|_| Self::Val::zero_vec(rows_per_chunk * width))
            .collect();

        // Distribute rows without using modulo: iterate blocks of size num_chunks.
        for i in 0..rows_per_chunk {
            let base_row = i * num_chunks;
            let dst_start = i * width;
            let dst_end = dst_start + width;
            for (chunk, dst_vec) in values.iter_mut().enumerate().take(num_chunks) {
                let r = base_row + chunk;
                // Safety: r < height == rows_per_chunk * num_chunks
                let row = unsafe { evals.row_slice_unchecked(r) };
                dst_vec[dst_start..dst_end].copy_from_slice(&row);
            }
        }

        values
            .into_iter()
            .map(|v| RowMajorMatrix::new(v, width))
            .collect()
    }

    /// Compute the vanishing polynomial at the given point:
    ///
    /// `Z_{gH}(X) = g^{-|H|}\prod_{h \in H} (X - gh) = (g^{-1}X)^|H| - 1`
    fn vanishing_poly_at_point<Ext: ExtensionField<Val>>(&self, point: Ext) -> Ext {
        (point * self.shift_inverse()).exp_power_of_2(self.log_size()) - Ext::ONE
    }

    /// Compute several Lagrange selectors at the given point:
    ///
    /// Defining the vanishing polynomial by `Z_{gH}(X) = g^{-|H|}\prod_{h \in H} (X - gh) = (g^{-1}X)^|H| - 1` return:
    /// - `Z_{gH}(X)/(g^{-1}X - 1)`: The Lagrange selector of the point `g`.
    /// - `Z_{gH}(X)/(g^{-1}X - h^{-1})`: The Lagrange selector of the point `gh^{-1}` where `h` is the generator of `H`.
    /// - `(g^{-1}X - h^{-1})`: The Lagrange selector of the subset consisting of everything but the point `gh^{-1}`.
    /// - `1/Z_{gH}(X)`: The inverse of the vanishing polynomial.
    fn selectors_at_point<Ext: ExtensionField<Val>>(&self, point: Ext) -> LagrangeSelectors<Ext> {
        let unshifted_point = point * self.shift_inverse();
        let z_h = unshifted_point.exp_power_of_2(self.log_size()) - Ext::ONE;
        LagrangeSelectors {
            is_first_row: z_h / (unshifted_point - Ext::ONE),
            is_last_row: z_h / (unshifted_point - self.subgroup_generator().inverse()),
            is_transition: unshifted_point - self.subgroup_generator().inverse(),
            inv_vanishing: z_h.inverse(),
        }
    }

    /// Compute the Lagrange selectors of our space at every point in the coset.
    ///
    /// This will error if our space is not the group `H` and if the given
    /// coset is not disjoint from `H`.
    fn selectors_on_coset(&self, coset: Self) -> LagrangeSelectors<Vec<Val>> {
        assert_eq!(self.shift(), Val::ONE);
        assert_ne!(coset.shift(), Val::ONE);
        assert!(coset.log_size() >= self.log_size());
        let rate_bits = coset.log_size() - self.log_size();

        let s_pow_n = coset.shift().exp_power_of_2(self.log_size());
        // evals of Z_H(X) = X^n - 1
        let evals = Val::two_adic_generator(rate_bits)
            .powers()
            .take(1 << rate_bits)
            .map(|x| s_pow_n * x - Val::ONE)
            .collect_vec();

        let xs = coset.iter().collect();

        let single_point_selector = |i: u64| {
            let coset_i = self.subgroup_generator().exp_u64(i);
            let denoms = xs.iter().map(|&x| x - coset_i).collect_vec();
            let invs = batch_multiplicative_inverse(&denoms);
            evals
                .iter()
                .cycle()
                .zip(invs)
                .map(|(&z_h, inv)| z_h * inv)
                .collect_vec()
        };

        let subgroup_last = self.subgroup_generator().inverse();

        LagrangeSelectors {
            is_first_row: single_point_selector(0),
            is_last_row: single_point_selector(self.size() as u64 - 1),
            is_transition: xs.into_iter().map(|x| x - subgroup_last).collect(),
            inv_vanishing: batch_multiplicative_inverse(&evals)
                .into_iter()
                .cycle()
                .take(coset.size())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_baby_bear::BabyBear;
    use lib_q_stark_field::{
        PrimeCharacteristicRing,
        PrimeField32,
    };

    use super::*;

    type F = BabyBear;

    fn coset(shift: F, log_size: usize) -> TwoAdicMultiplicativeCoset<F> {
        TwoAdicMultiplicativeCoset::new(shift, log_size).unwrap()
    }

    fn sorted_u32(points: impl IntoIterator<Item = F>) -> Vec<u32> {
        let mut v: Vec<u32> = points.into_iter().map(|p| p.as_canonical_u32()).collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn size_and_first_point_match_constructor_arguments() {
        let c = coset(F::new(7), 3);
        assert_eq!(PolynomialSpace::size(&c), 8);
        assert_eq!(PolynomialSpace::first_point(&c), F::new(7));
    }

    #[test]
    fn next_point_is_multiplication_by_the_subgroup_generator() {
        let c = coset(F::new(5), 4);
        let g = c.subgroup_generator();
        let x = F::new(123);
        assert_eq!(PolynomialSpace::next_point::<F>(&c, x), Some(x * g));
    }

    /// The subgroup generator has order exactly `size()`, so walking `next_point` around the
    /// coset `size()` times must return to the start. This is the group-law identity the whole
    /// `PolynomialSpace` abstraction rests on (`h^{|H|} = 1`).
    #[test]
    fn next_point_returns_to_start_after_exactly_size_steps() {
        let c = coset(F::new(11), 5);
        let mut x = PolynomialSpace::first_point(&c);
        for _ in 0..PolynomialSpace::size(&c) {
            x = PolynomialSpace::next_point::<F>(&c, x).unwrap();
        }
        assert_eq!(x, PolynomialSpace::first_point(&c));
    }

    /// `vanishing_poly_at_point` must be the zero polynomial exactly on the coset's own points.
    /// This is the soundness-relevant property of the whole module: every FRI/DEEP quotient in
    /// the STARK built on top of this crate divides by this polynomial, so if it is nonzero on an
    /// in-domain point (or zero off-domain), proofs either fail to verify honestly or a cheating
    /// prover gets a spurious zero to hide behind.
    #[test]
    fn vanishing_poly_is_zero_exactly_on_the_coset() {
        let c = coset(F::new(9), 4);
        for point in c.iter() {
            assert_eq!(
                PolynomialSpace::vanishing_poly_at_point::<F>(&c, point),
                F::ZERO
            );
        }

        // `create_disjoint_domain` is contractually guaranteed to be disjoint from `c` (see the
        // proof in its doc comment, exercised separately below), so every one of its points is
        // guaranteed to lie outside `c` and must NOT be a root of `c`'s vanishing polynomial.
        let disjoint = PolynomialSpace::create_disjoint_domain(&c, PolynomialSpace::size(&c));
        for point in disjoint.iter() {
            assert_ne!(
                PolynomialSpace::vanishing_poly_at_point::<F>(&c, point),
                F::ZERO
            );
        }
    }

    /// Negative control for the test above: prove it can actually distinguish "zero" from
    /// "nonzero" rather than passing vacuously (e.g. because of a mixed-up domain). Deliberately
    /// assert the wrong polarity and confirm the test harness reports it red.
    #[test]
    fn vanishing_poly_negative_control_distinguishes_in_from_out_of_domain() {
        let c = coset(F::new(9), 4);
        let on_domain_is_zero =
            PolynomialSpace::vanishing_poly_at_point::<F>(&c, PolynomialSpace::first_point(&c)) ==
                F::ZERO;
        let disjoint = PolynomialSpace::create_disjoint_domain(&c, PolynomialSpace::size(&c));
        let off_domain_is_zero = PolynomialSpace::vanishing_poly_at_point::<F>(
            &c,
            PolynomialSpace::first_point(&disjoint),
        ) == F::ZERO;
        // If these ever agreed, `vanishing_poly_is_zero_exactly_on_the_coset` above would be
        // unable to tell in-domain from out-of-domain and would pass no matter what the
        // implementation did.
        assert_ne!(on_domain_is_zero, off_domain_is_zero);
    }

    /// `create_disjoint_domain`'s two claims, checked directly: the returned coset (a) has size
    /// `min_size` rounded up to a power of two, and (b) shares no point with the original coset
    /// (the short proof for this is in the doc comment on the trait method).
    #[test]
    fn create_disjoint_domain_has_correct_size_and_shares_no_point() {
        let c = coset(F::new(13), 3); // size 8
        let c_points = sorted_u32(c.iter());
        for min_size in [1usize, 2, 3, 7, 8, 9, 20, 64] {
            let k = PolynomialSpace::create_disjoint_domain(&c, min_size);
            assert_eq!(PolynomialSpace::size(&k), min_size.next_power_of_two());
            assert_eq!(k.shift(), c.shift() * F::GENERATOR);

            let k_points = sorted_u32(k.iter());
            let mut merged = c_points.clone();
            merged.extend(&k_points);
            merged.sort_unstable();
            merged.dedup();
            // No duplicates survive dedup <=> the two point sets were disjoint.
            assert_eq!(merged.len(), c_points.len() + k_points.len());
        }
    }

    #[test]
    fn try_create_disjoint_domain_agrees_with_the_infallible_version_in_range() {
        let c = coset(F::new(13), 3);
        for min_size in [1usize, 5, 8, 100] {
            assert_eq!(
                PolynomialSpace::try_create_disjoint_domain(&c, min_size).map(|k| k.shift()),
                Some(PolynomialSpace::create_disjoint_domain(&c, min_size).shift())
            );
        }
    }

    #[test]
    fn try_create_disjoint_domain_rejects_out_of_range_min_size() {
        let c = coset(F::new(13), 3);
        // `F::TWO_ADICITY` itself is exactly representable...
        assert!(PolynomialSpace::try_create_disjoint_domain(&c, 1 << F::TWO_ADICITY).is_some());
        // ...but one more element than that requires one more bit of two-adicity than the field has.
        assert!(
            PolynomialSpace::try_create_disjoint_domain(&c, (1 << F::TWO_ADICITY) + 1).is_none()
        );
    }

    #[test]
    #[should_panic(expected = "exceeds 1 << Val::TWO_ADICITY")]
    fn create_disjoint_domain_panics_out_of_range_where_try_returns_none() {
        let c = coset(F::new(13), 3);
        let _ = PolynomialSpace::create_disjoint_domain(&c, (1 << F::TWO_ADICITY) + 1);
    }

    /// `split_domains` decomposes `gH` into cosets of the index-`num_chunks` subgroup `K <= H`.
    /// Group theory says those cosets exactly partition `gH`: pairwise disjoint, and their union
    /// recovers every point of the original coset. Check both halves of that claim directly
    /// instead of trusting the doc comment's proof sketch.
    #[test]
    fn split_domains_partition_the_original_coset() {
        let c = coset(F::new(17), 4); // size 16
        let orig_points = sorted_u32(c.iter());
        for &num_chunks in &[1usize, 2, 4, 8, 16] {
            let subs = PolynomialSpace::split_domains(&c, num_chunks);
            assert_eq!(subs.len(), num_chunks);

            let mut all_points: Vec<u32> = Vec::new();
            for s in &subs {
                assert_eq!(PolynomialSpace::size(s), c.size() / num_chunks);
                all_points.extend(s.iter().map(|p| p.as_canonical_u32()));
            }
            all_points.sort_unstable();
            assert_eq!(
                all_points, orig_points,
                "split_domains({num_chunks}) did not exactly partition the original coset"
            );
        }
    }

    /// Negative control: corrupt the recombination (drop the last sub-domain) and confirm the
    /// partition check above would in fact catch a broken split — i.e. it is not vacuously true
    /// because e.g. both sides happen to be sorted-empty.
    #[test]
    fn split_domains_negative_control_detects_a_missing_chunk() {
        let c = coset(F::new(17), 4);
        let orig_points = sorted_u32(c.iter());
        let subs = PolynomialSpace::split_domains(&c, 4);
        let mut all_points: Vec<u32> = Vec::new();
        // Deliberately drop one sub-domain, simulating a broken split.
        for s in &subs[..subs.len() - 1] {
            all_points.extend(s.iter().map(|p| p.as_canonical_u32()));
        }
        all_points.sort_unstable();
        assert_ne!(all_points, orig_points);
    }

    /// `split_evals` must place row `r` of the input into chunk `r % num_chunks` at position
    /// `r / num_chunks` — the same decimation `split_domains` performs on points (chunk `c`'s
    /// domain is `g^c * K` for `K = H^{num_chunks}`, so its `i`-th point is the `(i*num_chunks+c)`-th
    /// point of the original domain).
    #[test]
    fn split_evals_decimates_rows_to_match_split_domains() {
        let c = coset(F::new(3), 4); // size 16
        let width = 2;
        let height = c.size();
        let values: Vec<F> = (0..height * width)
            .map(|i| F::new((i / width) as u32))
            .collect();
        let evals = RowMajorMatrix::new(values, width);

        let num_chunks = 4;
        let chunks = PolynomialSpace::split_evals(&c, num_chunks, evals);
        assert_eq!(chunks.len(), num_chunks);
        let rows_per_chunk = height / num_chunks;
        for (chunk_idx, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.height(), rows_per_chunk);
            for i in 0..rows_per_chunk {
                let expected_row = i * num_chunks + chunk_idx;
                let row = chunk.row_slice(i).unwrap();
                assert_eq!(row[0], F::new(expected_row as u32));
            }
        }
    }

    /// `selectors_on_coset` is a batched, independently-derived recomputation of
    /// `selectors_at_point` (see the two doc comments: same closed forms, different code paths —
    /// one via `batch_multiplicative_inverse`, one via direct field division). Cross-checking them
    /// against each other is a much stronger test than checking either in isolation, since a bug
    /// shared by both derivations would not show up in either alone — but a bug in just one of the
    /// two implementations will.
    #[test]
    fn selectors_on_coset_agrees_with_selectors_at_point_for_every_point() {
        let h = coset(F::ONE, 3); // the subgroup H itself, size 8
        let disjoint_coset = PolynomialSpace::create_disjoint_domain(&h, 2 * h.size()); // size 16, rate 2

        let batched = PolynomialSpace::selectors_on_coset(&h, disjoint_coset);
        let points: Vec<F> = disjoint_coset.iter().collect();
        assert_eq!(points.len(), batched.is_first_row.len());

        for (i, &x) in points.iter().enumerate() {
            let single = PolynomialSpace::selectors_at_point::<F>(&h, x);
            assert_eq!(single.is_first_row, batched.is_first_row[i]);
            assert_eq!(single.is_last_row, batched.is_last_row[i]);
            assert_eq!(single.is_transition, batched.is_transition[i]);
            assert_eq!(single.inv_vanishing, batched.inv_vanishing[i]);
        }
    }

    /// Negative control: two different points of `disjoint_coset` must not, in general, produce
    /// identical selector values — otherwise the per-point comparison above could pass simply
    /// because every entry is some constant, independent of which point is plugged in.
    #[test]
    fn selectors_negative_control_values_actually_vary_by_point() {
        let h = coset(F::ONE, 3);
        let disjoint_coset = PolynomialSpace::create_disjoint_domain(&h, 2 * h.size());
        let mut points = disjoint_coset.iter();
        let x0 = points.next().unwrap();
        let x1 = points.next().unwrap();
        let s0 = PolynomialSpace::selectors_at_point::<F>(&h, x0);
        let s1 = PolynomialSpace::selectors_at_point::<F>(&h, x1);
        assert_ne!(s0.is_first_row, s1.is_first_row);
    }
}
