//! Foundational ML-KEM value types shared by `algebra` (which holds their arithmetic, NTT, and
//! sampling implementations) and `param` (the parameter traits).
//!
//! `NttVector<K: ArraySize>` is generic over `ArraySize` while `param`'s parameter traits refer to
//! `FieldElement`/`NttVector`, which previously made `algebra` and `param` mutually dependent.
//! Keeping just the bare definitions in this leaf module (no arithmetic, no `crypto`/`encode`
//! dependencies) lets both modules depend on it instead of on each other — same types, same
//! layout, no behavioral change.

use core::fmt::Debug;

use hybrid_array::Array;
use hybrid_array::typenum::U256;

/// Backing integer for [`FieldElement`]; wider than `q` (12 bits) so modular reductions can be
/// deferred.
pub type Integer = u16;

/// An element of GF(q).  Although `q` is only 16 bits wide, we use a wider uint type to so that we
/// can defer modular reductions.
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct FieldElement(pub Integer);

/// An element of the ring `T_q`, i.e., a tuple of 128 elements of the direct sum components of `T_q`.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct NttPolynomial(pub Array<FieldElement, U256>);

/// A vector of K NTT-domain polynomials
#[derive(Clone, Default, Debug, PartialEq)]
pub struct NttVector<K: ArraySize>(pub Array<NttPolynomial, K>);

/// An array length with other useful properties
pub trait ArraySize: hybrid_array::ArraySize + PartialEq + Debug {}

impl<T> ArraySize for T where T: hybrid_array::ArraySize + PartialEq + Debug {}
