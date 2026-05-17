//! SIMD layout: 32 lanes × 8 coefficients = 256.

/// Field element in ML-DSA sense (`i32` representative).
pub type FieldElement = i32;

pub const COEFFICIENTS_IN_SIMD_UNIT: usize = 8;
pub const SIMD_UNITS_IN_RING_ELEMENT: usize = 32;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Coefficients {
    pub values: [FieldElement; COEFFICIENTS_IN_SIMD_UNIT],
}
