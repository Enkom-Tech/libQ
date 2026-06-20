#[cfg(all(feature = "simd256", target_arch = "x86_64"))]
pub(crate) mod avx2;

pub(crate) mod portable;
pub(crate) mod traits;

#[cfg(test)]
pub(crate) mod tests;
