use lib_q_stark_field::extension::{
    BinomiallyExtendable,
    BinomiallyExtendableAlgebra,
    HasTwoAdicBinomialExtension,
};
use lib_q_stark_field::{
    PrimeCharacteristicRing,
    TwoAdicField,
    field_to_array,
    packed_mod_add,
    packed_mod_sub,
};

use crate::utils::{
    add,
    sub,
};
use crate::{
    BinomialExtensionData,
    FieldParameters,
    MontyField31,
    TwoAdicData,
    base_mul_packed,
    octic_mul_packed,
    quartic_mul_packed,
    quintic_mul_packed,
};

// If a field implements BinomialExtensionData<WIDTH> then there is a natural
// field extension of degree WIDTH we can define.
// We perform no checks to make sure the data given in BinomialExtensionData<WIDTH> is valid and
// corresponds to an actual field extension. Ensuring that is left to the implementer.

impl<const WIDTH: usize, FP> BinomiallyExtendableAlgebra<Self, WIDTH> for MontyField31<FP>
where
    FP: BinomialExtensionData<WIDTH> + FieldParameters,
{
    #[inline(always)]
    fn binomial_mul(a: &[Self; WIDTH], b: &[Self; WIDTH], res: &mut [Self; WIDTH], _w: Self) {
        match WIDTH {
            4 => quartic_mul_packed(a, b, res),
            5 => quintic_mul_packed(a, b, res),
            8 => octic_mul_packed(a, b, res),
            _ => panic!("Unsupported binomial extension degree: {}", WIDTH),
        }
    }

    #[inline(always)]
    fn binomial_add(a: &[Self; WIDTH], b: &[Self; WIDTH]) -> [Self; WIDTH] {
        let mut res = [Self::ZERO; WIDTH];
        unsafe {
            // Safe as Self is repr(transparent) and stores a single u32.
            let a: &[u32; WIDTH] = &*(a.as_ptr() as *const [u32; WIDTH]);
            let b: &[u32; WIDTH] = &*(b.as_ptr() as *const [u32; WIDTH]);
            let res: &mut [u32; WIDTH] = &mut *(res.as_mut_ptr() as *mut [u32; WIDTH]);

            packed_mod_add(a, b, res, FP::PRIME, add::<FP>);
        }
        res
    }

    #[inline(always)]
    fn binomial_sub(a: &[Self; WIDTH], b: &[Self; WIDTH]) -> [Self; WIDTH] {
        let mut res = [Self::ZERO; WIDTH];
        unsafe {
            // Safe as Self is repr(transparent) and stores a single u32.
            let a: &[u32; WIDTH] = &*(a.as_ptr() as *const [u32; WIDTH]);
            let b: &[u32; WIDTH] = &*(b.as_ptr() as *const [u32; WIDTH]);
            let res: &mut [u32; WIDTH] = &mut *(res.as_mut_ptr() as *mut [u32; WIDTH]);

            packed_mod_sub(a, b, res, FP::PRIME, sub::<FP>);
        }
        res
    }

    #[inline(always)]
    fn binomial_base_mul(lhs: [Self; WIDTH], rhs: Self) -> [Self; WIDTH] {
        let mut res = [Self::ZERO; WIDTH];
        base_mul_packed(lhs, rhs, &mut res);
        res
    }
}

impl<const WIDTH: usize, FP> BinomiallyExtendable<WIDTH> for MontyField31<FP>
where
    FP: BinomialExtensionData<WIDTH> + FieldParameters,
{
    const W: Self = FP::W;

    const DTH_ROOT: Self = FP::DTH_ROOT;

    const EXT_GENERATOR: [Self; WIDTH] = FP::EXT_GENERATOR;
}

impl<const WIDTH: usize, FP> HasTwoAdicBinomialExtension<WIDTH> for MontyField31<FP>
where
    FP: BinomialExtensionData<WIDTH> + TwoAdicData + FieldParameters,
{
    const EXT_TWO_ADICITY: usize = FP::EXT_TWO_ADICITY;

    fn ext_two_adic_generator(bits: usize) -> [Self; WIDTH] {
        assert!(bits <= Self::EXT_TWO_ADICITY);
        if bits <= FP::TWO_ADICITY {
            field_to_array(Self::two_adic_generator(bits))
        } else {
            FP::TWO_ADIC_EXTENSION_GENERATORS.as_ref()[bits - FP::TWO_ADICITY - 1]
        }
    }
}

/// Degree-4 binomial extension tests (the FRI challenge field, in Plonky3's usual parameter
/// regime). `test_extension_field!` drives multiplication through `BinomiallyExtendableAlgebra::
/// binomial_mul`, which for `MontyField31<FP>` dispatches to `quartic_mul_packed` — the
/// portable version under the default (no_packing) build, and the SIMD version (`x86_64_avx2`/
/// `x86_64_avx512`) when this crate is recompiled with the corresponding `target-feature`. Running
/// this same test file under each `RUSTFLAGS` variant (see `scratchpad/monty31-simd-ci.md`) is what
/// actually exercises and validates the SIMD binomial-multiplication code, which otherwise compiles
/// under `#[cfg(...)]` but is never run by any test in this workspace.
#[cfg(test)]
mod ext4_tests {
    use lib_q_stark_field_testing::{
        test_extension_field,
        test_two_adic_extension_field,
    };

    test_extension_field!(crate::test_utils::TestField, crate::test_utils::TestEF4);
    test_two_adic_extension_field!(crate::test_utils::TestField, crate::test_utils::TestEF4);
}

/// Degree-5 binomial extension tests — exercises `quintic_mul_packed` the same way `ext4_tests`
/// exercises `quartic_mul_packed`. In its own module (as upstream does for BabyBear) because
/// `test_two_adic_extension_field!`'s internal `test_two_adic_field` import would otherwise clash
/// with `ext4_tests`'s.
#[cfg(test)]
mod ext5_tests {
    use lib_q_stark_field_testing::test_extension_field;

    test_extension_field!(crate::test_utils::TestField, crate::test_utils::TestEF5);
}
