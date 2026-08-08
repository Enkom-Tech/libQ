use core::fmt;

use digest::block_api::{
    AlgorithmName,
    BlockSizeUser,
    ExtendableOutputCore,
    Reset,
    UpdateCore,
    XofReaderCore,
};
use digest::block_buffer::{
    EagerBuffer,
    ReadBuffer,
};
use digest::consts::{
    U0,
    U16,
    U32,
    U136,
    U168,
};
use digest::{
    CollisionResistance,
    ExtendableOutput,
    ExtendableOutputReset,
    HashMarker,
    Update,
    XofReader,
};

use crate::internal_block_api::{
    Sha3HasherCore,
    Sha3ReaderCore,
};
use crate::{
    DEFAULT_ROUND_COUNT,
    SHAKE_PAD,
};

macro_rules! impl_shake {
    (
        $name:ident, $reader_name:ident, $rate:ty, $alg_name:expr
    ) => {
        #[doc = $alg_name]
        #[doc = " hasher."]
        #[derive(Clone)]
        pub struct $name {
            core: Sha3HasherCore<$rate, U0, SHAKE_PAD, DEFAULT_ROUND_COUNT>,
            buffer: EagerBuffer<$rate>,
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self {
                    core: Default::default(),
                    buffer: Default::default(),
                }
            }
        }

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                let Self { core, buffer } = self;
                buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));
            }
        }

        impl ExtendableOutput for $name {
            type Reader = $reader_name;

            #[inline]
            fn finalize_xof(mut self) -> Self::Reader {
                let Self { core, buffer } = &mut self;
                let core = core.finalize_xof_core(buffer);
                let buffer = Default::default();
                Self::Reader { core, buffer }
            }
        }

        impl ExtendableOutputReset for $name {
            #[inline]
            fn finalize_xof_reset(&mut self) -> Self::Reader {
                let Self { core, buffer } = self;
                let core = core.finalize_xof_core(buffer);
                self.reset();
                let buffer = Default::default();
                Self::Reader { core, buffer }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($alg_name)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        #[cfg(feature = "zeroize")]
        impl digest::zeroize::ZeroizeOnDrop for $name {}

        #[doc = $alg_name]
        #[doc = " XOF reader."]
        #[derive(Clone)]
        pub struct $reader_name {
            core: Sha3ReaderCore<$rate, DEFAULT_ROUND_COUNT>,
            buffer: ReadBuffer<$rate>,
        }

        impl XofReader for $reader_name {
            #[inline]
            fn read(&mut self, buf: &mut [u8]) {
                let Self { core, buffer } = self;
                buffer.read(buf, |block| {
                    *block = core.read_block();
                });
            }
        }

        impl fmt::Debug for $reader_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($reader_name), " { ... }"))
            }
        }
    };
}

impl_shake!(Shake128, Shake128Reader, U168, "SHAKE128");
impl_shake!(Shake256, Shake256Reader, U136, "SHAKE256");

// `digest::CollisionResistance` is documented as "Collision resistance in BYTES ... applies to
// an output size of at least `2 * CollisionResistance` bytes" (digest 0.11.3, src/lib.rs:230).
// These previously carried U168 and U136 — the SHAKE sponge *rates*, copied from the
// `impl_shake!` lines above — which overstated both by roughly 10x. See card `t_c6851177`.
//
// FIPS 202 Table 4 caps SHAKE128 collision resistance at 128 bits and SHAKE256 at 256 bits, so
// the byte counts are 16 and 32. Every other `CollisionResistance` impl in this workspace and
// in the RustCrypto reference already uses these values.
impl CollisionResistance for Shake128 {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=31 — 128 bits / 8.
    type CollisionResistance = U16;
}

impl CollisionResistance for Shake256 {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=31 — 256 bits / 8.
    type CollisionResistance = U32;
}

#[cfg(test)]
mod tests {
    use digest::CollisionResistance;
    use digest::consts::{
        U16,
        U32,
    };
    use digest::typenum::Unsigned;

    use super::{
        Shake128,
        Shake256,
    };

    /// Pin the collision-resistance byte counts so the rate constants cannot drift back in.
    ///
    /// The defect this guards was a type-level overclaim with no runtime effect and no in-tree
    /// consumer, so nothing else in the suite could have caught it: a workspace-wide grep for
    /// `::CollisionResistance` finds no code that binds on or branches over the associated
    /// type. That is exactly why it needs an explicit assertion rather than being left to be
    /// noticed.
    #[test]
    fn collision_resistance_is_in_bytes_not_the_sponge_rate() {
        assert_eq!(
            <Shake128 as CollisionResistance>::CollisionResistance::USIZE,
            U16::USIZE,
            "SHAKE128 collision resistance must be 16 bytes (128 bits), not the 168-byte rate"
        );
        assert_eq!(
            <Shake256 as CollisionResistance>::CollisionResistance::USIZE,
            U32::USIZE,
            "SHAKE256 collision resistance must be 32 bytes (256 bits), not the 136-byte rate"
        );

        // Positive control: the two values must also differ from each other, so a change that
        // collapsed both to one constant could not satisfy the asserts above by accident.
        assert_ne!(U16::USIZE, U32::USIZE);
    }
}
