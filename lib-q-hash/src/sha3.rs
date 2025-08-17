use crate::block_api::{Sha3HasherCore, Sha3ReaderCore};
use digest::consts::{U0, U104, U136, U144, U16, U168, U200, U28, U32, U48, U64, U72};

// Paddings
const KECCAK_PAD: u8 = 0x01;
const SHA3_PAD: u8 = 0x06;
const SHAKE_PAD: u8 = 0x1f;

digest::buffer_fixed!(
    /// SHA-3-224 hasher.
    pub struct Sha3_224(Sha3HasherCore<U144, U28, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.7";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-3-256 hasher.
    pub struct Sha3_256(Sha3HasherCore<U136, U32, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.8";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-3-384 hasher.
    pub struct Sha3_384(Sha3HasherCore<U104, U48, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.9";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-3-512 hasher.
    pub struct Sha3_512(Sha3HasherCore<U72, U64, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.10";
    impl: FixedHashTraits;
);
digest::buffer_xof!(
    /// SHAKE128 hasher.
    pub struct Shake128(Sha3HasherCore<U168, U0, SHAKE_PAD>);
    oid: "2.16.840.1.101.3.4.2.11";
    impl: XofHasherTraits;
    /// SHAKE128 XOF reader.
    pub struct Shake128Reader(Sha3ReaderCore<U168>);
    impl: XofReaderTraits;
);
digest::buffer_xof!(
    /// SHAKE256 hasher.
    pub struct Shake256(Sha3HasherCore<U136, U0, SHAKE_PAD>);
    oid: "2.16.840.1.101.3.4.2.12";
    impl: XofHasherTraits;
    /// SHAKE256 XOF reader.
    pub struct Shake256Reader(Sha3ReaderCore<U136>);
    impl: XofReaderTraits;
);

digest::buffer_fixed!(
    /// SHA-3 CryptoNight variant.
    pub struct Keccak256Full(Sha3HasherCore<U136, U200, KECCAK_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-224 hasher.
    pub struct Keccak224(Sha3HasherCore<U144, U28, KECCAK_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-256 hasher.
    pub struct Keccak256(Sha3HasherCore<U136, U32, KECCAK_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-384 hasher.
    pub struct Keccak384(Sha3HasherCore<U104, U48, KECCAK_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-512 hasher.
    pub struct Keccak512(Sha3HasherCore<U72, U64, KECCAK_PAD>);
    impl: FixedHashTraits;
);

impl digest::CollisionResistance for Shake128 {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=31
    type CollisionResistance = U16;
}

impl digest::CollisionResistance for Shake256 {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=31
    type CollisionResistance = U32;
}
