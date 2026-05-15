//! Hash address definitions and serialization
//!
//! From FIPS-205 section 4.2:
//! > An ADRS
//! > consists of public values that indicate the position of the value being computed by the function. A
//! > different ADRS value is used for each call to each function. In the case of PRF, this is in order
//! > to generate a large number of different secret values from a single seed. In the case of Tℓ, H, and
//! > F, it is used to mitigate multi-target attacks.
//!
//! Address fields are big-endian integers. Each 32-bit or 64-bit lane is stored as a plain **stack**
//! byte array (`[u8; 4]` / `[u8; 8]`) so the in-memory representation matches the wire encoding without
//! relying on typed integer endianness or extra serialization crates.
//!
//! Note that `tree_adrs_high` is unused in all parameter sets currently defined by FIPS-205
//!
//! Rather than implementing a generic `setTypeAndClear` as specified in FIPS-205, we define specific transitions for those
//! address conversions which are actually used.

use hybrid_array::Array;
use typenum::U22;

/// A single 32-bit FIPS-205 ADRS word stored as four **big-endian** bytes on the stack.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct AdrsWord32([u8; 4]);

impl AdrsWord32 {
    /// Writes `value` in big-endian form into this ADRS word.
    #[inline]
    pub fn set(&mut self, value: u32) {
        self.0 = value.to_be_bytes();
    }

    /// Reads this ADRS word as a big-endian `u32`.
    #[inline]
    pub fn get(self) -> u32 {
        u32::from_be_bytes(self.0)
    }
}

impl From<u32> for AdrsWord32 {
    #[inline]
    fn from(value: u32) -> Self {
        Self(value.to_be_bytes())
    }
}

/// A single 64-bit FIPS-205 ADRS field (`tree_adrs` low half) stored as eight **big-endian** bytes.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct AdrsWord64([u8; 8]);

impl AdrsWord64 {
    /// Writes `value` in big-endian form into this ADRS field.
    #[inline]
    pub fn set(&mut self, value: u64) {
        self.0 = value.to_be_bytes();
    }
}

impl From<u64> for AdrsWord64 {
    #[inline]
    fn from(value: u64) -> Self {
        Self(value.to_be_bytes())
    }
}

/// `Address` represents a hash address as defined by FIPS-205 section 4.2
pub trait Address: AsRef<[u8]> {
    const TYPE_CONST: u32;

    #[allow(clippy::doc_markdown)] // False positive
    /// Returns the address as a compressed 22-byte array
    /// ADRSc = ADRS[3] ∥ ADRS[8 : 16] ∥ ADRS[19] ∥ ADRS[20 : 32]
    fn compressed(&self) -> Array<u8, U22> {
        let bytes = self.as_ref();
        let mut compressed = Array::<u8, U22>::default();
        compressed[0] = bytes[3];
        compressed[1..9].copy_from_slice(&bytes[8..16]);
        compressed[9] = bytes[19];
        compressed[10..22].copy_from_slice(&bytes[20..32]);
        compressed
    }
}

#[inline]
fn adrs_as_bytes<T>(t: &T) -> &[u8; 32] {
    debug_assert_eq!(core::mem::size_of::<T>(), 32);
    // SAFETY: Each `T` below is `#[repr(C)]` and composed only of `AdrsWord32` / `AdrsWord64`,
    // totalling exactly 32 bytes with no implicit padding (checked by the `debug_assert_eq` above).
    unsafe { &*core::ptr::from_ref(t).cast::<[u8; 32]>() }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct WotsHash {
    pub layer_adrs: AdrsWord32,
    pub tree_adrs_high: AdrsWord32,
    pub tree_adrs_low: AdrsWord64,
    type_const: AdrsWord32, // 0
    pub key_pair_adrs: AdrsWord32,
    pub chain_adrs: AdrsWord32,
    pub hash_adrs: AdrsWord32,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct WotsPk {
    pub layer_adrs: AdrsWord32,
    pub tree_adrs_high: AdrsWord32,
    pub tree_adrs_low: AdrsWord64,
    type_const: AdrsWord32, // 1
    pub key_pair_adrs: AdrsWord32,
    padding: AdrsWord64, // 0
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct HashTree {
    pub layer_adrs: AdrsWord32,
    pub tree_adrs_high: AdrsWord32,
    pub tree_adrs_low: AdrsWord64,
    type_const: AdrsWord32, // 2
    padding: AdrsWord32,    // 0
    pub tree_height: AdrsWord32,
    pub tree_index: AdrsWord32,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct ForsTree {
    layer_adrs: AdrsWord32, // 0
    pub tree_adrs_high: AdrsWord32,
    pub tree_adrs_low: AdrsWord64,
    type_const: AdrsWord32, // 3
    pub key_pair_adrs: AdrsWord32,
    pub tree_height: AdrsWord32,
    pub tree_index: AdrsWord32,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct ForsRoots {
    layer_adrs: AdrsWord32, // 0
    pub tree_adrs_high: AdrsWord32,
    pub tree_adrs_low: AdrsWord64,
    type_const: AdrsWord32, // 4
    pub key_pair_adrs: AdrsWord32,
    padding: AdrsWord64, // 0
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct WotsPrf {
    pub layer_adrs: AdrsWord32,
    pub tree_adrs_high: AdrsWord32,
    pub tree_adrs_low: AdrsWord64,
    type_const: AdrsWord32, // 5
    pub key_pair_adrs: AdrsWord32,
    pub chain_adrs: AdrsWord32,
    hash_adrs: AdrsWord32, // 0
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct ForsPrf {
    layer_adrs: AdrsWord32, // 0
    pub tree_adrs_high: AdrsWord32,
    pub tree_adrs_low: AdrsWord64,
    type_const: AdrsWord32, // 6
    pub key_pair_adrs: AdrsWord32,
    tree_height: AdrsWord32, // 0
    pub tree_index: AdrsWord32,
}

impl Address for WotsHash {
    const TYPE_CONST: u32 = 0;
}
impl AsRef<[u8]> for WotsHash {
    fn as_ref(&self) -> &[u8] {
        adrs_as_bytes(self).as_slice()
    }
}

impl Address for WotsPk {
    const TYPE_CONST: u32 = 1;
}
impl AsRef<[u8]> for WotsPk {
    fn as_ref(&self) -> &[u8] {
        adrs_as_bytes(self).as_slice()
    }
}

impl Address for HashTree {
    const TYPE_CONST: u32 = 2;
}
impl AsRef<[u8]> for HashTree {
    fn as_ref(&self) -> &[u8] {
        adrs_as_bytes(self).as_slice()
    }
}

impl Address for ForsTree {
    const TYPE_CONST: u32 = 3;
}
impl AsRef<[u8]> for ForsTree {
    fn as_ref(&self) -> &[u8] {
        adrs_as_bytes(self).as_slice()
    }
}

impl Address for ForsRoots {
    const TYPE_CONST: u32 = 4;
}
impl AsRef<[u8]> for ForsRoots {
    fn as_ref(&self) -> &[u8] {
        adrs_as_bytes(self).as_slice()
    }
}

impl Address for WotsPrf {
    const TYPE_CONST: u32 = 5;
}
impl AsRef<[u8]> for WotsPrf {
    fn as_ref(&self) -> &[u8] {
        adrs_as_bytes(self).as_slice()
    }
}

impl Address for ForsPrf {
    const TYPE_CONST: u32 = 6;
}
impl AsRef<[u8]> for ForsPrf {
    fn as_ref(&self) -> &[u8] {
        adrs_as_bytes(self).as_slice()
    }
}

impl WotsHash {
    pub fn prf_adrs(&self) -> WotsPrf {
        WotsPrf {
            layer_adrs: self.layer_adrs,
            tree_adrs_low: self.tree_adrs_low,
            tree_adrs_high: self.tree_adrs_high,
            type_const: WotsPrf::TYPE_CONST.into(),
            key_pair_adrs: self.key_pair_adrs,
            chain_adrs: 0.into(),
            hash_adrs: 0.into(),
        }
    }

    pub fn pk_adrs(&self) -> WotsPk {
        WotsPk {
            layer_adrs: self.layer_adrs,
            tree_adrs_low: self.tree_adrs_low,
            tree_adrs_high: self.tree_adrs_high,
            type_const: WotsPk::TYPE_CONST.into(),
            key_pair_adrs: self.key_pair_adrs,
            padding: 0.into(),
        }
    }

    pub fn tree_adrs(&self) -> HashTree {
        HashTree {
            layer_adrs: self.layer_adrs,
            tree_adrs_low: self.tree_adrs_low,
            tree_adrs_high: self.tree_adrs_high,
            type_const: HashTree::TYPE_CONST.into(),
            padding: 0.into(),
            tree_height: 0.into(),
            tree_index: 0.into(),
        }
    }
}

impl ForsTree {
    pub fn new(tree_adrs_low: u64, key_pair_adrs: u32) -> ForsTree {
        ForsTree {
            layer_adrs: 0.into(),
            tree_adrs_low: tree_adrs_low.into(),
            tree_adrs_high: 0.into(),
            type_const: ForsTree::TYPE_CONST.into(),
            key_pair_adrs: key_pair_adrs.into(),
            tree_height: 0.into(),
            tree_index: 0.into(),
        }
    }
    pub fn prf_adrs(&self) -> ForsPrf {
        ForsPrf {
            layer_adrs: 0.into(),
            tree_adrs_low: self.tree_adrs_low,
            tree_adrs_high: self.tree_adrs_high,
            type_const: ForsPrf::TYPE_CONST.into(),
            key_pair_adrs: self.key_pair_adrs,
            tree_height: 0.into(),
            tree_index: self.tree_index,
        }
    }

    pub fn fors_roots(&self) -> ForsRoots {
        ForsRoots {
            layer_adrs: 0.into(),
            tree_adrs_low: self.tree_adrs_low,
            tree_adrs_high: self.tree_adrs_high,
            type_const: ForsRoots::TYPE_CONST.into(),
            key_pair_adrs: self.key_pair_adrs,
            padding: 0.into(),
        }
    }
}

impl Default for WotsHash {
    fn default() -> Self {
        WotsHash {
            layer_adrs: AdrsWord32::default(),
            tree_adrs_low: AdrsWord64::default(),
            tree_adrs_high: AdrsWord32::default(),
            type_const: 0.into(),
            key_pair_adrs: AdrsWord32::default(),
            chain_adrs: AdrsWord32::default(),
            hash_adrs: AdrsWord32::default(),
        }
    }
}
