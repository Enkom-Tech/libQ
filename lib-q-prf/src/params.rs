//! Hard-coded safe primes and Gold exponents for pilot parameter sets.
//!
//! # Provenance (256-bit set)
//!
//! - **Generation:** `openssl prime -generate -safe -bits 255` (OpenSSL 3.x), decimal output
//!   `50427571419144900628919267453863926315743253667527897108380512375229288045819`.
//! - **Independent check:** SymPy `isprime(p)` and `isprime((p-1)//2)` both `True` (Miller-Rabin
//!   internally; deterministic for this size class).
//! - **Bit length:** 255 bits (`p < 2^256`, fits [`crypto_bigint::U256`]).
//! - **Encoding below:** big-endian hex (same integer as OpenSSL decimal).
//!
//! # Provenance (512-bit set)
//!
//! - **Generation:** `openssl prime -generate -safe -bits 511`, decimal
//!   `5846462199204458696044836418989331885058164550456003028279732171283212220247560926277230464259799968087668834545163644537944481399188821346081377725974863`.
//! - **Independent check:** SymPy `isprime(p)` and `isprime((p-1)//2)` both `True`.
//! - **Bit length:** 511 bits (fits [`crypto_bigint::U512`]).
//!
//! # Gold exponent
//!
//! For each safe prime `p = 2q + 1` with `q` prime, `p - 1 = 2^1 · q`. The pilot Gold exponent is
//! `g = q = (p-1)/2`, an odd divisor of `p-1` suitable for the power-residue PRF construction.

use crypto_bigint::modular::MontyParams;
use crypto_bigint::{
    NonZero,
    Odd,
    U256,
    U512,
};

/// Parameters for the Legendre PRF over \(\mathbb{F}_p\) with `p` a safe prime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegendrePrfParams256 {
    /// Safe prime modulus (`p > 0`).
    pub p: NonZero<U256>,
    /// Montgomery parameters for `p`.
    pub monty: MontyParams<U256>,
}

/// Parameters for the Legendre PRF at the 512-bit pilot modulus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegendrePrfParams512 {
    /// Safe prime modulus.
    pub p: U512,
    /// Montgomery parameters for `p`.
    pub monty: MontyParams<U512>,
}

/// Parameters for the Gold (power-residue) PRF: odd divisor `g` of `p-1` and modulus `p`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoldPrfParams256 {
    /// Prime modulus.
    pub p: U256,
    /// Montgomery parameters for `p`.
    pub monty: MontyParams<U256>,
    /// Gold exponent `g | (p-1)`.
    pub g: U256,
}

/// Gold PRF parameters at 512-bit pilot modulus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoldPrfParams512 {
    /// Prime modulus.
    pub p: U512,
    /// Montgomery parameters for `p`.
    pub monty: MontyParams<U512>,
    /// Gold exponent `g | (p-1)`.
    pub g: U512,
}

/// 256-bit pilot: `p` (255-bit safe prime), big-endian hex.
pub const P256_BE_HEX: &str = "6f7cfe74b8a1892ed54ec11ae8141a65dad3440973464111361ce7de4a5c5cfb";

/// 512-bit pilot: `p` (511-bit safe prime), big-endian hex.
pub const P512_BE_HEX: &str = "6fa0e975b4660858abfccfb1a2f3b5f8cda4239a89afa1840e62d758ae53a94059ab27f1f7833146306bf0d1c2647d9ca136b85e4c24dbdf0a4c8ef916f0094f";

#[inline]
fn monty_params_u256(p: U256) -> MontyParams<U256> {
    let odd = Odd::new(p).into_option().expect("pilot modulus is odd");
    MontyParams::new_vartime(odd)
}

#[inline]
fn monty_params_u512(p: U512) -> MontyParams<U512> {
    let odd = Odd::new(p).into_option().expect("pilot modulus is odd");
    MontyParams::new_vartime(odd)
}

impl LegendrePrfParams256 {
    /// Pilot modulus: 255-bit safe prime (`p = 2q+1`, `q` prime).
    #[must_use]
    pub fn pilot() -> Self {
        let p_uint = U256::from_be_hex(P256_BE_HEX);
        let p = NonZero::new(p_uint).expect("pilot modulus is non-zero");
        let monty = monty_params_u256(p.get());
        Self { p, monty }
    }

    /// Sophie Germain cofactor `q = (p-1)/2`.
    #[must_use]
    pub fn sophie_germain_cofactor(&self) -> U256 {
        self.p.get().wrapping_sub(&U256::ONE).shr(1)
    }
}

impl LegendrePrfParams512 {
    /// Pilot modulus: 511-bit safe prime.
    #[must_use]
    pub fn pilot() -> Self {
        let p = U512::from_be_hex(P512_BE_HEX);
        let monty = monty_params_u512(p);
        Self { p, monty }
    }

    /// `q = (p-1)/2`.
    #[must_use]
    pub fn sophie_germain_cofactor(&self) -> U512 {
        self.p.wrapping_sub(&U512::ONE).shr(1)
    }
}

impl GoldPrfParams256 {
    /// Pilot Gold PRF: `g = (p-1)/2` for the 256-bit safe prime field.
    #[must_use]
    pub fn pilot() -> Self {
        let leg = LegendrePrfParams256::pilot();
        let g = leg.sophie_germain_cofactor();
        GoldPrfParams256 {
            p: leg.p.get(),
            monty: leg.monty,
            g,
        }
    }
}

impl GoldPrfParams512 {
    /// Pilot Gold PRF at the 512-bit modulus.
    #[must_use]
    pub fn pilot() -> Self {
        let leg = LegendrePrfParams512::pilot();
        let g = leg.sophie_germain_cofactor();
        GoldPrfParams512 {
            p: leg.p,
            monty: leg.monty,
            g,
        }
    }
}

/// Encode a field element as fixed little-endian bytes (for wire formats / digests).
#[must_use]
pub fn u256_to_le_bytes(x: &U256) -> [u8; 32] {
    x.to_le_bytes().into()
}

/// Encode a `U512` as little-endian bytes.
#[must_use]
pub fn u512_to_le_bytes(x: &U512) -> [u8; 64] {
    x.to_le_bytes().into()
}

/// Parse a little-endian field element; must be `< p` for valid keys.
#[must_use]
pub fn u256_from_le_bytes(bytes: &[u8; 32]) -> U256 {
    U256::from_le_slice(bytes.as_slice())
}

/// Parse `U512` from little-endian bytes.
#[must_use]
pub fn u512_from_le_bytes(bytes: &[u8; 64]) -> U512 {
    U512::from_le_slice(bytes.as_slice())
}
