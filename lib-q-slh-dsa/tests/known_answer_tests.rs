//! Known-answer tests from the SPHINCS+ reference implementation
//! Generated via https://github.com/sphincs/sphincsplus on branch consistent_basew (eccdc43a99e194f52d5ef0e4030ef4dd1e31828b)
//! with PQCgenKAT_sign.c modified on line 59 to reduce iterations from 100 to 10
//!
//! These tests call the `slh_*_internal` functions directly, bypassing context processing.
//! By default only the Shake128f KAT is built. Enable `--features all-parameter-set-tests` for the full set.
//!
//! The FIPS 205 SHA2 parameter sets are not implemented (lib-Q ships no SHA-2), so their KATs are gone.
//!
//! The `*s` (small signature) parameter sets do heavy signing work; in a **debug** build, each KAT can exceed
//! Rust's 60s "still running" notice and total runtime grows quickly when tests run in parallel. For the full
//! six KATs locally or in CI, use the workspace `release-ci` profile, for example:
//! `cargo test -p lib-q-slh-dsa --profile release-ci --features all-parameter-set-tests --test known_answer_tests`.
//! The default Shake128f KAT is additionally `#[ignore]` in dev builds only (see `test_kat_shake_128f`).
#![cfg(feature = "alloc")]
#![cfg(not(target_arch = "wasm32"))]
use core::{error, fmt};
use std::array::from_fn;
use std::fmt::Write;

use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use lib_q_slh_dsa::*;
use rand_core::{Rng, TryCryptoRng, TryRng, UnwrapErr, utils};
use signature::{Keypair, SignatureEncoding};
use typenum::Unsigned;

/// AES-CTR-DRBG used to reproduce SPHINCS+ reference KAT streams.
///
/// This is deterministic by construction (seeded from test vectors) and exists solely for KAT
/// reproducibility.
struct KatDeterministicDrbg(Ctr128BE<Aes256>);

impl KatDeterministicDrbg {
    fn new(entropy: &[u8; 48]) -> Self {
        let key = [0u8; 32];
        let mut iv = [0u8; 16];
        iv[15] = 1;
        let mut this = Self(Ctr128BE::<Aes256>::new_from_slices(&key, &iv).unwrap());
        this.update(Some(entropy));
        this
    }

    fn update(&mut self, entropy: Option<&[u8; 48]>) {
        let mut tmp = entropy.map_or([0u8; 48], |e| *e);
        self.0.apply_keystream(&mut tmp);
        self.0 = Ctr128BE::<Aes256>::new_from_slices(&tmp[0..32], &tmp[32..48]).unwrap();
        self.0.apply_keystream(&mut [0; 16]); // discard one block
    }
}

impl TryRng for KatDeterministicDrbg {
    type Error = core::convert::Infallible;

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        dest.fill(0);
        self.0.apply_keystream(dest);
        // Discard up to end of block if not a multiple of 16
        let pad = (16 - (dest.len() % 16)) % 16;
        self.0.apply_keystream(&mut [0; 16][..pad]);
        self.update(None);
        Ok(())
    }

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        utils::next_word_via_fill::<u32, Self>(self)
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        utils::next_word_via_fill::<u64, Self>(self)
    }
}

impl TryCryptoRng for KatDeterministicDrbg {}

/// Fixed byte-stream RNG for deterministic key material replay in KATs.
///
/// Not an entropy source. `TryCryptoRng` is implemented only because the signature API requires a
/// crypto RNG marker even for deterministic test harnesses.
struct FixedKatByteStreamRng(Vec<u8>);

impl TryRng for FixedKatByteStreamRng {
    type Error = RandError;
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        let len = dest.len();
        if len > self.0.len() {
            return Err(RandError);
        }

        dest.iter_mut()
            .zip(self.0.drain(..len))
            .for_each(|(d, s)| *d = s);
        Ok(())
    }

    fn try_next_u32(&mut self) -> Result<u32, RandError> {
        let mut buf = [0; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, RandError> {
        let mut buf = [0; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

/// Not enough bytes error
#[derive(Debug)]
struct RandError;

impl fmt::Display for RandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not enough bytes")
    }
}

impl error::Error for RandError {}

impl TryCryptoRng for FixedKatByteStreamRng {}

const ITERS: usize = 10;
fn test_kat<P: ParameterSet + VerifyingKeyLen>(expected: &str)
where
    Signature<P>: SignatureEncoding,
{
    let mut resp: String = "# SPHINCS+\n\n".to_string();
    let mut rng = KatDeterministicDrbg::new(&from_fn(|i| i as u8));
    let mut seeds = [[0u8; 48]; ITERS];
    let mut msgs: Vec<Vec<u8>> = (0..ITERS).map(|i| vec![0; 33 * (i + 1)]).collect();

    for (seed, msg) in seeds.iter_mut().zip(msgs.iter_mut()) {
        rng.fill_bytes(seed);
        rng.fill_bytes(msg.as_mut_slice());
    }

    for i in 0..ITERS {
        let mut rng = KatDeterministicDrbg::new(&seeds[i]);

        writeln!(&mut resp, "count = {}", i).unwrap();
        writeln!(&mut resp, "seed = {}", hex::encode_upper(seeds[i])).unwrap();

        let mlen = 33 * (i + 1);
        writeln!(resp, "mlen = {}", mlen).unwrap();
        let msg = msgs[i].as_slice();
        writeln!(resp, "msg = {}", hex::encode_upper(msg)).unwrap();

        let mut seed = vec![0; (P::VkLen::USIZE * 3) / 2];
        rng.fill_bytes(&mut seed);
        let mut seed_rng = UnwrapErr(FixedKatByteStreamRng(seed));

        let sk = SigningKey::<P>::new(&mut seed_rng);
        let pk = sk.verifying_key();

        writeln!(resp, "pk = {}", hex::encode_upper(pk.to_bytes())).unwrap();
        writeln!(resp, "sk = {}", hex::encode_upper(sk.to_bytes().as_slice())).unwrap();

        let mut opt_rand = vec![0; P::VkLen::USIZE / 2];
        rng.fill_bytes(opt_rand.as_mut());

        let sig = sk.slh_sign_internal(&[msg], Some(&opt_rand)).to_bytes();
        writeln!(resp, "smlen = {}", sig.as_slice().len() + msg.len()).unwrap();
        writeln!(
            resp,
            "sm = {}{}\n",
            hex::encode_upper(&sig),
            hex::encode_upper(msg)
        )
        .unwrap();
    }

    let digest = lib_q_sha3::sha3_256(resp.as_bytes());
    assert_eq!(hex::encode(digest), expected);
}

/*
KATs generated via https://github.com/sphincs/sphincsplus on branch consistent_basew (eccdc43a99e194f52d5ef0e4030ef4dd1e31828b)
with PQCgenKAT_sign.c modified on line 59 to reduce iterations from 100 to 10.

Upstream publishes SHA-256 digests of the response files. lib-Q ships no SHA-2, so the tests pin the
SHA3-256 digest of the same response file instead. The pins were derived in one run that rebuilt each
response file, asserted that its SHA-256 equals the upstream digest, and printed its SHA3-256.

columns: SHA3-256 pin, upstream SHA-256, parameter set
7864641734c6a81e515f1cad3d35de2879d76bd964e60e93beee1356e13e743f 056ee235f9a8ff3fb3f3799807d82690ffe3ff5681f0c6e3809ddca4fb539b29 sphincs-shake-128f-simple
0fd079303d013c2367e1eeba3f70916aa26e64c3fcd0c0b711f2b2435d2c9a83 d83825fb99bc22a3eb4ae388a9e88716b5cae0622682a210bd11f7b8ffbd47ee sphincs-shake-192f-simple
d7c39afe5078362f19b193de564f79c29183c5a5085de9c5f93fedcf4d1ea5fb be37b5222c98b3a1f0d2d3d69bc32205ed17e93c6a4da684c76ee1ca29ec28ef sphincs-shake-256f-simple
a8f42c3b16de8dd2bea8fe4d8b9736a2b98b328d2ffbc67ce02f0c51bb9cf1dd 1930c23fb13b4f95ec11343d9a68d270879bfbb8821c1cfb59b37cd0b5e4665e sphincs-shake-128s-simple
0903d0232893313590e9c7f54924fdb1aa4589b9cc5e73b2d483468e181a8d13 7d35e89f91116f0869d7a7591df026c4033f8ca3e33d795f03b25905277175cd sphincs-shake-192s-simple
e643980cf4e38562e90ede2302fb387ba4ee2e29f2395e4430c2bd6cb18ceb89 7c8f16c7b9645df58518b1c0aa7a26f7a2e1b9ee860819f25305cf97aecce1f3 sphincs-shake-256s-simple
*/

// SHAKE-128f KAT does enough signing that a dev (unoptimized) build often exceeds Rust's 60s
// "still running" notice; CI already re-runs this suite under `--profile release-ci`.
#[cfg_attr(
    debug_assertions,
    ignore = "slow in dev profile; run: cargo test -p lib-q-slh-dsa --profile release-ci --test known_answer_tests test_kat_shake_128f"
)]
#[test]
fn test_kat_shake_128f() {
    test_kat::<Shake128f>("7864641734c6a81e515f1cad3d35de2879d76bd964e60e93beee1356e13e743f");
}

#[cfg(feature = "all-parameter-set-tests")]
#[test]
fn test_kat_shake_128s() {
    test_kat::<Shake128s>("a8f42c3b16de8dd2bea8fe4d8b9736a2b98b328d2ffbc67ce02f0c51bb9cf1dd");
}

#[cfg(feature = "all-parameter-set-tests")]
#[test]
fn test_kat_shake_192s() {
    test_kat::<Shake192s>("0903d0232893313590e9c7f54924fdb1aa4589b9cc5e73b2d483468e181a8d13");
}

#[cfg(feature = "all-parameter-set-tests")]
#[test]
fn test_kat_shake_192f() {
    test_kat::<Shake192f>("0fd079303d013c2367e1eeba3f70916aa26e64c3fcd0c0b711f2b2435d2c9a83");
}

#[cfg(feature = "all-parameter-set-tests")]
#[test]
fn test_kat_shake_256s() {
    test_kat::<Shake256s>("e643980cf4e38562e90ede2302fb387ba4ee2e29f2395e4430c2bd6cb18ceb89");
}

#[cfg(feature = "all-parameter-set-tests")]
#[test]
fn test_kat_shake_256f() {
    test_kat::<Shake256f>("d7c39afe5078362f19b193de564f79c29183c5a5085de9c5f93fedcf4d1ea5fb");
}
