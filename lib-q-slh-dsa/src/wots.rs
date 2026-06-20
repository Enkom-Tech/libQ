use core::fmt::Debug;

use hybrid_array::{
    Array,
    ArraySize,
};
use typenum::Unsigned;
use typenum::generic_const_mappings::U;

use crate::hashes::HashSuite;
use crate::util::base_2b;
use crate::{
    SkSeed,
    address,
};

// WOTS+ in general is parameterized on these values
// But the FIPS standard uses the same values for all parameter sets
// So we make these global consts for simplicity
const LOG_W: usize = 4;
const W: u32 = 16;
const CK_LEN: usize = 3; // Length of a checksum in chunks

/// Largest `WotsSigLen` across all parameter sets (`2·N + 3`, N ≤ 32) — sizes the on-stack scratch
/// for per-index chain lengths so the batched paths need no allocation.
const MAX_WOTS_SIG_LEN: usize = 67;

/// Whether 4-way hash batching is worth it for **variable-length** chains.
///
/// Unlike `wots_pk_gen` (every chain runs the full `W-1` steps, no wasted work), `wots_sign` /
/// `wots_pk_from_sig` chains have per-index lengths, so lockstep batching wastes the steps a
/// finished lane would have skipped. That is a net win only when the batched permutation is itself
/// faster than the scalar one — i.e. on a CPU with AVX2. Off AVX2 (or no `std` for runtime
/// detection) the scalar path is used, which never does the wasted work.
#[inline]
fn variable_chain_batching_beneficial() -> bool {
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    {
        std::arch::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(all(feature = "std", target_arch = "x86_64")))]
    {
        false
    }
}

#[derive(Clone, Debug)]
pub struct WotsSig<P: WotsParams>(Array<Array<u8, P::N>, P::WotsSigLen>);

// Hand-written to avoid the `derive` adding a spurious `P: PartialEq/Eq` bound; the
// hash suite `P` is not `Eq`, but the signature contents (`Array<u8, _>`) are.
impl<P: WotsParams> PartialEq for WotsSig<P> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<P: WotsParams> Eq for WotsSig<P> {}

impl<P: WotsParams> WotsSig<P> {
    pub const SIZE: usize = P::N::USIZE * P::WotsSigLen::USIZE;

    pub fn write_to(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() == Self::SIZE, "WOTS+ serialize length mismatch");

        buf.chunks_exact_mut(P::N::USIZE)
            .zip(self.0.iter())
            .for_each(|(buf, sig)| buf.copy_from_slice(sig.as_slice()));
    }

    #[cfg(feature = "alloc")]
    #[cfg(test)]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut vec = alloc::vec![0u8; Self::SIZE];
        self.write_to(&mut vec);
        vec
    }
}

impl<P: WotsParams> TryFrom<&[u8]> for WotsSig<P> {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != Self::SIZE {
            return Err(());
        }
        let mut sig = Array::<Array<u8, P::N>, P::WotsSigLen>::default();
        for i in 0..P::WotsSigLen::USIZE {
            sig[i].copy_from_slice(&value[i * P::N::USIZE..(i + 1) * P::N::USIZE]);
        }
        Ok(WotsSig(sig))
    }
}

pub(crate) trait WotsParams: HashSuite {
    type WotsMsgLen: ArraySize; // Number of chunks in a WOTS message. Must equal 2 * Self::N
    type WotsSigLen: ArraySize + Debug + Eq; // Number of chunks in a WOTS signature. Must equal WotsSigLen + CK_LEN;

    /// Algorithm 4
    fn wots_chain(
        hasher: &Self,
        x: &Array<u8, Self::N>,
        i: u32,
        s: u32,
        adrs: &address::WotsHash,
    ) -> Array<u8, Self::N> {
        debug_assert!(i + s < 1 << LOG_W, "Invalid wots_chain index");

        let mut tmp = x.clone(); //TODO: no clone
        let mut adrs = adrs.clone(); // TODO: no clone
        for j in i..(i + s) {
            adrs.hash_adrs.set(j);
            tmp = hasher.f(&adrs, &tmp); // TODO: overwrite existing buffer
        }
        tmp
    }

    /// Run four WOTS+ chains in lockstep through [`f_x4`](crate::hashes::HashSuite::f_x4): lane `k`
    /// starts from `cur[k]` at hash index `starts[k]` and applies `lens[k]` steps. Lanes that finish
    /// early are frozen — their surplus `f_x4` lanes are computed but discarded — so callers gate on
    /// [`variable_chain_batching_beneficial`]. Byte-identical to four scalar [`wots_chain`] calls.
    fn wots_chain_x4(
        hasher: &Self,
        base_adrs: &address::WotsHash,
        chain_idx: [u32; 4],
        starts: [u32; 4],
        lens: [u32; 4],
        mut cur: [Array<u8, Self::N>; 4],
    ) -> [Array<u8, Self::N>; 4] {
        let max_len = lens.iter().copied().max().unwrap_or(0);
        let mut adrs: [address::WotsHash; 4] = core::array::from_fn(|k| {
            let mut a = base_adrs.clone();
            a.chain_adrs.set(chain_idx[k]);
            a.hash_adrs.set(starts[k]);
            a
        });
        for g in 0..max_len {
            for k in 0..4 {
                if g < lens[k] {
                    adrs[k].hash_adrs.set(starts[k] + g);
                }
            }
            let res = hasher.f_x4(&adrs, &cur);
            for k in 0..4 {
                if g < lens[k] {
                    cur[k] = res[k].clone();
                }
            }
        }
        cur
    }

    /// Algorithm 5
    fn wots_pk_gen(
        hasher: &Self,
        sk_seed: &SkSeed<Self::N>,
        adrs: &address::WotsHash,
    ) -> Array<u8, Self::N> {
        let mut adrs = adrs.clone();
        let mut sk_adrs = adrs.prf_adrs();
        let total = Self::WotsSigLen::USIZE;
        let mut tmp = Array::<Array<u8, Self::N>, Self::WotsSigLen>::default();

        // The `total` chains are independent, and in `pk_gen` every chain runs the full `W-1`
        // steps, so we batch them four at a time and step the four chains in lockstep through
        // `f_x4`. This is byte-for-byte identical to the scalar `from_fn` it replaces (the SHAKE
        // suites override `f_x4` with a 4-way Keccak permutation; everyone else falls back to four
        // scalar `f` calls).
        let mut i = 0;
        while i + 4 <= total {
            let mut chain_adrs: [address::WotsHash; 4] = core::array::from_fn(|lane| {
                let mut a = adrs.clone();
                a.chain_adrs
                    .set((i + lane).try_into().expect("i is less than 2^32"));
                a
            });
            let mut cur: [Array<u8, Self::N>; 4] = core::array::from_fn(|lane| {
                sk_adrs
                    .chain_adrs
                    .set((i + lane).try_into().expect("i is less than 2^32"));
                hasher.prf_sk(sk_seed, &sk_adrs)
            });
            for j in 0..(W - 1) {
                for a in &mut chain_adrs {
                    a.hash_adrs.set(j);
                }
                cur = hasher.f_x4(&chain_adrs, &cur);
            }
            for (lane, c) in cur.into_iter().enumerate() {
                tmp[i + lane] = c;
            }
            i += 4;
        }
        // Tail chains (`total % 4`): scalar.
        while i < total {
            let ci = u32::try_from(i).expect("i is less than 2^32");
            sk_adrs.chain_adrs.set(ci);
            adrs.chain_adrs.set(ci);
            let sk = hasher.prf_sk(sk_seed, &sk_adrs);
            tmp[i] = Self::wots_chain(hasher, &sk, 0, (1 << LOG_W) - 1, &adrs);
            i += 1;
        }

        hasher.t(&adrs.pk_adrs(), &tmp)
    }

    // Algorithm 6
    fn wots_sign(
        hasher: &Self,
        m: &Array<u8, Self::N>,
        sk_seed: &SkSeed<Self::N>,
        adrs: &address::WotsHash,
    ) -> WotsSig<Self> {
        let msg = base_2b::<Self::WotsMsgLen, U<LOG_W>>(m.as_slice());
        let csum = msg.iter().map(|&x| (1 << LOG_W) - 1 - x).sum::<u16>() << 4; // Algorithm 6 Line 9

        let csum_bytes = csum.to_be_bytes();
        let csum_chunks = base_2b::<U<CK_LEN>, U<LOG_W>>(&csum_bytes);
        let mut msg_csum = msg.iter().chain(csum_chunks.iter());

        let mut adrs = adrs.clone();
        let mut sk_adrs = adrs.prf_adrs();
        let total = Self::WotsSigLen::USIZE;

        if variable_chain_batching_beneficial() {
            // Per-index chain length = message/checksum digit (each in `0..W`).
            let mut steps = [0u16; MAX_WOTS_SIG_LEN];
            for (slot, v) in steps.iter_mut().zip(msg_csum.by_ref()) {
                *slot = *v;
            }
            let mut sig = Array::<Array<u8, Self::N>, Self::WotsSigLen>::default();
            let mut i = 0;
            while i + 4 <= total {
                let sks: [Array<u8, Self::N>; 4] = core::array::from_fn(|k| {
                    sk_adrs
                        .chain_adrs
                        .set((i + k).try_into().expect("i is less than 2^32"));
                    hasher.prf_sk(sk_seed, &sk_adrs)
                });
                let chain_idx =
                    core::array::from_fn(|k| u32::try_from(i + k).expect("i is less than 2^32"));
                let lens = core::array::from_fn(|k| u32::from(steps[i + k]));
                let res = Self::wots_chain_x4(hasher, &adrs, chain_idx, [0; 4], lens, sks);
                for (k, c) in res.into_iter().enumerate() {
                    sig[i + k] = c;
                }
                i += 4;
            }
            while i < total {
                let ci = u32::try_from(i).expect("i is less than 2^32");
                sk_adrs.chain_adrs.set(ci);
                adrs.chain_adrs.set(ci);
                let sk = hasher.prf_sk(sk_seed, &sk_adrs);
                sig[i] = Self::wots_chain(hasher, &sk, 0, u32::from(steps[i]), &adrs);
                i += 1;
            }
            WotsSig(sig)
        } else {
            let sig = Array::<Array<u8, Self::N>, Self::WotsSigLen>::from_fn(|i: usize| {
                let i: u32 = i.try_into().expect("i is less than 2^32");
                sk_adrs.chain_adrs.set(i);
                adrs.chain_adrs.set(i);

                let sk = hasher.prf_sk(sk_seed, &sk_adrs);
                Self::wots_chain(hasher, &sk, 0, u32::from(*msg_csum.next().unwrap()), &adrs)
            });

            WotsSig(sig)
        }
    }

    fn wots_pk_from_sig(
        hasher: &Self,
        sig: &WotsSig<Self>,
        m: &Array<u8, Self::N>,
        adrs: &address::WotsHash,
    ) -> Array<u8, Self::N> {
        let msg = base_2b::<Self::WotsMsgLen, U<LOG_W>>(m.as_slice());
        let csum = msg.iter().map(|&x| (1 << LOG_W) - 1 - x).sum::<u16>() << 4; // TODO: remove magic 4
        let csum_bytes = csum.to_be_bytes();
        let csum_chunks = base_2b::<U<CK_LEN>, U<LOG_W>>(&csum_bytes);
        let mut msg_csum = msg.iter().chain(csum_chunks.iter());

        let mut adrs = adrs.clone();
        let total = Self::WotsSigLen::USIZE;
        let tmp = if variable_chain_batching_beneficial() {
            // Chain `i` starts at `msg_i` and runs `W-1-msg_i` steps from `sig[i]`.
            let mut msg_i = [0u16; MAX_WOTS_SIG_LEN];
            for (slot, v) in msg_i.iter_mut().zip(msg_csum.by_ref()) {
                *slot = *v;
            }
            let mut tmp = Array::<Array<u8, Self::N>, Self::WotsSigLen>::default();
            let mut i = 0;
            while i + 4 <= total {
                let chain_idx =
                    core::array::from_fn(|k| u32::try_from(i + k).expect("i is less than 2^32"));
                let starts = core::array::from_fn(|k| u32::from(msg_i[i + k]));
                let lens = core::array::from_fn(|k| W - 1 - u32::from(msg_i[i + k]));
                let cur: [Array<u8, Self::N>; 4] = core::array::from_fn(|k| sig.0[i + k].clone());
                let res = Self::wots_chain_x4(hasher, &adrs, chain_idx, starts, lens, cur);
                for (k, c) in res.into_iter().enumerate() {
                    tmp[i + k] = c;
                }
                i += 4;
            }
            while i < total {
                adrs.chain_adrs
                    .set(i.try_into().expect("i is less than 2^32"));
                let m_i = u32::from(msg_i[i]);
                tmp[i] = Self::wots_chain(hasher, &sig.0[i], m_i, W - 1 - m_i, &adrs);
                i += 1;
            }
            tmp
        } else {
            Array::<Array<u8, Self::N>, Self::WotsSigLen>::from_fn(|i: usize| {
                adrs.chain_adrs
                    .set(i.try_into().expect("i is less than 2^32"));
                let msg_i = u32::from(*msg_csum.next().unwrap());
                Self::wots_chain(hasher, &sig.0[i], msg_i, W - 1 - msg_i, &adrs)
            })
        };
        hasher.t(&adrs.pk_adrs(), &tmp)
    }
}
#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use hybrid_array::Array;
    use lib_q_random::new_secure_rng;
    use rand_core::Rng;

    use super::WotsParams;
    use crate::address::WotsHash;
    use crate::hashes::{
        HashSuite,
        Shake128f,
    };
    use crate::util::macros::test_parameter_sets;
    use crate::{
        PkSeed,
        SkSeed,
    };

    fn test_sign_verify<Wots: WotsParams>() {
        // Generate random sk_seed, pk_seed, message, address
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");

        let sk_seed = SkSeed::new(&mut rng);

        let pk_seed = PkSeed::new(&mut rng);

        let mut msg = Array::<u8, _>::default();
        rng.fill_bytes(msg.as_mut_slice());

        let adrs = &WotsHash::default();
        let hasher = Wots::new_from_pk_seed(&pk_seed);

        let pk = Wots::wots_pk_gen(&hasher, &sk_seed, adrs);

        let sig = Wots::wots_sign(&hasher, &msg, &sk_seed, adrs);
        let pk_recovered = Wots::wots_pk_from_sig(&hasher, &sig, &msg, adrs);

        assert_eq!(pk, pk_recovered);
    }

    test_parameter_sets!(test_sign_verify);

    fn test_sign_verify_fail<Wots: WotsParams>() {
        // Generate random sk_seed, pk_seed, message
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");

        let sk_seed = SkSeed::new(&mut rng);

        let pk_seed = PkSeed::new(&mut rng);

        let mut msg = Array::<u8, _>::default();
        rng.fill_bytes(msg.as_mut_slice());

        let adrs = &WotsHash::default();
        let hasher = Wots::new_from_pk_seed(&pk_seed);

        // Generate public key
        let pk = Wots::wots_pk_gen(&hasher, &sk_seed, adrs);

        // Sign the message
        let sig = Wots::wots_sign(&hasher, &msg, &sk_seed, adrs);

        // Tweak the message
        msg[0] ^= 0xFF; // Invert the first byte of the message

        // Attempt to recover the public key from the tweaked message and signature
        let pk_recovered = Wots::wots_pk_from_sig(&hasher, &sig, &msg, adrs);

        // Check that the recovered public key does not match the original public key
        assert_ne!(
            pk, pk_recovered,
            "Signature verification should fail with a modified message"
        );
    }

    test_parameter_sets!(test_sign_verify_fail);

    #[test]
    fn test_pk_gen_shake128f_kat() {
        let sk_seed = SkSeed(Array([1; 16]));
        let pk_seed = PkSeed(Array([2; 16]));
        let adrs = WotsHash::default();

        // Generated by https://github.com/mjosaarinen/slh-dsa-py
        let expected = Array(hex!("98b63dd1574484876b1f8a1120421eac"));

        let hasher = Shake128f::new_from_pk_seed(&pk_seed);
        let result = Shake128f::wots_pk_gen(&hasher, &sk_seed, &adrs);

        assert_eq!(result, expected);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_sign_shake128f_kat() {
        let sk_seed = SkSeed(Array([1; 16]));
        let pk_seed = PkSeed(Array([2; 16]));
        let adrs = &WotsHash::default();
        let msg = Array([3; 16]);

        let expected = &hex!(
            "f7bcb9575590faae2e6a8ae33149082d2ec777cff4051f43177ef44bcbd2c18d
            a94146c50037c914461dd6ed720192b059bd2be6ed8d8cf26e4e9d68fbf9ded1
            6c334bed21677c6a3679f17a8425de40431b4317326c5d825d931b4a54a1b81f
            e7ad259086ea665109a7eca79f03e3619d99af5d0419fece8300973f29467f28
            d2b18639eeaa826488f6c785d492703463e80f8b088e64de9ca3b373cead611f
            d356bf6c22f70f98f229174a9ac815342f0439eb289a78f49f47aa8c3f272a15
            f5f0f5020b5d71981254daa9e1f01a90248935c1c67ad1cf71d9224184820cf9
            ece9b737ec986c86ba0a9431ff8485c274140bebc9d856316d49128eb075f81a
            c00d32b9f949940f2dd684a2e615e16b47093eb49e3bc9d77e69c7944d7063c6
            f8b4b5aa46fe759999fa2892ce4c7881b80f38d684427a0b77f3ad43377833d2
            d94c600b340ea408a0ad7c32c409bdb4ebaade3b1dda4ac8584acba979c845a9
            b0ddfc69ea22ffb415745b779b45d7af00ca9fde87e5d59385d7b5cedec6e30f
            3346f573f59a00af993a2ec314ed951e3a8c00f69364a82fa34d14933fe3cdb7
            bd5e5d511297695bad5cda22daea8d39f61d4ed34412acd1f5399a54953ae04b
            09828f90877ad7f01605631ace0a4e7c773cc887e2d0fa0bd3d6db811794df3a
            a8721c308482ccb511c9133311653ce8f9c2336e2980c2ab554c41bad436c0c7
            1c394d3f7eafcea2806c153113d6291a912c0e73e44197763b9ead341c298585
            bc6e16d8458fc1917ff4ac57de461ee1"
        );

        let hasher = Shake128f::new_from_pk_seed(&pk_seed);
        let result = Shake128f::wots_sign(&hasher, &msg, &sk_seed, adrs);
        assert_eq!(result.to_vec(), expected.as_slice());
    }
}
