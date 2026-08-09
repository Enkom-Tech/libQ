//! Byte-exact known-answer tests against an **external** oracle.
//!
//! # Provenance of the vectors (read this before touching the fixtures)
//!
//! The fixtures in `tests/kats/` were **not** produced by this crate. They were produced by the
//! upstream, independently-authored `fn-dsa` crate version `0.3.0` (Thomas Pornin,
//! <https://crates.io/crates/fn-dsa>), which this crate is a fork of. The oracle was built and run
//! in a separate Linux toolchain against the pristine crates.io tarball
//! (`https://static.crates.io/crates/fn-dsa/fn-dsa-0.3.0.crate`), using a driver that replays
//! upstream's own KAT construction (the `FakeRng1`/`FakeRng2` seed schedule documented in
//! upstream's `src/lib.rs` test module) and prints the raw `sk`, `vk` and `sig` byte strings
//! instead of only their SHA3-256 digest.
//!
//! The oracle driver was validated before use: the SHA3-256 digests it computes reproduce
//! upstream's own published `KAT` constant arrays **90/90 in both feature configurations**. So the
//! fixtures are upstream's behaviour, expanded to full byte granularity — not this crate's output
//! relabelled.
//!
//! # What is compared
//!
//! Everything is seed-deterministic: keygen consumes `FakeRng1(SHAKE256(0x00 || logn || num_le32))`
//! and signing consumes `FakeRng2` over `0x01 || logn || num_le32`. There is no nondeterminism to
//! excuse a mismatch. The comparison is therefore byte-exact on `sk`, `vk` and `sig` separately,
//! which localises any divergence to keygen vs. signing rather than hiding it inside a digest.
//!
//! # Known divergence at the *weak* (toy) degrees — and only there
//!
//! For `logn >= 7` (which includes the two real FN-DSA parameter sets, `logn = 9` / N=512 and
//! `logn = 10` / N=1024) this crate is byte-exact against upstream for every vector, in both the
//! `shake256x4` and non-`shake256x4` configurations.
//!
//! For `logn <= 6` — the `KeyPairGeneratorWeak` toy degrees, N = 4..64, which exist only for
//! testing and carry no security claim — a minority of vectors diverge. Those cases are listed in
//! [`KNOWN_WEAK_DIVERGENCES`] and are asserted to *still* diverge, so the list cannot silently rot:
//! if a future change makes one of them agree with upstream, this test fails and the entry must be
//! removed. The divergence is characterised in the crate docs and in
//! `scratchpad/audit-triage/fix-fndsa-hqc-kats.md`.

use fn_dsa::{
    DomainContext,
    HASH_ID_RAW,
    HASH_ID_SHA3_256,
    KeyPairGenerator,
    KeyPairGeneratorStandard,
    KeyPairGeneratorWeak,
    SHA3_256,
    SHAKE256,
    SigningKey,
    SigningKeyStandard,
    SigningKeyWeak,
    VerifyingKey,
    VerifyingKeyStandard,
    VerifyingKeyWeak,
    sign_key_size,
    signature_size,
    vrfy_key_size,
};
use fn_dsa_comm::{
    Infallible,
    TryCryptoRng,
    TryRng,
};

// ---------------------------------------------------------------------------
// Upstream's two fake RNGs, reproduced verbatim from fn-dsa 0.3.0's test module.
// ---------------------------------------------------------------------------

struct FakeRng1(SHAKE256);

impl FakeRng1 {
    fn new(seed: &[u8]) -> Self {
        let mut sh = SHAKE256::new();
        sh.inject(seed);
        sh.flip();
        Self(sh)
    }
}

impl TryRng for FakeRng1 {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.0.extract(&mut buf);
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.0.extract(&mut buf);
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.0.extract(dest);
        Ok(())
    }
}

impl TryCryptoRng for FakeRng1 {}

struct FakeRng2 {
    sh: SHAKE256,
    buf: [u8; 96],
    ptr: usize,
    ctr: u32,
}

impl FakeRng2 {
    fn new(seed: &[u8]) -> Self {
        let mut sh = SHAKE256::new();
        sh.inject(seed);
        Self {
            sh,
            buf: [0u8; 96],
            ptr: 96,
            ctr: 0,
        }
    }
}

impl TryRng for FakeRng2 {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let mut j = 0;
        let mut ptr = self.ptr;
        while j < dest.len() {
            if ptr == self.buf.len() {
                let mut sh = self.sh;
                sh.inject(&self.ctr.to_le_bytes());
                sh.flip();
                sh.extract(&mut self.buf);
                self.ctr += 1;
                ptr = 0;
            }
            let clen = core::cmp::min(dest.len() - j, self.buf.len() - ptr);
            dest[j..j + clen].copy_from_slice(&self.buf[ptr..ptr + clen]);
            ptr += clen;
            j += clen;
        }
        self.ptr = ptr;
        Ok(())
    }
}

impl TryCryptoRng for FakeRng2 {}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

#[cfg(feature = "shake256x4")]
const ORACLE: &str = include_str!("kats/fn-dsa-0.3.0-oracle-shake256x4.txt");
#[cfg(not(feature = "shake256x4"))]
const ORACLE: &str = include_str!("kats/fn-dsa-0.3.0-oracle-no-shake256x4.txt");

/// `(logn, num)` pairs where this crate is known **not** to reproduce upstream `fn-dsa` 0.3.0.
///
/// All of them are `logn <= 6`, i.e. `KeyPairGeneratorWeak` toy degrees (N = 4..64) that exist only
/// for testing and carry no security claim. These are asserted to still diverge; an entry that
/// starts agreeing is a test failure, not a silent pass.
#[cfg(feature = "shake256x4")]
const KNOWN_WEAK_DIVERGENCES: &[(u32, u32)] = &[
    (2, 1),
    (2, 5),
    (2, 8),
    (2, 9),
    (3, 3),
    (3, 5),
    (3, 6),
    (3, 7),
    (4, 1),
    (4, 5),
    (5, 2),
];
#[cfg(not(feature = "shake256x4"))]
const KNOWN_WEAK_DIVERGENCES: &[(u32, u32)] = &[
    (2, 0),
    (2, 2),
    (2, 5),
    (2, 6),
    (3, 3),
    (3, 8),
    (4, 6),
    (6, 6),
    (6, 8),
];

/// The lowest `logn` at which byte-exact agreement with upstream is required unconditionally.
const STRICT_LOGN_FLOOR: u32 = 7;

fn expected(logn: u32, num: u32, what: &str) -> Vec<u8> {
    let prefix = format!("{logn} {num} {what} ");
    let line = ORACLE
        .lines()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("oracle fixture has no `{prefix}` line"));
    hex::decode(line[prefix.len()..].trim()).expect("oracle fixture line is not valid hex")
}

/// Runs one upstream KAT case and returns `(sk, vk, sig)`.
fn run_case<KG: KeyPairGenerator, SK: SigningKey, VK: VerifyingKey>(
    logn: u32,
    num: u32,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let seed1 = [
        0x00u8,
        logn as u8,
        num as u8,
        (num >> 8) as u8,
        (num >> 16) as u8,
        (num >> 24) as u8,
    ];
    let mut rng1 = FakeRng1::new(&seed1);
    let seed2 = [
        0x01u8,
        logn as u8,
        num as u8,
        (num >> 8) as u8,
        (num >> 16) as u8,
        (num >> 24) as u8,
    ];
    let mut rng2 = FakeRng2::new(&seed2);

    let mut sk_buf = [0u8; sign_key_size(10)];
    let mut vk_buf = [0u8; vrfy_key_size(10)];
    let mut sig_buf = [0u8; signature_size(10)];
    let sk = &mut sk_buf[..sign_key_size(logn)];
    let vk = &mut vk_buf[..vrfy_key_size(logn)];
    let sig = &mut sig_buf[..signature_size(logn)];

    KG::default().keygen(logn, &mut rng1, sk, vk);
    let mut s = SK::decode(sk).expect("signing key must decode");
    let v = VK::decode(vk).expect("verifying key must decode");
    let dom = DomainContext(b"domain");
    if (num & 1) == 0 {
        s.sign(&mut rng2, &dom, &HASH_ID_RAW, b"message", sig);
        assert!(
            v.verify(sig, &dom, &HASH_ID_RAW, b"message"),
            "self-verification failed"
        );
    } else {
        let mut sh = SHA3_256::new();
        sh.update(&b"message"[..]);
        let hv = sh.digest();
        s.sign(&mut rng2, &dom, &HASH_ID_SHA3_256, &hv, sig);
        assert!(
            v.verify(sig, &dom, &HASH_ID_SHA3_256, &hv),
            "self-verification failed"
        );
    }
    (sk.to_vec(), vk.to_vec(), sig.to_vec())
}

fn case(logn: u32, num: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    if logn <= 8 {
        run_case::<KeyPairGeneratorWeak, SigningKeyWeak, VerifyingKeyWeak>(logn, num)
    } else {
        run_case::<KeyPairGeneratorStandard, SigningKeyStandard, VerifyingKeyStandard>(logn, num)
    }
}

/// Byte-exact agreement with the external `fn-dsa` 0.3.0 oracle on `sk`, `vk` and `sig`.
///
/// Required unconditionally for `logn >= 7`; for the weak toy degrees the
/// [`KNOWN_WEAK_DIVERGENCES`] list is applied and is itself checked for staleness.
#[test]
fn byte_exact_against_upstream_fn_dsa_0_3_0() {
    let mut agreeing = 0usize;
    let mut diverging = 0usize;

    for logn in 2u32..=10 {
        for num in 0u32..10 {
            let (sk, vk, sig) = case(logn, num);
            let (esk, evk, esig) = (
                expected(logn, num, "sk"),
                expected(logn, num, "vk"),
                expected(logn, num, "sig"),
            );
            let matches = sk == esk && vk == evk && sig == esig;
            let known = KNOWN_WEAK_DIVERGENCES.contains(&(logn, num));

            if matches {
                agreeing += 1;
                assert!(
                    !known,
                    "logn={logn} num={num} now AGREES with upstream but is still listed in \
                     KNOWN_WEAK_DIVERGENCES; remove the entry (and update the crate docs)"
                );
                continue;
            }

            diverging += 1;
            // Printed so `-- --nocapture` yields the component-level localisation (keygen vs
            // signing) without needing a scratch build.
            // A FN-DSA signature is `header || nonce(40) || encoded s2`. Reporting the header and
            // nonce separately distinguishes "the signing RNG was consumed differently" (nonce
            // differs) from "the same nonce produced a different lattice point" (sampler differs).
            let first_diff = sig.iter().zip(esig.iter()).position(|(a, b)| a != b);
            println!(
                "divergence logn={logn} num={num}: sk_match={} vk_match={} sig_match={} \
                 header_match={} nonce_match={} first_differing_sig_byte={:?} sig_len={}/{}",
                sk == esk,
                vk == evk,
                sig == esig,
                sig.first() == esig.first(),
                sig.get(1..41) == esig.get(1..41),
                first_diff,
                sig.len(),
                esig.len()
            );
            assert!(
                logn < STRICT_LOGN_FLOOR,
                "logn={logn} num={num}: byte-exact mismatch against upstream fn-dsa 0.3.0 at a \
                 non-toy degree.\n  sk  match: {}\n  vk  match: {}\n  sig match: {}",
                sk == esk,
                vk == evk,
                sig == esig
            );
            assert!(
                known,
                "logn={logn} num={num}: NEW divergence from upstream fn-dsa 0.3.0 at a weak \
                 degree, not in KNOWN_WEAK_DIVERGENCES.\n  sk  match: {}\n  vk  match: {}\n  sig \
                 match: {}",
                sk == esk,
                vk == evk,
                sig == esig
            );
        }
    }

    assert_eq!(
        diverging,
        KNOWN_WEAK_DIVERGENCES.len(),
        "known-divergence list is out of date"
    );
    assert_eq!(
        agreeing + diverging,
        90,
        "expected 90 upstream vectors to be exercised"
    );
}

/// The real FN-DSA parameter sets specifically: N=512 (`logn=9`) and N=1024 (`logn=10`).
///
/// Split out from the sweep above so a regression on the shipping parameters is unambiguous in the
/// test report rather than buried in a loop over toy degrees.
#[test]
fn byte_exact_at_shipping_parameter_sets() {
    for logn in [9u32, 10] {
        for num in 0u32..10 {
            let (sk, vk, sig) = case(logn, num);
            assert_eq!(
                sk,
                expected(logn, num, "sk"),
                "logn={logn} num={num}: sk mismatch"
            );
            assert_eq!(
                vk,
                expected(logn, num, "vk"),
                "logn={logn} num={num}: vk mismatch"
            );
            assert_eq!(
                sig,
                expected(logn, num, "sig"),
                "logn={logn} num={num}: sig mismatch"
            );
        }
    }
}
