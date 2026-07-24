//! Unlinkable lattice blind token via GPV signatures + a re-randomizable ZK proof of possession.
//!
//! Construction (keyed-verification anonymous-credential style; Agrawal–Kirshanova–Stehlé–Yadav
//! CCS'22 family). The issuer holds an MP gadget trapdoor for `A`. A credential on a *hidden*
//! attribute `a_tok` is a short GPV preimage `x` with `A·x = d·a_tok + d0` for public `(d, d0)` —
//! the binding is a public **linear** map (no hash), so possession is provable with a lattice
//! sigma-protocol. Redemption is a Fiat–Shamir-with-aborts proof of knowledge of short
//! `(x, a_tok)` satisfying `[A | −d]·(x ‖ a_tok) = d0`, made with **fresh** randomness each time:
//!
//! * **Unlinkability (issuance ↔ redemption):** the proof is honest-verifier zero-knowledge, so it
//!   reveals nothing about `(a_tok, x)`. An issuer that recorded every issued `(a_tok_i, x_i)` and
//!   colludes with the verifier cannot match a redemption to an issuance better than guessing in the
//!   `(issuer_key_id, epoch)` anonymity set. Freshness ⇒ even repeated redemptions are unlinkable.
//! * **One-more unforgeability:** producing a fresh accepting proof requires a short `(x, a_tok)`
//!   with `A·x = d·a_tok + d0`; without the trapdoor this is ISIS on `A` (→ one-more-ISIS), so a
//!   user cannot redeem more tokens than were issued.
//!
//! **Concrete security (this instance).** The self-contained ring (`N = 1024`, `q ≈ 2^51`, see
//! [`super::ring`]) is sized against a BKZ core-SVP cost model so that, together: the challenge
//! weight `τ = 16` gives ≈128-bit knowledge soundness, the masked response `z` still fits below
//! `q/2`, and Module-SIS on `A` (binding / one-more-unforgeability) is ≈143-bit classical
//! (≈130-bit quantum, BKZ-491). The trapdoor is hidden statistically (`m̄ = 18`), so no Module-LWE
//! assumption is needed. See `LIBQ_API.md` §3/§7 for the full derivation and caveats.

use alloc::vec::Vec;

use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
};
use subtle::ConstantTimeEq;

use super::gadget::GADGET_GAUSSIAN_WIDTH;
use super::ring::{
    N,
    Rq,
    centered_coeffs,
    const_poly,
    ring_add,
    ring_mul,
    ring_sub,
    sample_gaussian_poly,
    sample_in_ball,
    sample_uniform_poly,
};
use super::trapdoor::{
    PREIMAGE_LEN,
    PublicMatrix,
    Trapdoor,
    trapdoor_gen,
};

/// Trapdoor Gaussian width.
pub const S_R: f64 = 4.0;
/// GPV signing (preimage) width — above the worst-slot perturbation PSD floor
/// (`≈ s_g·σ_1(R)_max ≈ 4.6e3` over the `N` canonical slots) with margin so keygen rarely
/// resamples `R`.
pub const S_SIGN: f64 = 5248.0;
/// Credential attribute width (short, hidden).
pub const S_A: f64 = 20.0;
/// Sparse challenge Hamming weight: `|C| = 2^τ·C(N,τ) ≈ 2^131.6` ⇒ ≈128-bit knowledge soundness.
pub const TAU: usize = 16;
/// Proof masking width (Lyubashevsky rejection; `≈ 11·‖c·w‖₂`).
pub const S_Y: f64 = 24_000_000.0;
/// Verifier infinity-norm bound on the response `z` (≈12·σ_z ≈ 1.15e8, far below `q/2 ≈ 1.4e14`).
pub const BETA_Z: i64 = 121_000_000;
/// Rejection-sampling tail factor (standard deviations covered).
pub const REJECT_KAPPA: f64 = 12.0;
/// Max FS-with-aborts attempts before giving up a redemption proof.
pub const MAX_ATTEMPTS: usize = 600;

/// Length of the proof witness / matrix `M = [A | −d]`: `PREIMAGE_LEN + 1`.
pub const WITNESS_LEN: usize = PREIMAGE_LEN + 1;

/// Issuer public key.
#[derive(Clone)]
pub struct IssuerPublic {
    /// GPV matrix `A` (row of `PREIMAGE_LEN` ring elements).
    pub a: PublicMatrix,
    /// Public attribute coefficient `d`.
    pub d: Rq,
    /// Public offset `d0`.
    pub d0: Rq,
    /// Parameterization label.
    pub issuer_key_id: u32,
    /// Epoch (anonymity-set label component).
    pub epoch: u32,
}

/// Issuer secret (trapdoor + public).
pub struct IssuerSecret {
    /// Public key.
    pub public: IssuerPublic,
    trapdoor: Trapdoor,
}

/// Issuance request (clear attribute; issuance is not blind — unlinkability comes from redemption).
#[derive(Clone)]
pub struct IssueRequest {
    /// Attribute the issuer signs.
    pub a_tok: Rq,
}

/// User state kept between request and unblind.
#[derive(Clone)]
pub struct IssueState {
    a_tok: Rq,
}

/// Issuer response: the GPV preimage signature.
#[derive(Clone)]
pub struct IssueResponse {
    /// Short `x` with `A·x = d·a_tok + d0`.
    pub x: Vec<Rq>,
}

/// A secret credential `(a_tok, x)`.
#[derive(Clone)]
pub struct Credential {
    a_tok: Rq,
    x: Vec<Rq>,
}

/// Redeemable token = a fresh ZK proof of possession (re-randomizable ⇒ unlinkable).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenProof {
    /// First message `W = M·y`.
    pub w_commit: Rq,
    /// Response `z = y + c·(x ‖ a_tok)`, `WITNESS_LEN` ring elements.
    pub z: Vec<Rq>,
}

/// Generate an issuer key for `(issuer_key_id, epoch)`.
pub fn keygen_issuer<R: CryptoRng + Rng>(
    rng: &mut R,
    issuer_key_id: u32,
    epoch: u32,
) -> (IssuerPublic, IssuerSecret) {
    let (a, trapdoor) = trapdoor_gen(rng, S_R, S_SIGN, GADGET_GAUSSIAN_WIDTH);
    let d = sample_uniform_poly(rng);
    let d0 = sample_uniform_poly(rng);
    let public = IssuerPublic {
        a,
        d,
        d0,
        issuer_key_id,
        epoch,
    };
    let secret = IssuerSecret {
        public: public.clone(),
        trapdoor,
    };
    (public, secret)
}

/// User: prepare an issuance request (sample a fresh hidden attribute).
pub fn blind<R: CryptoRng + Rng>(
    rng: &mut R,
    _public: &IssuerPublic,
) -> (IssueRequest, IssueState) {
    let mut br = super::rngbuf::BufRng::new(rng);
    let a_tok = sample_gaussian_poly(&mut br, S_A);
    (
        IssueRequest {
            a_tok: a_tok.clone(),
        },
        IssueState { a_tok },
    )
}

/// Issuer: sign `u = d·a_tok + d0` with a GPV preimage.
pub fn blind_sign<R: CryptoRng + Rng>(
    rng: &mut R,
    secret: &IssuerSecret,
    req: &IssueRequest,
) -> IssueResponse {
    let u = ring_add(&ring_mul(&secret.public.d, &req.a_tok), &secret.public.d0);
    let x = secret.trapdoor.sample_preimage(rng, &secret.public.a, &u);
    IssueResponse { x }
}

/// User: finalize a credential (checks the signature is valid).
#[must_use]
pub fn unblind(
    public: &IssuerPublic,
    state: &IssueState,
    resp: &IssueResponse,
) -> Option<Credential> {
    let u = ring_add(&ring_mul(&public.d, &state.a_tok), &public.d0);
    let ax = public.a.apply(&resp.x);
    // Constant-time equality: `u` is derived from the *secret* hidden attribute `a_tok`, so a
    // short-circuiting `!=` would leak (via timing) the first coefficient where the issuer's
    // signature check fails. Compare the whole centered-coefficient vectors in constant time.
    if centered_coeffs(&ax)[..]
        .ct_eq(&centered_coeffs(&u)[..])
        .unwrap_u8() ==
        0
    {
        return None;
    }
    Some(Credential {
        a_tok: state.a_tok.clone(),
        x: resp.x.clone(),
    })
}

/// Build `M = [A | −d]` (the proof matrix, `WITNESS_LEN` ring elements).
fn proof_matrix(public: &IssuerPublic) -> Vec<Rq> {
    let mut m = public.a.cols.clone();
    m.push(ring_sub(&const_poly(0), &public.d)); // −d
    m
}

/// `M · vec` (single ring element).
fn matrix_apply(m: &[Rq], vec: &[Rq]) -> Rq {
    let mut acc = Rq::zero();
    for (mi, vi) in m.iter().zip(vec.iter()) {
        acc = ring_add(&acc, &ring_mul(mi, vi));
    }
    acc
}

/// Fiat–Shamir sparse challenge bound to the issuer key, nonce, and first message.
fn fs_challenge(public: &IssuerPublic, nonce: &[u8], w_commit: &Rq) -> Rq {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(b"lib-q-blind-token/redeem/v1");
    h.update(&public.issuer_key_id.to_le_bytes());
    h.update(&public.epoch.to_le_bytes());
    for col in &public.a.cols {
        absorb_poly(&mut h, col);
    }
    absorb_poly(&mut h, &public.d);
    absorb_poly(&mut h, &public.d0);
    h.update(&(nonce.len() as u64).to_le_bytes());
    h.update(nonce);
    absorb_poly(&mut h, w_commit);
    let mut seed = [0u8; 32];
    let mut r = h.finalize_xof();
    XofReader::read(&mut r, &mut seed);
    sample_in_ball(&seed, TAU)
}

fn absorb_poly(h: &mut lib_q_sha3::Shake256, p: &Rq) {
    for c in centered_coeffs(p) {
        h.update(&c.to_le_bytes());
    }
}

/// Centered integer inner product `⟨a, b⟩` over all ring elements / coefficients.
fn inner(a: &[Rq], b: &[Rq]) -> i128 {
    let mut acc = 0i128;
    for (ai, bi) in a.iter().zip(b.iter()) {
        let ca = centered_coeffs(ai);
        let cb = centered_coeffs(bi);
        for t in 0..N {
            acc += ca[t] as i128 * cb[t] as i128;
        }
    }
    acc
}

fn l2_sq(v: &[Rq]) -> f64 {
    let mut acc = 0.0;
    for vi in v {
        for c in centered_coeffs(vi) {
            acc += (c as f64) * (c as f64);
        }
    }
    acc
}

/// Uniform `f64` in `[0,1)`.
fn uniform_unit<R: Rng>(rng: &mut R) -> f64 {
    let mut b = [0u8; 8];
    rng.fill_bytes(&mut b);
    ((u64::from_le_bytes(b) >> 11) as f64) * (1.0 / ((1u64 << 53) as f64))
}

/// Redeem: produce a fresh ZK proof of possession bound to `nonce`. Returns `None` if rejection
/// sampling exhausts `MAX_ATTEMPTS` (vanishingly unlikely).
pub fn redeem<R: CryptoRng + Rng>(
    rng: &mut R,
    public: &IssuerPublic,
    cred: &Credential,
    nonce: &[u8],
) -> Option<TokenProof> {
    // Buffer the RNG: each FS-with-aborts attempt samples WITNESS_LEN·N masking coordinates.
    let mut br = super::rngbuf::BufRng::new(rng);
    let rng = &mut br;
    let m = proof_matrix(public);
    // Witness w = (x ‖ a_tok).
    let mut w = cred.x.clone();
    w.push(cred.a_tok.clone());

    let s2 = S_Y * S_Y;
    for _ in 0..MAX_ATTEMPTS {
        let y: Vec<Rq> = (0..WITNESS_LEN)
            .map(|_| sample_gaussian_poly(rng, S_Y))
            .collect();
        let w_commit = matrix_apply(&m, &y);
        let c = fs_challenge(public, nonce, &w_commit);

        // v = c·w ; z = y + v.
        let v: Vec<Rq> = w.iter().map(|wi| ring_mul(&c, wi)).collect();
        let z: Vec<Rq> = y
            .iter()
            .zip(v.iter())
            .map(|(yi, vi)| ring_add(yi, vi))
            .collect();

        // Reject so accepted z ~ D_{S_Y, 0} independent of w (Lyubashevsky).
        let norm_v_sq = l2_sq(&v);
        let norm_v = norm_v_sq.sqrt();
        let zv = inner(&z, &v) as f64;
        // log ratio = −π(2⟨z,v⟩ − ‖v‖²)/s² ; logM covers the κ-σ tail of ⟨y,v⟩.
        let log_ratio = -core::f64::consts::PI * (2.0 * zv - norm_v_sq) / s2;
        let log_m = REJECT_KAPPA * norm_v * (2.0 * core::f64::consts::PI).sqrt() / S_Y;
        let accept = (log_ratio - log_m).exp().min(1.0);
        if uniform_unit(rng) < accept {
            // Shortness must hold for a usable proof.
            if z.iter()
                .all(|zi| centered_coeffs(zi).into_iter().all(|c| c.abs() <= BETA_Z))
            {
                return Some(TokenProof { w_commit, z });
            }
        }
    }
    None
}

/// Verify a redemption proof against the issuer key and nonce.
#[must_use]
pub fn verify(public: &IssuerPublic, nonce: &[u8], proof: &TokenProof) -> bool {
    if proof.z.len() != WITNESS_LEN {
        return false;
    }
    // Shortness.
    if !proof
        .z
        .iter()
        .all(|zi| centered_coeffs(zi).into_iter().all(|c| c.abs() <= BETA_Z))
    {
        return false;
    }
    let m = proof_matrix(public);
    let c = fs_challenge(public, nonce, &proof.w_commit);
    // M·z == W + c·d0.
    let lhs = matrix_apply(&m, &proof.z);
    let rhs = ring_add(&proof.w_commit, &ring_mul(&c, &public.d0));
    centered_coeffs(&lhs) == centered_coeffs(&rhs)
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;

    use super::*;

    fn issue<R: CryptoRng + Rng>(
        rng: &mut R,
        pubk: &IssuerPublic,
        sk: &IssuerSecret,
    ) -> Credential {
        let (req, st) = blind(rng, pubk);
        let resp = blind_sign(rng, sk, &req);
        unblind(pubk, &st, &resp).expect("valid signature")
    }

    #[test]
    fn honest_redeem_verifies_and_is_fresh() {
        let mut rng = new_deterministic_rng([0xA1u8; 32]);
        let (pubk, sk) = keygen_issuer(&mut rng, 7, 3);
        let cred = issue(&mut rng, &pubk, &sk);
        let nonce = b"context-42";
        let p1 = redeem(&mut rng, &pubk, &cred, nonce).expect("redeem 1");
        let p2 = redeem(&mut rng, &pubk, &cred, nonce).expect("redeem 2");
        assert!(verify(&pubk, nonce, &p1));
        assert!(verify(&pubk, nonce, &p2));
        // Re-randomized: two redemptions of the same credential differ.
        assert_ne!(p1, p2, "redemptions must be fresh");
    }

    #[test]
    fn wrong_nonce_and_tamper_fail() {
        let mut rng = new_deterministic_rng([0xB2u8; 32]);
        let (pubk, sk) = keygen_issuer(&mut rng, 1, 1);
        let cred = issue(&mut rng, &pubk, &sk);
        let proof = redeem(&mut rng, &pubk, &cred, b"good").expect("redeem");
        assert!(verify(&pubk, b"good", &proof));
        assert!(!verify(&pubk, b"bad", &proof), "wrong nonce must fail");
        let mut tampered = proof.clone();
        tampered.z[0].coeffs[0] ^= 1;
        assert!(
            !verify(&pubk, b"good", &tampered),
            "tampered proof must fail"
        );
    }

    /// Unlinkability experiment: the issuer records every issued credential `(a_tok_i, x_i)`, then
    /// observes redemptions and, colluding with the verifier, tries to match each redemption to its
    /// issuance via the best residual attack `argmin_i ‖z − c·(x_i ‖ a_tok_i)‖`. Under the ZK proof
    /// the success rate must be ≈ `1/N` (chance), not ≈ 1 (which a linkable scheme would yield).
    #[test]
    #[ignore = "statistical (40 redemptions); run with: cargo test --release -- --ignored"]
    fn unlinkability_experiment() {
        let mut rng = new_deterministic_rng([0xD4u8; 32]);
        let (pubk, sk) = keygen_issuer(&mut rng, 9, 5);

        // Issue N credentials; the adversary keeps the witnesses w_i = (x_i ‖ a_tok_i).
        let n = 8usize;
        let mut creds = Vec::new();
        let mut witnesses: Vec<Vec<Rq>> = Vec::new();
        for _ in 0..n {
            let cred = issue(&mut rng, &pubk, &sk);
            let mut w = cred.x.clone();
            w.push(cred.a_tok.clone());
            witnesses.push(w);
            creds.push(cred);
        }

        let nonce = b"redeem-ctx";
        let trials = 32usize;
        let mut correct = 0usize;
        // Deterministic-but-varying target selection.
        for trial in 0..trials {
            let target = (trial.wrapping_mul(5).wrapping_add(3)) % n;
            let proof = redeem(&mut rng, &pubk, &creds[target], nonce).expect("redeem");
            assert!(verify(&pubk, nonce, &proof), "redemption must verify");
            // Adversary: same challenge for all candidates (fixed proof).
            let c = fs_challenge(&pubk, nonce, &proof.w_commit);
            let mut best = 0usize;
            let mut best_norm = f64::INFINITY;
            for (i, w) in witnesses.iter().enumerate() {
                // residual_i = z − c·w_i.
                let resid: Vec<Rq> = proof
                    .z
                    .iter()
                    .zip(w.iter())
                    .map(|(zi, wi)| ring_sub(zi, &ring_mul(&c, wi)))
                    .collect();
                let nrm = l2_sq(&resid);
                if nrm < best_norm {
                    best_norm = nrm;
                    best = i;
                }
            }
            if best == target {
                correct += 1;
            }
        }
        let rate = correct as f64 / trials as f64;
        // Chance is 1/n = 0.125. A linkable scheme scores ≈ 1.0. Require clearly-near-chance.
        assert!(
            rate < 0.45,
            "linking success rate {rate} too high (chance = {:.3}); blindness broken",
            1.0 / n as f64,
        );
    }

    #[test]
    fn forged_proof_without_credential_fails() {
        let mut rng = new_deterministic_rng([0xC3u8; 32]);
        let (pubk, _sk) = keygen_issuer(&mut rng, 2, 2);
        // A random "proof" must not verify.
        let z: Vec<Rq> = (0..WITNESS_LEN)
            .map(|_| sample_gaussian_poly(&mut rng, S_Y))
            .collect();
        let w_commit = sample_uniform_poly(&mut rng);
        let bogus = TokenProof { w_commit, z };
        assert!(!verify(&pubk, b"ctx", &bogus));
    }
}
