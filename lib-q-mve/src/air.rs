//! mVE key-consistency AIR (RED — mve-rekey-v0 freeze-gate).
//!
//! Proves, in zero knowledge of `(K, {ss_i})`, that a **single** key `K` is wrapped to every
//! recipient:
//!
//! ```text
//! ∃ (K, {ss_i}):  ∀ i:  w_i = K + H_zk(ss_i)
//! and  acc = HashChain(w_0, w_1, …, w_{H-1})   (public, recomputable from the wire)
//! ```
//!
//! `H_zk` is the truncated Poseidon-256 wide sponge (`hash_suite_id = 5`), shared with the
//! membership AIR. One trace row per recipient; recipient count is padded to a power-of-two trace
//! height by **repeating the last recipient** (so every padding row is a valid copy and the
//! verifier can recompute `acc` knowing only the wire wraps + the repeat-last rule).
//!
//! A "split" — different `K` to different recipients — cannot satisfy the cross-row constant-`K`
//! constraint, so no verifying proof exists for it. The `acc` hash-chain binds the committed `w_i`
//! columns to a single public digest the relay recomputes from the envelope wraps.
//!
//! RED: shares the unverified-over-GF(p²) Poseidon-256 round counts; binding `ss_i` to its KEM
//! ciphertext is NOT in-circuit (see crate docs / freeze-gate doc M1). NOT proven sound / ZK yet.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_poseidon::PoseidonField;
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::air::{
    WIDE_DIGEST_ELEMS,
    WideDigest,
    constrain_wide_sponge,
    generate_wide_sponge_cells,
    next_power_of_two,
    poseidon_to_field,
    poseidon256_wide_hash,
    wide_sponge_interm_cols,
};

use crate::{
    KEY_ELEMS,
    Key,
    SS_ELEMS,
    Wrap,
    ss_to_felts,
};

/// Minimum trace height (power of two) — clears the FRI blowup / ZK minimum.
pub const MVE_MIN_ROWS: usize = 8;

/// The `acc` hash-chain absorbs `running ‖ w` = 10 elements per row.
const ACC_INPUT_LEN: usize = WIDE_DIGEST_ELEMS + KEY_ELEMS; // 10

// --- Column layout (one row per recipient). ---
const K_START: usize = 0;
const W_START: usize = K_START + KEY_ELEMS; // 5
const RUN_START: usize = W_START + KEY_ELEMS; // 10
const ACC_INTERM_START: usize = RUN_START + WIDE_DIGEST_ELEMS; // 15
const SS_START: usize = ACC_INTERM_START + wide_sponge_interm_cols(ACC_INPUT_LEN);
const SS_INTERM_START: usize = SS_START + SS_ELEMS;
/// Total trace width.
pub const MVE_ROW_WIDTH: usize = SS_INTERM_START + wide_sponge_interm_cols(SS_ELEMS);

/// Public values = `[ acc(5) ]` (the hash-chain digest over all wraps).
pub const MVE_NUM_PUBLIC: usize = WIDE_DIGEST_ELEMS;

/// AIR for the mVE key-consistency statement. Recipient count = trace height.
#[derive(Debug, Clone, Default)]
pub struct MveConsistencyAir;

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for MveConsistencyAir {
    fn width(&self) -> usize {
        MVE_ROW_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for MveConsistencyAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        let one = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE);

        // --- Read current-row columns. ---
        let (k_cols, w_cols, run_cols, ss_cols) = {
            let main = builder.main();
            let local = main.current_slice();
            let k_cols: Vec<AB::Expr> = (0..KEY_ELEMS).map(|i| local[K_START + i].into()).collect();
            let w_cols: Vec<AB::Expr> = (0..KEY_ELEMS).map(|i| local[W_START + i].into()).collect();
            let run_cols: Vec<AB::Expr> = (0..WIDE_DIGEST_ELEMS)
                .map(|i| local[RUN_START + i].into())
                .collect();
            let ss_cols: Vec<AB::Expr> =
                (0..SS_ELEMS).map(|i| local[SS_START + i].into()).collect();
            (k_cols, w_cols, run_cols, ss_cols)
        };
        let pub_acc: Vec<AB::Expr> = {
            let pubs = builder.public_values();
            (0..WIDE_DIGEST_ELEMS).map(|i| pubs[i].into()).collect()
        };

        // === mask = H_zk(ss) (ungated every row, degree 5) ===
        let mask = match constrain_wide_sponge(builder, &ss_cols, SS_INTERM_START) {
            Ok(d) => d,
            Err(_) => {
                builder.assert_zero(one.clone());
                return;
            }
        };

        // === w == K + mask (every row, degree 1) ===
        for j in 0..KEY_ELEMS {
            builder.assert_eq(w_cols[j].clone(), k_cols[j].clone() + mask[j].clone());
        }

        // === acc hash-chain: parent = H(running ‖ w) (ungated every row) ===
        let mut acc_input: Vec<AB::Expr> = Vec::with_capacity(ACC_INPUT_LEN);
        acc_input.extend(run_cols.iter().cloned());
        acc_input.extend(w_cols.iter().cloned());
        let parent = match constrain_wide_sponge(builder, &acc_input, ACC_INTERM_START) {
            Ok(p) => p,
            Err(_) => {
                builder.assert_zero(one.clone());
                return;
            }
        };

        // First row: running = 0 (IV).
        {
            let mut b = builder.when_first_row();
            for i in 0..WIDE_DIGEST_ELEMS {
                b.assert_eq(run_cols[i].clone(), AB::Expr::ZERO);
            }
        }

        // Transition: thread the running acc, and hold K constant.
        {
            let (next_run, next_k): (Vec<AB::Expr>, Vec<AB::Expr>) = {
                let main = builder.main();
                let next = main.next_slice();
                let nr = (0..WIDE_DIGEST_ELEMS)
                    .map(|i| next[RUN_START + i].into())
                    .collect();
                let nk = (0..KEY_ELEMS).map(|i| next[K_START + i].into()).collect();
                (nr, nk)
            };
            let mut b = builder.when_transition();
            for i in 0..WIDE_DIGEST_ELEMS {
                b.assert_eq(next_run[i].clone(), parent[i].clone());
            }
            for j in 0..KEY_ELEMS {
                b.assert_eq(next_k[j].clone(), k_cols[j].clone());
            }
        }

        // Last row: the final hash-chain digest is the public acc.
        {
            let mut b = builder.when_last_row();
            for i in 0..WIDE_DIGEST_ELEMS {
                b.assert_eq(parent[i].clone(), pub_acc[i].clone());
            }
        }
    }
}

/// Fold the wrap hash-chain `acc = H(…H(H(0 ‖ w_0) ‖ w_1)… ‖ w_{H-1})` (value-level reference).
/// `wraps` must be the **padded** sequence (real wraps then repeat-last padding), length = height.
pub fn fold_acc(wraps: &[Wrap]) -> WideDigest {
    let mut running: WideDigest = [PoseidonField::ZERO; WIDE_DIGEST_ELEMS];
    for w in wraps {
        let mut input = [PoseidonField::ZERO; ACC_INPUT_LEN];
        input[..WIDE_DIGEST_ELEMS].copy_from_slice(&running);
        input[WIDE_DIGEST_ELEMS..].copy_from_slice(w);
        running = poseidon256_wide_hash(&input);
    }
    running
}

/// Pad a recipient count to the trace height (power of two, ≥ [`MVE_MIN_ROWS`]).
pub fn padded_height(n: usize) -> usize {
    core::cmp::max(next_power_of_two(n), MVE_MIN_ROWS)
}

/// Generate the mVE consistency trace. `shared_secrets[i]` is recipient `i`'s ML-KEM shared secret
/// bytes; the wraps are `w_i = K + H_zk(ss_i)`. The recipient set is padded to [`padded_height`]
/// by repeating the last recipient.
pub fn generate_mve_trace<F: Field + BasedVectorSpace<Mersenne31>>(
    key: &Key,
    shared_secrets: &[Vec<u8>],
) -> RowMajorMatrix<F> {
    assert!(!shared_secrets.is_empty(), "need ≥1 recipient");
    let n = shared_secrets.len();
    let height = padded_height(n);

    let mut cells: Vec<PoseidonField> = Vec::with_capacity(height * MVE_ROW_WIDTH);
    let mut running: WideDigest = [PoseidonField::ZERO; WIDE_DIGEST_ELEMS];

    for row in 0..height {
        // Repeat the last real recipient for padding rows.
        let ss = &shared_secrets[core::cmp::min(row, n - 1)];
        let ss_felts = ss_to_felts(ss);
        let mask = crate::mask_from_shared_secret(ss);
        let w: Wrap = core::array::from_fn(|j| key[j] + mask[j]);

        // Column order MUST match the AIR reads / interm starts.
        cells.extend_from_slice(key); // K (5)
        cells.extend_from_slice(&w); // w (5)
        cells.extend_from_slice(&running); // running (5)
        let mut acc_input = [PoseidonField::ZERO; ACC_INPUT_LEN];
        acc_input[..WIDE_DIGEST_ELEMS].copy_from_slice(&running);
        acc_input[WIDE_DIGEST_ELEMS..].copy_from_slice(&w);
        let (acc_cells, parent) = generate_wide_sponge_cells(&acc_input);
        cells.extend_from_slice(&acc_cells); // acc node interm
        cells.extend_from_slice(&ss_felts); // ss (SS_ELEMS)
        let (ss_cells, _mask_digest) = generate_wide_sponge_cells(&ss_felts);
        cells.extend_from_slice(&ss_cells); // ss interm

        running = parent;
    }

    debug_assert_eq!(cells.len(), height * MVE_ROW_WIDTH);
    let values: Vec<F> = cells.iter().map(poseidon_to_field).collect();
    RowMajorMatrix::new(values, MVE_ROW_WIDTH)
}

/// Public values `[ acc(5) ]` for the mVE AIR, from the padded wrap sequence.
pub fn mve_public_values<F: Field + BasedVectorSpace<Mersenne31>>(padded_wraps: &[Wrap]) -> Vec<F> {
    let acc = fold_acc(padded_wraps);
    acc.iter().map(poseidon_to_field::<F>).collect()
}

#[cfg(test)]
mod tests {
    use lib_q_stark::check_constraints;
    use lib_q_stark_field::extension::Complex;

    use super::*;

    type TestField = Complex<Mersenne31>;

    fn fe(x: u32) -> PoseidonField {
        Complex::<Mersenne31>::from(Mersenne31::new(x))
    }
    fn key(seed: u32) -> Key {
        core::array::from_fn(|i| fe(seed.wrapping_mul(7) + i as u32 + 1))
    }

    /// Build the padded wrap sequence the verifier reconstructs from the wire (repeat last).
    fn padded_wraps(k: &Key, secrets: &[Vec<u8>]) -> Vec<Wrap> {
        let n = secrets.len();
        let h = padded_height(n);
        (0..h)
            .map(|row| {
                let ss = &secrets[core::cmp::min(row, n - 1)];
                let mask = crate::mask_from_shared_secret(ss);
                core::array::from_fn(|j| k[j] + mask[j])
            })
            .collect()
    }

    #[test]
    fn consistent_key_satisfies_constraints() {
        let k = key(42);
        let secrets: Vec<Vec<u8>> = (0..3u8).map(|i| alloc::vec![i + 1; 32]).collect();
        let trace = generate_mve_trace::<TestField>(&k, &secrets);
        let pubs = mve_public_values::<TestField>(&padded_wraps(&k, &secrets));
        check_constraints(&MveConsistencyAir, &trace, &pubs);
    }

    /// A divergent (split) envelope: recipient 1's wrap is built from a DIFFERENT key. The trace's
    /// constant-K constraint cannot hold ⇒ constraints must FAIL.
    #[test]
    #[should_panic(expected = "values didn't match on row")]
    fn divergent_key_fails_constraints() {
        let k = key(1);
        let k2 = key(999);
        let secrets: Vec<Vec<u8>> = (0..2u8).map(|i| alloc::vec![i + 1; 32]).collect();
        // Honest trace for k, then overwrite recipient-1's wrap to wrap k2 instead (a split).
        let mut trace = generate_mve_trace::<TestField>(&k, &secrets);
        let mask1 = crate::mask_from_shared_secret(&secrets[1]);
        for j in 0..KEY_ELEMS {
            let w = k2[j] + mask1[j];
            trace.values[1 * MVE_ROW_WIDTH + W_START + j] = poseidon_to_field::<TestField>(&w);
        }
        // Public acc still folds the (tampered) wrap sequence as the relay would see it.
        let wraps: Vec<Wrap> = (0..padded_height(2))
            .map(|row| {
                let r = core::cmp::min(row, 1);
                let mask = crate::mask_from_shared_secret(&secrets[r]);
                let kk = if r == 1 { k2 } else { k };
                core::array::from_fn(|j| kk[j] + mask[j])
            })
            .collect();
        let pubs = mve_public_values::<TestField>(&wraps);
        check_constraints(&MveConsistencyAir, &trace, &pubs); // must panic: w_1 != K + mask_1
    }
}
