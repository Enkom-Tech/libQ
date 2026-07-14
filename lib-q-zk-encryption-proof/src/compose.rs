//! Batch-STARK composition (design §6): the heterogeneous-AIR enum wrapper and the
//! `prove_batch`/`verify_batch` driver that *cryptographically* enforces the LogUp joins between
//! the sponge, the squeeze-byte table, and the samplers.
//!
//! ## Why an enum
//! [`lib_q_plonky_batch_stark::prove_batch`] is generic over a **single** AIR type `A`
//! (`instances: &[StarkInstance<'_, SC, A>]`); every instance in one batch must be the same Rust
//! type. The encryption proof composes structurally different AIRs (a ~2600-column Keccak sponge, a
//! 21-column byte table, a 14-/323-column sampler, …), so they are unified under one
//! [`EncProofAir`] enum whose [`BaseAir`]/[`Air`] impls dispatch to the active variant. Each
//! `StarkInstance` pairs one enum value with its own trace and public values, so per-instance widths
//! and public-value counts line up.
//!
//! ## Which STARK stack
//! The per-AIR unit tests use the `lib-q-stark` single-AIR path (`lib_q_zkp::stark::StarkProver`).
//! Composition needs LogUp cross-table lookups, which live in the **`lib-q-plonky-*` stack**
//! (`lib_q_plonky_uni_stark` config + `lib_q_plonky_batch_stark` driver + `lib_q_plonky_lookup`).
//! Both stacks build on the shared [`lib_q_stark_air`] `Air`/`AirBuilder` traits, so the AIRs (all
//! generic over `AB: AirBuilder`) are usable by either; only the *config type* differs. The batch
//! config is assembled in tests here from `lib_q_zkp::stark`'s PCS type aliases + the shared
//! `ComplexFieldChallenger` (the config the crate's production `prove`/`verify` entry points will
//! later use, at production FRI params rather than the test ones).
//!
//! ## Status (RED)
//! Validated end-to-end through `prove_batch`/`verify_batch` (cryptographic enforcement via the batch
//! verifier's `verify_global_final_value`, not merely the debug `check_lookups`):
//!   * the composition primitives — a `Kind::Global` cross-table lookup between two heterogeneous AIR
//!     instances, and a **preprocessed** column feeding a lookup (via [`build_preprocessed`]);
//!   * the **byte-provenance chain** (join 1) — sponge (68 limb-Sends + preprocessed position column) ⇒
//!     squeeze-byte table (limb-Receive + consumed-prefix byte-Send) ⇒ sampler (byte-Receive), verifying
//!     iff the sampler consumed the genuine SHAKE output; a sponge proving a *different* μ is rejected;
//!   * the bounded sampler's 8 byte-Receives (join 1) — eight single-tuple lookups (degree 3), not one
//!     8-tuple (degree ~9, which overflowed the FRI quotient domain — caught + fixed here);
//!   * **join 2** (sampler coeff-Send ⇒ fold coeff-Receive) and **join 3** (fold `E`-Send ⇒ relation
//!     `w`-Receive), each cryptographically enforced;
//!   * the **full vertical slice** — sponge ⇒ squeeze ⇒ ternary sampler ⇒ Horner fold ⇒ relation check,
//!     FIVE instances across FOUR buses in one proof, verifying iff every bus balances. The mid-chain
//!     instances carry two lookup groups (e.g. the fold's coeff-Receive on aux cols 0..4 + its `E`-Send
//!     on cols 4..8) without collision, via each join constructor's `col_base`.
//!
//! Building [`prove_batch`]-with-lookups surfaced (and this crate fixed) a real degree-under-count bug
//! in `lib-q-plonky-lookup` (the path had no end-to-end test repo-wide).
//!
//! **Status of #26 (updated 2026-07-14):** the `e`-provenance ⇒ R3b composition has been **lifted out
//! of these tests into real library API** — [`crate::encryption_proof::assemble_e_provenance_prover`] /
//! `..._verifier` build exactly this batch over a REAL ciphertext at N=1024, verified at **production
//! FRI params** (`encryption_proof::tests`), with the verifier rebuilding every AIR + the pk-binding
//! public values from `(t0, ct)` — never prover claims — and wired into the tkem partial-decap gate
//! (#33). **Remaining:** bind `f` (R3a bounded errors, the classic `f = δ·unitₖ` spike) and `g` via a
//! bounded sampler at the XOF byte-offset after `e`; multi-challenge amplification; and hiding-FRI ZK
//! (blind μ, #32). The `#[cfg(test)]` assemblies below remain as the mechanism's provenance/regression
//! suite (join-1/2/3 isolation, fan-out, the `f`/`g` bounded-sampler slices the extension will reuse).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_zkp::stark::ConfigVal;

use crate::logup_join::XofStreamTableAir;
use crate::sampler::{
    BoundedSamplerAir,
    TernarySamplerAir,
};
use crate::sponge_air::ShakeSpongeAir;
use crate::squeeze_byte::SqueezeByteAir;
use crate::zq::{
    EncodeMuFoldAir,
    HornerFoldAir,
    RelationCheckAir,
};

/// One-type-fits-all wrapper over the encryption-proof AIRs so a single `prove_batch` call can
/// carry the heterogeneous tables. Each variant holds the concrete AIR; `BaseAir`/`Air` dispatch to
/// it. `Clone` is required by `prove_batch`'s `A: … + Clone` bound.
///
/// `XofStream` is the interim byte-stream *source* stand-in (design §5.1); it is replaced by the
/// sponge's own limb-Send once byte provenance is closed. The other variants are the real tables.
#[derive(Clone)]
pub enum EncProofAir {
    /// SHAKE-256 sponge boundary AIR (design §3.2).
    Sponge(ShakeSpongeAir),
    /// Squeeze limb→byte decomposition table (design §5.1c, the sponge Send side of join 1).
    SqueezeByte(SqueezeByteAir),
    /// Ternary rejection sampler for `e` (design §5).
    Ternary(TernarySamplerAir),
    /// Bounded rejection sampler for `f`/`g` (design §5.2).
    Bounded(BoundedSamplerAir),
    /// Horner `E = Σ cᵢ·ζⁱ (mod q)` fold for a witness ring element (design §4.1, R3).
    HornerFold(HornerFoldAir),
    /// `encode(μ)(ζ)` fold with boolean-μ binding (design §4.4, R3b).
    EncodeMuFold(EncodeMuFoldAir),
    /// Non-native `Z_q` linear-relation check `Σ_j a_j·w_j + c ≡ 0` (design §4.1, R3).
    RelationCheck(RelationCheckAir),
    /// Interim positional byte-stream source stand-in (design §5.1) — removed once the sponge sends.
    XofStream(XofStreamTableAir),
}

impl BaseAir<ConfigVal> for EncProofAir {
    fn width(&self) -> usize {
        match self {
            EncProofAir::Sponge(a) => BaseAir::<ConfigVal>::width(a),
            EncProofAir::SqueezeByte(a) => BaseAir::<ConfigVal>::width(a),
            EncProofAir::Ternary(a) => BaseAir::<ConfigVal>::width(a),
            EncProofAir::Bounded(a) => BaseAir::<ConfigVal>::width(a),
            EncProofAir::HornerFold(a) => BaseAir::<ConfigVal>::width(a),
            EncProofAir::EncodeMuFold(a) => BaseAir::<ConfigVal>::width(a),
            EncProofAir::RelationCheck(a) => BaseAir::<ConfigVal>::width(a),
            EncProofAir::XofStream(a) => BaseAir::<ConfigVal>::width(a),
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            EncProofAir::Sponge(a) => BaseAir::<ConfigVal>::num_public_values(a),
            EncProofAir::SqueezeByte(a) => BaseAir::<ConfigVal>::num_public_values(a),
            EncProofAir::Ternary(a) => BaseAir::<ConfigVal>::num_public_values(a),
            EncProofAir::Bounded(a) => BaseAir::<ConfigVal>::num_public_values(a),
            EncProofAir::HornerFold(a) => BaseAir::<ConfigVal>::num_public_values(a),
            EncProofAir::EncodeMuFold(a) => BaseAir::<ConfigVal>::num_public_values(a),
            EncProofAir::RelationCheck(a) => BaseAir::<ConfigVal>::num_public_values(a),
            EncProofAir::XofStream(a) => BaseAir::<ConfigVal>::num_public_values(a),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<ConfigVal>> {
        match self {
            EncProofAir::Sponge(a) => BaseAir::<ConfigVal>::preprocessed_trace(a),
            EncProofAir::SqueezeByte(a) => BaseAir::<ConfigVal>::preprocessed_trace(a),
            EncProofAir::Ternary(a) => BaseAir::<ConfigVal>::preprocessed_trace(a),
            EncProofAir::Bounded(a) => BaseAir::<ConfigVal>::preprocessed_trace(a),
            EncProofAir::HornerFold(a) => BaseAir::<ConfigVal>::preprocessed_trace(a),
            EncProofAir::EncodeMuFold(a) => BaseAir::<ConfigVal>::preprocessed_trace(a),
            EncProofAir::RelationCheck(a) => BaseAir::<ConfigVal>::preprocessed_trace(a),
            EncProofAir::XofStream(a) => BaseAir::<ConfigVal>::preprocessed_trace(a),
        }
    }
}

impl<AB: AirBuilder<F = ConfigVal>> Air<AB> for EncProofAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            EncProofAir::Sponge(a) => a.eval(builder),
            EncProofAir::SqueezeByte(a) => a.eval(builder),
            EncProofAir::Ternary(a) => a.eval(builder),
            EncProofAir::Bounded(a) => a.eval(builder),
            EncProofAir::HornerFold(a) => a.eval(builder),
            EncProofAir::EncodeMuFold(a) => a.eval(builder),
            EncProofAir::RelationCheck(a) => a.eval(builder),
            EncProofAir::XofStream(a) => a.eval(builder),
        }
    }
}

#[cfg(test)]
mod tests {
    use lib_q_plonky_batch_stark::{
        CommonData,
        ProverData,
        ProverOnlyData,
        StarkInstance,
        prove_batch,
        verify_batch,
    };
    use lib_q_plonky_uni_stark::StarkConfig;
    use lib_q_sha3::{
        ExtendableOutput,
        Update,
        XofReader,
    };
    use lib_q_stark_challenger::{
        ComplexFieldChallenger,
        Shake256Challenger32,
    };
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_fri::create_test_fri_params;
    use lib_q_stark_matrix::dense::RowMajorMatrix;
    use lib_q_stark_mersenne31::Mersenne31;
    use lib_q_stark_shake256::Shake256Hash;
    use lib_q_zkp::stark::{
        ConfigDft,
        DefaultChallengeMmcs,
        DefaultPcs,
        DefaultValMmcs,
    };

    use super::*;
    use crate::logup_join::{
        fc,
        generate_xof_stream_table,
        xof_stream_send_lookup,
    };
    use crate::sampler::{
        SAMPLER_WIDTH,
        generate_ternary_trace,
        ternary_public_values,
        ternary_receive_lookup,
    };

    type TestChallenger = ComplexFieldChallenger<Shake256Challenger32<Mersenne31>>;
    type TestConfig = StarkConfig<DefaultPcs, ConfigVal, TestChallenger>;

    /// A batch-stack STARK config (uni-stark `StarkConfig`) at **test** FRI params (2 queries, 1
    /// PoW bit) — same PCS/challenger construction as `lib_q_zkp::stark::default_config`, but the
    /// batch driver needs the uni-stark `StarkGenericConfig`, and small FRI params keep the
    /// round-trip fast. Not production-sound.
    fn test_batch_config() -> TestConfig {
        let shake = Shake256Hash {};
        let hash = lib_q_stark_symmetric::SerializingHasher::<Shake256Hash>::new(shake);
        let compress =
            lib_q_stark_symmetric::CompressionFunctionFromHasher::<Shake256Hash, 2, 32>::new(shake);
        let val_mmcs = DefaultValMmcs::new(hash, compress);
        let challenge_mmcs = DefaultChallengeMmcs::new(val_mmcs.clone());
        let dft = ConfigDft::default();
        let fri_params = create_test_fri_params(challenge_mmcs, 2);
        let pcs = DefaultPcs::new(dft, val_mmcs, fri_params);
        let base = Shake256Challenger32::<Mersenne31>::from_hasher(Vec::new(), Shake256Hash);
        let challenger = ComplexFieldChallenger::new(base);
        StarkConfig::new(pcs, challenger)
    }

    // ── Hiding-FRI (zero-knowledge) batch config (design §7, task #32) ────────────────────────────
    // A `HidingFriPcs` PCS (whose `ZK` const is `true`, so `config.is_zk() == 1`): the prover appends
    // random codewords to every committed matrix and the quotient is randomized, so the opened values
    // reveal nothing about the witness beyond the statement — the proof becomes zero-knowledge (μ is
    // blinded). The AIRs, lookups and composition are unchanged; only the PCS/config differ. Uses a
    // hiding Merkle MMCS (both the value and challenge MMCS must be hiding) + a deterministic RNG for
    // reproducible blinding in tests.
    type TestZkValMmcs = lib_q_stark_merkle::MerkleTreeHidingMmcs<
        <ConfigVal as lib_q_stark_field::Field>::Packing,
        u8,
        lib_q_stark_symmetric::SerializingHasher<Shake256Hash>,
        lib_q_stark_symmetric::CompressionFunctionFromHasher<Shake256Hash, 2, 32>,
        lib_q_random::DeterministicRng,
        32,
        4,
    >;
    type TestZkChallengeMmcs =
        lib_q_stark_commit::ExtensionMmcs<ConfigVal, ConfigVal, TestZkValMmcs>;
    type TestZkPcs = lib_q_stark_fri::HidingFriPcs<
        ConfigVal,
        ConfigDft,
        TestZkValMmcs,
        TestZkChallengeMmcs,
        lib_q_random::DeterministicRng,
    >;
    type TestZkConfig = StarkConfig<TestZkPcs, ConfigVal, TestChallenger>;

    /// A **hiding-FRI (zero-knowledge)** batch config at test FRI params. `is_zk() == 1` (the PCS's
    /// `ZK` const), so the batch prover blinds the trace + randomizes the quotient. Not production
    /// params, but the ZK code path the production `prove` will use.
    fn test_batch_config_zk() -> TestZkConfig {
        use lib_q_random::DeterministicRng;
        let shake = Shake256Hash {};
        let hash = lib_q_stark_symmetric::SerializingHasher::<Shake256Hash>::new(shake);
        let compress =
            lib_q_stark_symmetric::CompressionFunctionFromHasher::<Shake256Hash, 2, 32>::new(shake);
        let val_mmcs = TestZkValMmcs::new(hash, compress, DeterministicRng::seed_from_u64(1));
        let challenge_mmcs = TestZkChallengeMmcs::new(val_mmcs.clone());
        let dft = ConfigDft::default();
        let fri_params = lib_q_stark_fri::create_test_fri_params_zk(challenge_mmcs);
        let pcs = TestZkPcs::new(
            dft,
            val_mmcs,
            fri_params,
            4,
            DeterministicRng::seed_from_u64(1),
        );
        let base = Shake256Challenger32::<Mersenne31>::from_hasher(Vec::new(), Shake256Hash);
        let challenger = ComplexFieldChallenger::new(base);
        StarkConfig::new(pcs, challenger)
    }

    /// Hand-assemble the batch prover's committed preprocessed data from a set of AIRs (the batch
    /// API provides no builder). For each AIR that returns a `preprocessed_trace()`, commit its
    /// matrix through the config's PCS and record a [`PreprocessedInstanceMeta`]; AIRs without one
    /// get a `None` slot. Returns the `GlobalPreprocessed` (for `CommonData`) and the matching
    /// `ProverOnlyData`. Generic over `SC` so the PCS's `Pcs<SC::Challenge, SC::Challenger>` impl is
    /// pinned (avoids the type-inference ambiguity a concrete call hits). Non-zk only for now
    /// (`is_zk` is threaded but the hiding-PCS path is exercised later).
    fn build_preprocessed<SC, A>(
        config: &SC,
        airs: &[A],
    ) -> (
        Option<lib_q_plonky_batch_stark::common::GlobalPreprocessed<SC>>,
        ProverOnlyData<SC>,
    )
    where
        SC: lib_q_plonky_uni_stark::StarkGenericConfig,
        A: BaseAir<lib_q_plonky_uni_stark::Val<SC>>,
    {
        use lib_q_plonky_batch_stark::common::{
            GlobalPreprocessed,
            PreprocessedInstanceMeta,
        };
        use lib_q_stark_commit::Pcs;

        let pcs = config.pcs();
        let is_zk = config.is_zk();
        let mut inputs = Vec::new();
        let mut instances = Vec::with_capacity(airs.len());
        let mut matrix_to_instance = Vec::new();
        for (i, air) in airs.iter().enumerate() {
            match air.preprocessed_trace() {
                Some(mat) => {
                    let width = mat.width;
                    let height = mat.values.len() / width;
                    let degree_bits = height.trailing_zeros() as usize;
                    let ext_db = degree_bits + is_zk;
                    let domain = pcs.natural_domain_for_degree(1usize << ext_db);
                    let matrix_index = inputs.len();
                    inputs.push((domain, mat));
                    instances.push(Some(PreprocessedInstanceMeta {
                        matrix_index,
                        width,
                        degree_bits: ext_db,
                    }));
                    matrix_to_instance.push(i);
                }
                None => instances.push(None),
            }
        }
        if inputs.is_empty() {
            return (None, ProverOnlyData::empty());
        }
        let (commitment, prover_data) = pcs.commit(inputs);
        (
            Some(GlobalPreprocessed {
                commitment,
                instances,
                matrix_to_instance,
            }),
            ProverOnlyData {
                preprocessed_prover_data: Some(prover_data),
            },
        )
    }

    fn shake256_xof(seed: &[u8], n: usize) -> Vec<u8> {
        let mut h = lib_q_sha3::Shake256::default();
        h.update(seed);
        let mut rd = h.finalize_xof();
        let mut out = vec![0u8; n];
        rd.read(&mut out);
        out
    }

    fn active_rows(trace: &RowMajorMatrix<ConfigVal>, width: usize, active_col: usize) -> usize {
        (0..trace.values.len() / width)
            .filter(|&r| trace.values[r * width + active_col] == ConfigVal::ONE)
            .count()
    }

    /// DIAGNOSTIC: is `XofStreamTableAir` provable at all via the batch path, with NO lookups?
    #[test]
    fn diag_xofstream_alone_no_lookup() {
        let bytes = shake256_xof(b"libq/diag/xof", 300);
        let source = generate_xof_stream_table(&bytes);
        let air = EncProofAir::XofStream(XofStreamTableAir);
        let config = test_batch_config();
        let prover_data = ProverData::empty(1);
        let instances = [StarkInstance {
            air: &air,
            trace: &source,
            public_values: Vec::new(),
            lookups: Vec::new(),
        }];
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");
        verify_batch(&config, &[air], &proof, &[Vec::new()], &prover_data.common)
            .expect("xofstream alone must verify");
    }

    /// DIAGNOSTIC: is `TernarySamplerAir` provable via the batch path, with NO lookups?
    #[test]
    fn diag_ternary_alone_no_lookup() {
        let bytes = shake256_xof(b"libq/diag/tern", 4096);
        let num = 512usize;
        let ternary = generate_ternary_trace(&bytes, num).expect("ternary trace");
        let air = EncProofAir::Ternary(TernarySamplerAir { num_coeffs: num });
        let config = test_batch_config();
        let prover_data = ProverData::empty(1);
        let instances = [StarkInstance {
            air: &air,
            trace: &ternary,
            public_values: ternary_public_values(num),
            lookups: Vec::new(),
        }];
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");
        verify_batch(
            &config,
            &[air],
            &proof,
            &[ternary_public_values(num)],
            &prover_data.common,
        )
        .expect("ternary alone must verify");
    }

    /// DIAGNOSTIC: a single Send-only instance WITH its Global lookup. The global multiset cannot
    /// balance (nothing receives), so verify must fail — but the FAILURE MODE tells us whether the
    /// per-instance lookup CONSTRAINT is sound: `GlobalCumulativeMismatch` ⇒ constraint fine, only
    /// balance fails; `OodEvaluationMismatch` ⇒ the lookup permutation constraint itself is broken.
    #[test]
    fn diag_xofstream_with_send_lookup_alone() {
        let bytes = shake256_xof(b"libq/diag/xof-send", 300);
        let source = generate_xof_stream_table(&bytes);
        let air = EncProofAir::XofStream(XofStreamTableAir);
        let send = xof_stream_send_lookup();
        let config = test_batch_config();
        let common = CommonData::new(None, Vec::from([Vec::from([send.clone()])]));
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };
        let instances = [StarkInstance {
            air: &air,
            trace: &source,
            public_values: Vec::new(),
            lookups: Vec::from([send.clone()]),
        }];
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");
        let res = verify_batch(&config, &[air], &proof, &[Vec::new()], &prover_data.common);
        // A send-only instance cannot balance (nothing receives), so verify must reject — and the
        // rejection must be the GLOBAL-BALANCE failure (`LookupError`/`GlobalCumulativeMismatch`),
        // NOT an `OodEvaluationMismatch` (which would mean the lookup constraint itself is broken).
        match res {
            Err(lib_q_plonky_batch_stark::VerificationError::OodEvaluationMismatch { .. }) => {
                panic!("send-only failed with OodEvaluationMismatch — lookup CONSTRAINT is broken")
            }
            Err(_) => {} // expected: global-balance rejection
            Ok(()) => panic!("send-only must not verify (unbalanced global lookup)"),
        }
    }

    /// **The de-risk milestone.** A `Kind::Global` cross-table lookup between two *different* AIR
    /// instances — the byte-stream source (`XofStreamTableAir`, Send) and the ternary sampler
    /// (`TernarySamplerAir`, Receive) — driven end-to-end through `prove_batch` then `verify_batch`.
    /// When the source sends exactly the bytes the sampler consumes, the per-bus cumulated sum is
    /// zero and the batch verifier accepts. This is the composition primitive the whole proof rests
    /// on, and it had **no** end-to-end test before now (only the debug `check_lookups`).
    #[test]
    fn compose_global_lookup_round_trip() {
        let seed = b"libq/compose/global-lookup";
        let bytes = shake256_xof(seed, 4096);
        let num = 512usize;
        let ternary = generate_ternary_trace(&bytes, num).expect("ternary trace");
        let consumed = active_rows(&ternary, SAMPLER_WIDTH, 0);
        let source = generate_xof_stream_table(&bytes[..consumed]);

        let source_air = EncProofAir::XofStream(XofStreamTableAir);
        let ternary_air = EncProofAir::Ternary(TernarySamplerAir { num_coeffs: num });

        let send = xof_stream_send_lookup();
        let recv = ternary_receive_lookup();

        let config = test_batch_config();
        let common = CommonData::new(
            None,
            Vec::from([Vec::from([send.clone()]), Vec::from([recv.clone()])]),
        );
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };

        let instances = [
            StarkInstance {
                air: &source_air,
                trace: &source,
                public_values: Vec::new(),
                lookups: Vec::from([send.clone()]),
            },
            StarkInstance {
                air: &ternary_air,
                trace: &ternary,
                public_values: ternary_public_values(num),
                lookups: Vec::from([recv.clone()]),
            },
        ];

        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");
        verify_batch(
            &config,
            &[source_air, ternary_air],
            &proof,
            &[Vec::new(), ternary_public_values(num)],
            &prover_data.common,
        )
        .expect("verify_batch must accept a balanced cross-table Global lookup");
    }

    /// **Preprocessed de-risk milestone.** A `Kind::Global` LogUp whose tuple element reads a
    /// **preprocessed** (fixed) column, committed and opened through `prove_batch`/`verify_batch`
    /// via a hand-assembled [`GlobalPreprocessed`]. This validates the mechanism the sponge
    /// limb-SEND needs: a deterministic per-row position offset supplied by a preprocessed column
    /// (sound because the verifier commits it independently of the prover). Self-balancing (Send
    /// `[p]` + Receive `[p]`), so it must verify. Previously untested repo-wide.
    #[test]
    fn compose_preprocessed_lookup_round_trip() {
        use lib_q_plonky_lookup::{
            Direction,
            Kind,
            Lookup,
        };
        use lib_q_stark_air::symbolic::{
            BaseEntry,
            SymbolicExpression,
            SymbolicVariable,
        };

        /// Width-1 AIR with a single **preprocessed** column (fixed values `0,1,2,…`) and no
        /// algebraic constraints of its own; the lookup is the only thing binding the trace.
        #[derive(Clone)]
        struct PreLookupAir {
            rows: usize,
        }
        impl BaseAir<ConfigVal> for PreLookupAir {
            fn width(&self) -> usize {
                1
            }
            fn num_public_values(&self) -> usize {
                0
            }
            fn preprocessed_trace(&self) -> Option<RowMajorMatrix<ConfigVal>> {
                Some(RowMajorMatrix::new(
                    (0..self.rows).map(|r| fc(r as u64)).collect(),
                    1,
                ))
            }
        }
        impl<AB: AirBuilder<F = ConfigVal>> Air<AB> for PreLookupAir {
            fn eval(&self, _builder: &mut AB) {}
        }

        let config = test_batch_config();
        let rows = 64usize;
        let air = PreLookupAir { rows };
        // Main trace: width 1, height `rows`, arbitrary values (no AIR constraints).
        let trace = RowMajorMatrix::new((0..rows as u64).map(fc).collect::<Vec<_>>(), 1);

        // Self-balancing Global lookup over PREPROCESSED column 0 (Send [p] + Receive [p]).
        let p = SymbolicExpression::from(SymbolicVariable::<ConfigVal>::new(
            BaseEntry::Preprocessed { offset: 0 },
            0,
        ));
        let one = SymbolicExpression::from(ConfigVal::ONE);
        let lookup = Lookup::new(
            Kind::Global("compose.pre.selftest.v0".into()),
            Vec::from([Vec::from([p.clone()]), Vec::from([p])]),
            Vec::from([
                Direction::Send.multiplicity(one.clone()),
                Direction::Receive.multiplicity(one),
            ]),
            Vec::from([0]),
        );

        // Hand-assemble the committed preprocessed trace via the reusable helper.
        let (global, prover_only) = build_preprocessed(&config, core::slice::from_ref(&air));
        let common = CommonData::new(global, Vec::from([Vec::from([lookup.clone()])]));
        let prover_data = ProverData {
            common,
            prover_only,
        };
        let instance = StarkInstance {
            air: &air,
            trace: &trace,
            public_values: Vec::new(),
            lookups: Vec::from([lookup]),
        };

        let proof = prove_batch(&config, &[instance], &prover_data)
            .expect("prove_batch preprocessed+lookup");
        verify_batch(&config, &[air], &proof, &[Vec::new()], &prover_data.common)
            .expect("a preprocessed-column Global lookup must verify");
    }

    /// **Full byte-provenance chain, cryptographically enforced via `prove_batch`.** Three
    /// enum-wrapped instances on two Global buses: the sponge Sends its 68 squeezed limbs/block
    /// (positioned by a committed preprocessed column) on the limb bus; the squeeze-byte table
    /// Receives the full squeeze there and Sends the consumed byte prefix on the byte bus; the
    /// ternary sampler Receives that prefix. `verify_batch` accepts iff every per-bus cumulated sum
    /// is zero — so this pins, in-proof, that the bytes the sampler consumed are the genuine SHAKE
    /// output of the sponge. This is the capstone that the limb-Send + consumed-flag design targets.
    #[test]
    fn compose_byte_provenance_prove_batch() {
        use lib_q_plonky_keccak_air::{
            NUM_KECCAK_COLS,
            NUM_ROUNDS,
        };

        use crate::sampler::{
            generate_ternary_trace,
            ternary_public_values,
        };
        use crate::sponge::RATE_BYTES;
        use crate::sponge_air::{
            ShakeSpongeAir,
            encap_preimage,
            generate_provable_sponge_trace,
            sponge_limb_send_lookups,
            sponge_public_values,
        };
        use crate::squeeze_byte::{
            generate_squeeze_byte_trace_partial,
            squeeze_byte_limb_receive_lookup,
            squeeze_byte_send_lookup,
        };

        let pk = [0x44u8; 32];
        let mu = [0x99u8; 32];
        let input = encap_preimage(&pk, &mu);

        // Small ternary draw to keep the (heavy, 2633-col) sponge trace proof fast.
        let bytes = shake256_xof(&input, 4096);
        let num_coeffs = 48usize;
        let ternary = generate_ternary_trace(&bytes, num_coeffs).expect("ternary trace");
        let consumed = active_rows(&ternary, SAMPLER_WIDTH, 0);

        let sponge = generate_provable_sponge_trace(&input, consumed + RATE_BYTES);
        let height = sponge.values.len() / NUM_KECCAK_COLS;
        let blocks = (0..height)
            .filter(|r| r % NUM_ROUNDS == NUM_ROUNDS - 1)
            .count();
        let full_limbs = blocks * (RATE_BYTES / 2);
        assert!(full_limbs * 2 >= consumed);
        let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, consumed);

        let sponge_air = EncProofAir::Sponge(ShakeSpongeAir { height });
        let squeeze_air = EncProofAir::SqueezeByte(SqueezeByteAir);
        let ternary_air = EncProofAir::Ternary(TernarySamplerAir { num_coeffs });
        let airs = [sponge_air, squeeze_air, ternary_air];

        let sponge_lookups = sponge_limb_send_lookups();
        let squeeze_lookups = Vec::from([
            squeeze_byte_send_lookup(),
            squeeze_byte_limb_receive_lookup(),
        ]);
        let ternary_lookups = Vec::from([ternary_receive_lookup()]);

        let config = test_batch_config();
        let (global, prover_only) = build_preprocessed(&config, &airs);
        let common = CommonData::new(
            global,
            Vec::from([
                sponge_lookups.clone(),
                squeeze_lookups.clone(),
                ternary_lookups.clone(),
            ]),
        );
        let prover_data = ProverData {
            common,
            prover_only,
        };

        let sponge_pubs = sponge_public_values(&pk);
        let ternary_pubs = ternary_public_values(num_coeffs);
        let instances = [
            StarkInstance {
                air: &airs[0],
                trace: &sponge,
                public_values: sponge_pubs.clone(),
                lookups: sponge_lookups,
            },
            StarkInstance {
                air: &airs[1],
                trace: &squeeze,
                public_values: Vec::new(),
                lookups: squeeze_lookups,
            },
            StarkInstance {
                air: &airs[2],
                trace: &ternary,
                public_values: ternary_pubs.clone(),
                lookups: ternary_lookups,
            },
        ];

        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch chain");
        verify_batch(
            &config,
            &airs,
            &proof,
            &[sponge_pubs, Vec::new(), ternary_pubs],
            &prover_data.common,
        )
        .expect("the byte-provenance chain must verify");
    }

    /// **The soundness point of byte provenance.** An honest squeeze-byte table + sampler over the
    /// real `input`, but a sponge proving a *different* μ′ (same pk). Each AIR is individually valid,
    /// so `prove_batch` succeeds — but the sponge Sends the limbs of `SHAKE(input′)` while the
    /// squeeze table Receives the limbs of `SHAKE(input)`, so the limb bus does not balance and
    /// `verify_batch` must reject. This is exactly the malformed-ciphertext substitution the join
    /// exists to catch.
    #[test]
    fn compose_byte_provenance_wrong_sponge_rejected() {
        use lib_q_plonky_keccak_air::{
            NUM_KECCAK_COLS,
            NUM_ROUNDS,
        };

        use crate::sampler::{
            generate_ternary_trace,
            ternary_public_values,
        };
        use crate::sponge::RATE_BYTES;
        use crate::sponge_air::{
            ShakeSpongeAir,
            encap_preimage,
            generate_provable_sponge_trace,
            sponge_limb_send_lookups,
            sponge_public_values,
        };
        use crate::squeeze_byte::{
            generate_squeeze_byte_trace_partial,
            squeeze_byte_limb_receive_lookup,
            squeeze_byte_send_lookup,
        };

        let pk = [0x44u8; 32];
        let input = encap_preimage(&pk, &[0x99u8; 32]);
        let input_wrong = encap_preimage(&pk, &[0x00u8; 32]); // different μ, same pk

        let bytes = shake256_xof(&input, 4096);
        let num_coeffs = 48usize;
        let ternary = generate_ternary_trace(&bytes, num_coeffs).expect("ternary trace");
        let consumed = active_rows(&ternary, SAMPLER_WIDTH, 0);

        // Sponge proves the WRONG μ; squeeze + sampler are the honest chain over `input`.
        let sponge = generate_provable_sponge_trace(&input_wrong, consumed + RATE_BYTES);
        let height = sponge.values.len() / NUM_KECCAK_COLS;
        let blocks = (0..height)
            .filter(|r| r % NUM_ROUNDS == NUM_ROUNDS - 1)
            .count();
        let full_limbs = blocks * (RATE_BYTES / 2);
        let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, consumed);

        let sponge_air = EncProofAir::Sponge(ShakeSpongeAir { height });
        let squeeze_air = EncProofAir::SqueezeByte(SqueezeByteAir);
        let ternary_air = EncProofAir::Ternary(TernarySamplerAir { num_coeffs });
        let airs = [sponge_air, squeeze_air, ternary_air];

        let sponge_lookups = sponge_limb_send_lookups();
        let squeeze_lookups = Vec::from([
            squeeze_byte_send_lookup(),
            squeeze_byte_limb_receive_lookup(),
        ]);
        let ternary_lookups = Vec::from([ternary_receive_lookup()]);

        let config = test_batch_config();
        let (global, prover_only) = build_preprocessed(&config, &airs);
        let common = CommonData::new(
            global,
            Vec::from([
                sponge_lookups.clone(),
                squeeze_lookups.clone(),
                ternary_lookups.clone(),
            ]),
        );
        let prover_data = ProverData {
            common,
            prover_only,
        };

        // The sponge proves SHAKE over `input_wrong` with pk's public values (pk is unchanged), so
        // constraint (A) is satisfied and the instance is individually valid.
        let sponge_pubs = sponge_public_values(&pk);
        let ternary_pubs = ternary_public_values(num_coeffs);
        let instances = [
            StarkInstance {
                air: &airs[0],
                trace: &sponge,
                public_values: sponge_pubs.clone(),
                lookups: sponge_lookups,
            },
            StarkInstance {
                air: &airs[1],
                trace: &squeeze,
                public_values: Vec::new(),
                lookups: squeeze_lookups,
            },
            StarkInstance {
                air: &airs[2],
                trace: &ternary,
                public_values: ternary_pubs.clone(),
                lookups: ternary_lookups,
            },
        ];

        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");
        let res = verify_batch(
            &config,
            &airs,
            &proof,
            &[sponge_pubs, Vec::new(), ternary_pubs],
            &prover_data.common,
        );
        assert!(
            res.is_err(),
            "a sponge proving a different μ must fail the limb-bus balance"
        );
    }

    /// The negative of the de-risk milestone: when the source sends the WRONG bytes (a source built
    /// from a *different* XOF stream than the sampler consumed), each per-instance AIR still holds
    /// individually, but the cross-table `Kind::Global` multiset does not balance, so the batch
    /// verifier's `verify_global_final_value` rejects. This proves the join is enforced
    /// *cryptographically* by `verify_batch`, not merely by the debug `check_lookups`.
    #[test]
    fn compose_global_lookup_unbalanced_rejected() {
        let seed = b"libq/compose/global-lookup-bad";
        let bytes = shake256_xof(seed, 4096);
        let num = 512usize;
        let ternary = generate_ternary_trace(&bytes, num).expect("ternary trace");
        let consumed = active_rows(&ternary, SAMPLER_WIDTH, 0);
        // Source over a DIFFERENT stream: valid stream table, but its (pos, byte) tuples do not
        // match what the sampler received → global multiset imbalance.
        let other = shake256_xof(b"libq/compose/other-stream", consumed);
        let source = generate_xof_stream_table(&other);

        let source_air = EncProofAir::XofStream(XofStreamTableAir);
        let ternary_air = EncProofAir::Ternary(TernarySamplerAir { num_coeffs: num });
        let send = xof_stream_send_lookup();
        let recv = ternary_receive_lookup();

        let config = test_batch_config();
        let common = CommonData::new(
            None,
            Vec::from([Vec::from([send.clone()]), Vec::from([recv.clone()])]),
        );
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };

        let instances = [
            StarkInstance {
                air: &source_air,
                trace: &source,
                public_values: Vec::new(),
                lookups: Vec::from([send.clone()]),
            },
            StarkInstance {
                air: &ternary_air,
                trace: &ternary,
                public_values: ternary_public_values(num),
                lookups: Vec::from([recv.clone()]),
            },
        ];

        // The prover can still produce a proof (per-instance constraints hold); the verifier must
        // reject on the global balance.
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");
        let res = verify_batch(
            &config,
            &[source_air, ternary_air],
            &proof,
            &[Vec::new(), ternary_public_values(num)],
            &prover_data.common,
        );
        assert!(
            res.is_err(),
            "verify_batch must reject an unbalanced cross-table Global lookup"
        );
    }

    /// **Join 3 (fold result → relation), cryptographically enforced via `prove_batch`.** A Horner
    /// fold computing `E = Σ cᵢ·ζⁱ (mod q)` Sends its last-row result on `FOLD_E_BUS`; a
    /// `RelationCheckAir` proving `1·w_0 + (q − E) ≡ 0 (mod q)` Receives it into `w_0`. `verify_batch`
    /// accepts iff the fold-E bus balances — pinning, in-proof, that the relation's witness term is the
    /// value the fold actually computed. A relation over a *different* `w_0` fails the bus balance.
    /// This is the join-3 analogue of the byte-provenance capstone: the boundary opening enforced by
    /// the batch verifier's `verify_global_final_value`, not merely the debug `check_lookups`.
    #[test]
    fn compose_fold_to_relation_prove_batch() {
        use crate::logup_join::FOLD_E_BUS;
        use crate::zq::{
            Q,
            RelationCheckAir,
            generate_horner_trace,
            generate_relation_trace,
            horner_e_send_lookups_at,
            horner_public_values,
        };

        const H: usize = 32; // trace height (power of two, safely above the test FRI minimum)

        // Fold over H coefficients (height H, no front padding).
        let coeffs: Vec<u64> = (0..H as u64).map(|i| (i * 7 + 3) % Q).collect();
        let zeta = 424_242u64;
        let (fold, e) = generate_horner_trace(&coeffs, zeta).expect("horner trace");
        let fold_air = EncProofAir::HornerFold(HornerFoldAir);
        let fold_pubs = horner_public_values(zeta);

        // Build a RelationCheck (1·w_0 + (q−w_0) ≡ 0) and pad its 2 replica rows to height H (row 0
        // keeps is_first = 1; the rest are is_first = 0 replicas — the descent/transition still pins it).
        let build_relation = |w0: u64| {
            let rc = RelationCheckAir { num_terms: 1 };
            let (m, pubs) = generate_relation_trace(&[1], &[w0], (Q - w0) % Q).expect("relation");
            let w = m.width;
            let mut vals = Vec::with_capacity(H * w);
            vals.extend_from_slice(&m.values[0..w]); // row 0 (is_first = 1)
            for _ in 0..H - 1 {
                vals.extend_from_slice(&m.values[w..2 * w]); // is_first = 0 replicas
            }
            (rc, RowMajorMatrix::new(vals, w), pubs)
        };

        let (rc, relation, rel_pubs) = build_relation(e);
        let relation_air = EncProofAir::RelationCheck(rc.clone());
        let send = horner_e_send_lookups_at(FOLD_E_BUS, 0, 0, 0);
        let recv = rc.relation_w_receive_lookups_at(FOLD_E_BUS, 0);

        let config = test_batch_config();
        let common = CommonData::new(None, Vec::from([send.clone(), recv.clone()]));
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };
        let instances = [
            StarkInstance {
                air: &fold_air,
                trace: &fold,
                public_values: fold_pubs.clone(),
                lookups: send.clone(),
            },
            StarkInstance {
                air: &relation_air,
                trace: &relation,
                public_values: rel_pubs.clone(),
                lookups: recv.clone(),
            },
        ];
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");
        verify_batch(
            &config,
            &[fold_air.clone(), relation_air],
            &proof,
            &[fold_pubs.clone(), rel_pubs],
            &prover_data.common,
        )
        .expect("the fold result must bind to the relation's w_0 on the fold-E bus");

        // Negative: a relation over w_0 = E+1 no longer matches the fold's Send → bus imbalance.
        let (rc2, relation2, rel_pubs2) = build_relation((e + 1) % Q);
        let relation_air2 = EncProofAir::RelationCheck(rc2.clone());
        let recv2 = rc2.relation_w_receive_lookups_at(FOLD_E_BUS, 0);
        let common2 = CommonData::new(None, Vec::from([send.clone(), recv2.clone()]));
        let prover_data2 = ProverData {
            common: common2,
            prover_only: ProverOnlyData::empty(),
        };
        let instances2 = [
            StarkInstance {
                air: &fold_air,
                trace: &fold,
                public_values: fold_pubs.clone(),
                lookups: send,
            },
            StarkInstance {
                air: &relation_air2,
                trace: &relation2,
                public_values: rel_pubs2.clone(),
                lookups: recv2,
            },
        ];
        let proof2 = prove_batch(&config, &instances2, &prover_data2).expect("prove_batch");
        let res = verify_batch(
            &config,
            &[fold_air, relation_air2],
            &proof2,
            &[fold_pubs, rel_pubs2],
            &prover_data2.common,
        );
        assert!(
            res.is_err(),
            "a relation over a fold value other than E must fail the fold-E bus balance"
        );
    }

    /// **Join 2 (sampler coeff → fold `w`), cryptographically enforced via `prove_batch`.** A ternary
    /// sampler Sends each emitted coefficient's mod-q lift on `COEFF_E_BUS`; a Horner fold over the same
    /// coefficients Receives them into its `w` limbs. `verify_batch` accepts iff the coeff bus balances
    /// — pinning, in-proof, that the fold evaluated the coefficients the sampler produced. A fold over a
    /// *different* coefficient fails the bus balance. This closes join 2's cryptographic enforcement
    /// (previously only the debug `check_lookups`).
    #[test]
    fn compose_sampler_to_fold_join2_prove_batch() {
        use crate::logup_join::COEFF_E_BUS;
        use crate::sampler::ternary_coeff_send_lookups_at;
        use crate::zq::{
            Q,
            generate_horner_trace,
            horner_coeff_receive_lookups_at,
            horner_public_values,
        };

        let bytes = shake256_xof(b"libq/compose/join2", 4096);
        let n = 32usize; // power of two ⇒ fold height = n, no front padding

        let ternary = generate_ternary_trace(&bytes, n).expect("ternary trace");
        let ternary_air = EncProofAir::Ternary(TernarySamplerAir { num_coeffs: n });
        let ternary_pubs = ternary_public_values(n);

        // The emitted signed coefficients, mod-q lifted, fed to the fold low-order first.
        let mut lifts: Vec<u64> = Vec::new();
        let mut i = 0usize;
        while lifts.len() < n {
            let two = bytes[i] & 0b11;
            i += 1;
            if two < 3 {
                lifts.push((i64::from(two) - 1).rem_euclid(Q as i64) as u64);
            }
        }
        let zeta = 191_919u64;
        let (fold, _e) = generate_horner_trace(&lifts, zeta).expect("horner trace");
        let fold_air = EncProofAir::HornerFold(HornerFoldAir);
        let fold_pubs = horner_public_values(zeta);

        let send = ternary_coeff_send_lookups_at(0, 0);
        let recv = horner_coeff_receive_lookups_at(COEFF_E_BUS, 0);

        let config = test_batch_config();
        let common = CommonData::new(None, Vec::from([send.clone(), recv.clone()]));
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };
        let instances = [
            StarkInstance {
                air: &ternary_air,
                trace: &ternary,
                public_values: ternary_pubs.clone(),
                lookups: send.clone(),
            },
            StarkInstance {
                air: &fold_air,
                trace: &fold,
                public_values: fold_pubs.clone(),
                lookups: recv.clone(),
            },
        ];
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");
        verify_batch(
            &config,
            &[ternary_air.clone(), fold_air.clone()],
            &proof,
            &[ternary_pubs.clone(), fold_pubs.clone()],
            &prover_data.common,
        )
        .expect("the fold coefficients must bind to the sampler's on the coeff bus");

        // Negative: fold a DIFFERENT coefficient at degree 0 → the coeff bus no longer balances.
        let mut bad = lifts.clone();
        bad[0] = if lifts[0] == 1 { 0 } else { 1 };
        let (bad_fold, _) = generate_horner_trace(&bad, zeta).expect("horner trace");
        let instances2 = [
            StarkInstance {
                air: &ternary_air,
                trace: &ternary,
                public_values: ternary_pubs.clone(),
                lookups: send,
            },
            StarkInstance {
                air: &fold_air,
                trace: &bad_fold,
                public_values: fold_pubs.clone(),
                lookups: recv,
            },
        ];
        let proof2 = prove_batch(&config, &instances2, &prover_data).expect("prove_batch");
        let res = verify_batch(
            &config,
            &[ternary_air, fold_air],
            &proof2,
            &[ternary_pubs, fold_pubs],
            &prover_data.common,
        );
        assert!(
            res.is_err(),
            "a fold over a coefficient the sampler did not produce must fail the coeff-bus balance"
        );
    }

    /// **Bounded 8-tuple join-1 receive through `prove_batch`** (design §5.1). The bounded sampler
    /// Receives its 8 consumed bytes/row as a single 8-tuple `Kind::Global` lookup — an 8-fold product
    /// common denominator ⇒ a degree-~9 LogUp constraint, the highest-degree lookup in the crate and
    /// the last one untested through the batch stack (the byte-provenance capstone used the 1-tuple
    /// ternary receive). This confirms the quotient domain accommodates it: the source Sends the bytes,
    /// the bounded sampler Receives 8/row, `verify_batch` accepts iff balanced.
    #[test]
    fn compose_bounded_join1_prove_batch() {
        use crate::sampler::{
            BOUNDED_WIDTH,
            bounded_public_values,
            bounded_receive_lookup,
            generate_bounded_trace,
        };

        let num = 32usize;
        let bytes = shake256_xof(b"libq/compose/bounded-join1", num * 8 + 2048);
        let bounded = generate_bounded_trace(&bytes, num).expect("bounded trace");
        let rows = active_rows(&bounded, BOUNDED_WIDTH, 0); // W_ACTIVE = 0
        let source = generate_xof_stream_table(&bytes[..rows * 8]); // 8 bytes per active row

        let source_air = EncProofAir::XofStream(XofStreamTableAir);
        let bounded_air = EncProofAir::Bounded(BoundedSamplerAir { num_coeffs: num });
        let send = xof_stream_send_lookup();
        let recv = bounded_receive_lookup(); // 8 single-tuple Receives

        let config = test_batch_config();
        let common = CommonData::new(None, Vec::from([Vec::from([send.clone()]), recv.clone()]));
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };
        let bounded_pubs = bounded_public_values(num);
        let instances = [
            StarkInstance {
                air: &source_air,
                trace: &source,
                public_values: Vec::new(),
                lookups: Vec::from([send]),
            },
            StarkInstance {
                air: &bounded_air,
                trace: &bounded,
                public_values: bounded_pubs.clone(),
                lookups: recv,
            },
        ];
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");
        verify_batch(
            &config,
            &[source_air, bounded_air],
            &proof,
            &[Vec::new(), bounded_pubs],
            &prover_data.common,
        )
        .expect("the bounded sampler's 8 consumed bytes/row must bind to the source");
    }

    /// **Three-instance chain — join 2 AND join 3 in ONE `prove_batch`.** Ternary sampler → Horner fold
    /// → relation check, over TWO buses simultaneously: the sampler Sends its coefficients on
    /// `COEFF_E_BUS`, the fold Receives them (join 2, aux cols 0..4) AND Sends its result `E` on
    /// `FOLD_E_BUS` (join 3, aux cols 4..8 via `col_base`), the relation Receives `E` into `w_0`.
    /// `verify_batch` accepts iff BOTH buses balance — the mid-chain fold carries two lookup groups
    /// without aux-column collision. This is the composition shape the full #26 chain scales up (every
    /// witness fold receives its coefficients and sends its evaluation), proven end-to-end here.
    #[test]
    fn compose_sampler_fold_relation_two_joins_prove_batch() {
        use crate::logup_join::{
            COEFF_E_BUS,
            FOLD_E_BUS,
        };
        use crate::sampler::ternary_coeff_send_lookups_at;
        use crate::zq::{
            Q,
            RelationCheckAir,
            generate_horner_trace,
            generate_relation_trace,
            horner_coeff_receive_lookups_at,
            horner_e_send_lookups_at,
            horner_public_values,
        };

        let bytes = shake256_xof(b"libq/compose/two-joins", 4096);
        let n = 32usize; // fold height = n (power of two, no front padding)

        let ternary = generate_ternary_trace(&bytes, n).expect("ternary trace");
        let ternary_air = EncProofAir::Ternary(TernarySamplerAir { num_coeffs: n });
        let ternary_pubs = ternary_public_values(n);

        // Coefficient lifts fed to the fold (low-order first).
        let mut lifts: Vec<u64> = Vec::new();
        let mut i = 0usize;
        while lifts.len() < n {
            let two = bytes[i] & 0b11;
            i += 1;
            if two < 3 {
                lifts.push((i64::from(two) - 1).rem_euclid(Q as i64) as u64);
            }
        }
        let zeta = 606_060u64;
        let (fold, e) = generate_horner_trace(&lifts, zeta).expect("horner trace");
        let fold_air = EncProofAir::HornerFold(HornerFoldAir);
        let fold_pubs = horner_public_values(zeta);

        // Relation 1·w_0 + (q−E) ≡ 0; pad its 2 replica rows to height n.
        let rc = RelationCheckAir { num_terms: 1 };
        let (rm, rel_pubs) =
            generate_relation_trace(&[1], &[e], (Q - e) % Q).expect("relation trace");
        let rw = rm.width;
        let mut rvals = Vec::with_capacity(n * rw);
        rvals.extend_from_slice(&rm.values[0..rw]); // row 0 (is_first = 1)
        for _ in 0..n - 1 {
            rvals.extend_from_slice(&rm.values[rw..2 * rw]); // is_first = 0 replicas
        }
        let relation = RowMajorMatrix::new(rvals, rw);
        let relation_air = EncProofAir::RelationCheck(rc.clone());

        // Lookups: sampler Send (coeff bus); fold Receive (coeff bus, cols 0..4) + Send (fold-E bus,
        // cols 4..8); relation Receive (fold-E bus).
        let s_send = ternary_coeff_send_lookups_at(0, 0);
        let f_recv = horner_coeff_receive_lookups_at(COEFF_E_BUS, 0);
        let f_send = horner_e_send_lookups_at(FOLD_E_BUS, 0, 0, 4);
        let mut fold_lookups = f_recv;
        fold_lookups.extend(f_send);
        let r_recv = rc.relation_w_receive_lookups_at(FOLD_E_BUS, 0);

        let config = test_batch_config();
        let common = CommonData::new(
            None,
            Vec::from([s_send.clone(), fold_lookups.clone(), r_recv.clone()]),
        );
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };
        let instances = [
            StarkInstance {
                air: &ternary_air,
                trace: &ternary,
                public_values: ternary_pubs.clone(),
                lookups: s_send,
            },
            StarkInstance {
                air: &fold_air,
                trace: &fold,
                public_values: fold_pubs.clone(),
                lookups: fold_lookups,
            },
            StarkInstance {
                air: &relation_air,
                trace: &relation,
                public_values: rel_pubs.clone(),
                lookups: r_recv,
            },
        ];
        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch");
        verify_batch(
            &config,
            &[ternary_air, fold_air, relation_air],
            &proof,
            &[ternary_pubs, fold_pubs, rel_pubs],
            &prover_data.common,
        )
        .expect("sampler→fold→relation must verify with both coeff and fold-E buses balanced");
    }

    /// **Full vertical slice — the whole pipeline for one coefficient stream, in ONE `prove_batch`.**
    /// Five instances across FOUR buses: sponge (Sends squeeze limbs) → squeeze-byte table (Receives
    /// limbs, Sends bytes) → ternary sampler (Receives bytes, Sends coefficient lifts) → Horner fold
    /// (Receives coefficients, Sends its evaluation `E`) → relation check (Receives `E`). `verify_batch`
    /// accepts iff ALL FOUR buses balance — so this pins, cryptographically and end-to-end, that the
    /// relation's witness term is the ζ-evaluation of a coefficient stream that is the exact 2-bit
    /// rejection sampling of the genuine `SHAKE(pk‖μ)` output. This is the composition depth the full
    /// #26 proof runs at (every ring element: SHAKE ⇒ sample ⇒ fold ⇒ relation); the full proof
    /// replicates it across all `e`/`f`/`g` components and all relations.
    #[test]
    fn compose_full_vertical_slice_prove_batch() {
        use lib_q_plonky_keccak_air::{
            NUM_KECCAK_COLS,
            NUM_ROUNDS,
        };

        use crate::logup_join::{
            COEFF_E_BUS,
            FOLD_E_BUS,
        };
        use crate::sampler::ternary_coeff_send_lookups_at;
        use crate::sponge::RATE_BYTES;
        use crate::sponge_air::{
            encap_preimage,
            generate_provable_sponge_trace,
            sponge_limb_send_lookups,
            sponge_public_values,
        };
        use crate::squeeze_byte::{
            generate_squeeze_byte_trace_partial,
            squeeze_byte_limb_receive_lookup,
            squeeze_byte_send_lookup,
        };
        use crate::zq::{
            Q,
            RelationCheckAir,
            generate_horner_trace,
            generate_relation_trace,
            horner_coeff_receive_lookups_at,
            horner_e_send_lookups_at,
            horner_public_values,
        };

        let pk = [0x21u8; 32];
        let mu = [0x7Eu8; 32];
        let input = encap_preimage(&pk, &mu);

        // n = 32 coefficients (power of two ⇒ fold height = n, no front padding).
        let n = 32usize;
        let bytes = shake256_xof(&input, 4096);
        let ternary = generate_ternary_trace(&bytes, n).expect("ternary trace");
        let consumed = active_rows(&ternary, SAMPLER_WIDTH, 0);

        // Sponge covers the consumed bytes (+ a block of slack); squeeze covers its full squeeze.
        let sponge = generate_provable_sponge_trace(&input, consumed + RATE_BYTES);
        let height = sponge.values.len() / NUM_KECCAK_COLS;
        let blocks = (0..height)
            .filter(|r| r % NUM_ROUNDS == NUM_ROUNDS - 1)
            .count();
        let full_limbs = blocks * (RATE_BYTES / 2);
        let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, consumed);

        // Coefficient lifts (reference 2-bit rejection sampling), fed to the fold low-order first.
        let mut lifts: Vec<u64> = Vec::new();
        let mut i = 0usize;
        while lifts.len() < n {
            let two = bytes[i] & 0b11;
            i += 1;
            if two < 3 {
                lifts.push((i64::from(two) - 1).rem_euclid(Q as i64) as u64);
            }
        }
        let zeta = 777_777u64;
        let (fold, e) = generate_horner_trace(&lifts, zeta).expect("horner trace");

        // Relation 1·w_0 + (q−E) ≡ 0, padded to height n.
        let rc = RelationCheckAir { num_terms: 1 };
        let (rm, rel_pubs) =
            generate_relation_trace(&[1], &[e], (Q - e) % Q).expect("relation trace");
        let rw = rm.width;
        let mut rvals = Vec::with_capacity(n * rw);
        rvals.extend_from_slice(&rm.values[0..rw]);
        for _ in 0..n - 1 {
            rvals.extend_from_slice(&rm.values[rw..2 * rw]);
        }
        let relation = RowMajorMatrix::new(rvals, rw);

        let airs = [
            EncProofAir::Sponge(ShakeSpongeAir { height }),
            EncProofAir::SqueezeByte(SqueezeByteAir),
            EncProofAir::Ternary(TernarySamplerAir { num_coeffs: n }),
            EncProofAir::HornerFold(HornerFoldAir),
            EncProofAir::RelationCheck(rc.clone()),
        ];

        // Per-instance lookups (aux columns kept distinct WITHIN each instance via col_base):
        let sponge_lookups = sponge_limb_send_lookups();
        let squeeze_lookups = Vec::from([
            squeeze_byte_send_lookup(),
            squeeze_byte_limb_receive_lookup(),
        ]);
        let mut ternary_lookups = Vec::from([ternary_receive_lookup()]); // byte Receive: col 0
        ternary_lookups.extend(ternary_coeff_send_lookups_at(0, 1)); // coeff Send: cols 1..5
        let mut fold_lookups = horner_coeff_receive_lookups_at(COEFF_E_BUS, 0); // cols 0..4
        fold_lookups.extend(horner_e_send_lookups_at(FOLD_E_BUS, 0, 0, 4)); // cols 4..8
        let relation_lookups = rc.relation_w_receive_lookups_at(FOLD_E_BUS, 0);

        let config = test_batch_config();
        let (global, prover_only) = build_preprocessed(&config, &airs);
        let common = CommonData::new(
            global,
            Vec::from([
                sponge_lookups.clone(),
                squeeze_lookups.clone(),
                ternary_lookups.clone(),
                fold_lookups.clone(),
                relation_lookups.clone(),
            ]),
        );
        let prover_data = ProverData {
            common,
            prover_only,
        };

        let sponge_pubs = sponge_public_values(&pk);
        let ternary_pubs = ternary_public_values(n);
        let fold_pubs = horner_public_values(zeta);
        let instances = [
            StarkInstance {
                air: &airs[0],
                trace: &sponge,
                public_values: sponge_pubs.clone(),
                lookups: sponge_lookups,
            },
            StarkInstance {
                air: &airs[1],
                trace: &squeeze,
                public_values: Vec::new(),
                lookups: squeeze_lookups,
            },
            StarkInstance {
                air: &airs[2],
                trace: &ternary,
                public_values: ternary_pubs.clone(),
                lookups: ternary_lookups,
            },
            StarkInstance {
                air: &airs[3],
                trace: &fold,
                public_values: fold_pubs.clone(),
                lookups: fold_lookups,
            },
            StarkInstance {
                air: &airs[4],
                trace: &relation,
                public_values: rel_pubs.clone(),
                lookups: relation_lookups,
            },
        ];

        let proof =
            prove_batch(&config, &instances, &prover_data).expect("prove_batch vertical slice");
        verify_batch(
            &config,
            &airs,
            &proof,
            &[sponge_pubs, Vec::new(), ternary_pubs, fold_pubs, rel_pubs],
            &prover_data.common,
        )
        .expect("the full SHAKE⇒sample⇒fold⇒relation slice must verify (all four buses balanced)");
    }

    /// **Zero-knowledge (hiding-FRI) round trip (task #32).** The join-3 fold→relation binding proven
    /// under the [`test_batch_config_zk`] **hiding** config (`is_zk() == 1`): the batch prover blinds
    /// every committed matrix with random codewords and randomizes the quotient, so the proof reveals
    /// nothing about the witness (the coefficients / `E` / μ) beyond the public statement, yet still
    /// verifies. This confirms the composition + Global lookups + the batch driver all work on the ZK
    /// code path — the config swap the production `prove`/`verify` will use to make μ zero-knowledge.
    #[test]
    fn compose_join3_zk_prove_batch() {
        use crate::logup_join::FOLD_E_BUS;
        use crate::zq::{
            Q,
            RelationCheckAir,
            generate_horner_trace,
            generate_relation_trace,
            horner_e_send_lookups_at,
            horner_public_values,
        };

        const H: usize = 32;
        let coeffs: Vec<u64> = (0..H as u64).map(|i| (i * 7 + 3) % Q).collect();
        let zeta = 424_242u64;
        let (fold, e) = generate_horner_trace(&coeffs, zeta).expect("horner trace");
        let fold_air = EncProofAir::HornerFold(HornerFoldAir);
        let fold_pubs = horner_public_values(zeta);

        let rc = RelationCheckAir { num_terms: 1 };
        let (rm, rel_pubs) =
            generate_relation_trace(&[1], &[e], (Q - e) % Q).expect("relation trace");
        let rw = rm.width;
        let mut rvals = Vec::with_capacity(H * rw);
        rvals.extend_from_slice(&rm.values[0..rw]);
        for _ in 0..H - 1 {
            rvals.extend_from_slice(&rm.values[rw..2 * rw]);
        }
        let relation = RowMajorMatrix::new(rvals, rw);
        let relation_air = EncProofAir::RelationCheck(rc.clone());

        let send = horner_e_send_lookups_at(FOLD_E_BUS, 0, 0, 0);
        let recv = rc.relation_w_receive_lookups_at(FOLD_E_BUS, 0);

        let config = test_batch_config_zk(); // hiding-FRI ZK config (is_zk == 1)
        let common = CommonData::new(None, Vec::from([send.clone(), recv.clone()]));
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };
        let instances = [
            StarkInstance {
                air: &fold_air,
                trace: &fold,
                public_values: fold_pubs.clone(),
                lookups: send,
            },
            StarkInstance {
                air: &relation_air,
                trace: &relation,
                public_values: rel_pubs.clone(),
                lookups: recv,
            },
        ];
        let proof = prove_batch(&config, &instances, &prover_data).expect("zk prove_batch");
        verify_batch(
            &config,
            &[fold_air, relation_air],
            &proof,
            &[fold_pubs, rel_pubs],
            &prover_data.common,
        )
        .expect("the zero-knowledge (hiding-FRI) proof must verify");
    }

    /// **R3b relation layer on a REAL ciphertext through `prove_batch` (task #26).** Proves the `v`
    /// equation `v = Σ_r t0_r·e_r + g + encode(μ) (mod X^N+1)` for a genuine `encapsulate_derand`
    /// ciphertext: `MU` folds evaluate `e_r(ζ)`, one evaluates `g(ζ)`, an `EncodeMuFold` evaluates
    /// `encode(μ)(ζ)`, one evaluates the quotient `H_b(ζ)`, and a `RelationCheckAir` binds all `MU + 3`
    /// fold results (join 3) into `Σ_j a_j·w_j + c ≡ 0 (mod q)` with the assembled public coefficients.
    /// `verify_batch` accepts iff the fold-E bus balances AND the relation holds — the relation half of
    /// the full proof, cryptographically enforced end-to-end on real witness data.
    #[test]
    fn compose_r3b_real_relation_prove_batch() {
        use lib_q_dkg::lattice::bdlop::MU;
        use lib_q_dkg::lattice::ring::{
            N,
            Rq,
        };
        use lib_q_plonky_lookup::Lookup;
        use lib_q_threshold_kem_lattice::kem::{
            encapsulate_derand,
            encode_msg,
            fo_expand_witness,
        };

        use crate::logup_join::FOLD_E_BUS;
        use crate::relation_assembly::{
            derive_zetas,
            r3b_public_coeffs,
            r3b_quotient_poly,
            rq_coeffs_zq,
        };
        use crate::zq::{
            EncodeMuFoldAir,
            RelationCheckAir,
            encode_mu_public_values,
            generate_encode_mu_trace,
            generate_horner_trace,
            generate_relation_trace,
            horner_e_send_lookups_at,
            horner_public_values,
        };

        let t0: Vec<Rq> = (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = (i as i64 * 17 + r as i64 * 5) % lib_q_dkg::lattice::ring::Q;
                }
                Rq::from_coeffs(c)
            })
            .collect();
        let mu = [0x3Cu8; 32];
        let ct = encapsulate_derand(&t0, &mu);
        let w = fo_expand_witness(&t0, &mu);

        let zeta = derive_zetas(&ct.to_bytes(), 1)[0];

        // Assemble R3b public coeffs + the quotient witness.
        let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
        let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
        let e_lifts: Vec<Vec<u64>> = w.e.iter().map(rq_coeffs_zq).collect();
        let e_ref: Vec<&[u64]> = e_lifts.iter().map(|v| v.as_slice()).collect();
        let v_z = rq_coeffs_zq(&ct.v);
        let g_z = rq_coeffs_zq(&w.g);
        let encode_z = rq_coeffs_zq(&encode_msg(&mu));
        let (a, c) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
        let hb =
            r3b_quotient_poly(&t0_cols, &e_ref, &g_z, &encode_z, &v_z, N).expect("R3b divisible");

        // Fold traces (each Sends its result E on FOLD_E at its relation-term position).
        let mut fold_traces = Vec::new();
        let mut fold_es = Vec::new();
        for e in &e_lifts {
            let (t, ev) = generate_horner_trace(e, zeta).expect("e fold");
            fold_traces.push(t);
            fold_es.push(ev);
        }
        let (g_trace, g_ev) = generate_horner_trace(&g_z, zeta).expect("g fold");
        let (enc_trace, enc_ev) = generate_encode_mu_trace(&mu, zeta).expect("encode fold");
        let (hb_trace, hb_ev) = generate_horner_trace(&hb, zeta).expect("hb fold");

        // Witness terms: E_0..E_{MU-1}, G, E_encode, HK_b.
        let mut w_terms = fold_es.clone();
        w_terms.push(g_ev);
        w_terms.push(enc_ev);
        w_terms.push(hb_ev);
        let l = MU + 3;
        assert_eq!(a.len(), l);
        assert_eq!(w_terms.len(), l);

        let rc = RelationCheckAir { num_terms: l };
        let (rm, rel_pubs) = generate_relation_trace(&a, &w_terms, c).expect("R3b relation holds");
        let rw = rm.width;
        let rh = 64usize;
        let mut rvals = Vec::with_capacity(rh * rw);
        rvals.extend_from_slice(&rm.values[0..rw]);
        for _ in 0..rh - 1 {
            rvals.extend_from_slice(&rm.values[rw..2 * rw]);
        }
        let relation = RowMajorMatrix::new(rvals, rw);

        // Enum-wrapped AIRs: MU HornerFold (e) + 1 (g) + 1 EncodeMuFold + 1 HornerFold (hb) + relation.
        let mut airs: Vec<EncProofAir> = Vec::new();
        for _ in 0..MU {
            airs.push(EncProofAir::HornerFold(HornerFoldAir));
        }
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // g
        airs.push(EncProofAir::EncodeMuFold(EncodeMuFoldAir)); // encode
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // hb
        airs.push(EncProofAir::RelationCheck(rc.clone()));

        // Per-instance lookups: each fold Sends E at its term (col_base 0); relation Receives all terms.
        let mut all_lookups: Vec<Vec<Lookup<ConfigVal>>> = Vec::new();
        for term in 0..l {
            all_lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, 0, term, 0));
        }
        all_lookups.push(rc.relation_w_receive_lookups_at(FOLD_E_BUS, 0));

        // Traces + public values in AIR order.
        let zeta_pubs = horner_public_values(zeta);
        let mut traces: Vec<&RowMajorMatrix<ConfigVal>> = Vec::new();
        let mut pubs: Vec<Vec<ConfigVal>> = Vec::new();
        for t in &fold_traces {
            traces.push(t);
            pubs.push(zeta_pubs.clone());
        }
        traces.push(&g_trace);
        pubs.push(zeta_pubs.clone());
        traces.push(&enc_trace);
        pubs.push(encode_mu_public_values(zeta));
        traces.push(&hb_trace);
        pubs.push(zeta_pubs.clone());
        traces.push(&relation);
        pubs.push(rel_pubs.clone());

        let config = test_batch_config();
        let common = CommonData::new(None, all_lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };
        let instances: Vec<StarkInstance<'_, TestConfig, EncProofAir>> = airs
            .iter()
            .zip(traces.iter())
            .zip(pubs.iter())
            .zip(all_lookups.iter())
            .map(|(((air, trace), pv), lookups)| StarkInstance {
                air,
                trace,
                public_values: pv.clone(),
                lookups: lookups.clone(),
            })
            .collect();

        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch R3b");
        verify_batch(&config, &airs, &proof, &pubs, &prover_data.common)
            .expect("the R3b relation over the real ciphertext must verify (fold-E bus balanced)");
    }

    /// **Multi-fold-from-one-sampler + fan-out (the last full-assembly wiring, task #26).** ONE ternary
    /// sampler emits `2n` coefficients; TWO folds Receive their halves (join 2 with per-ring-element
    /// bases `0` and `n`), and EACH fold fans its result out to TWO relations (join 3, distinct
    /// fold-E bases + `col_base`), which both Receive `[E_0, E_1]`. This is exactly how the full proof
    /// shares one `e`-sampler across the `MU` `e_r` folds and each `e_r` across all `KAPPA + 1`
    /// relations. `verify_batch` accepts iff the coeff bus AND both fold-E buses balance AND both
    /// relations hold — validating the aux-column composition (each fold carries a join-2 receive on
    /// cols 0..4 plus two join-3 sends on cols 4..8 and 8..12) at full breadth.
    #[test]
    fn compose_multifold_fanout_prove_batch() {
        use crate::logup_join::{
            COEFF_E_BUS,
            FOLD_E_BUS,
        };
        use crate::sampler::ternary_coeff_send_lookups_at;
        use crate::zq::{
            Q,
            RelationCheckAir,
            generate_horner_trace,
            generate_relation_trace,
            horner_coeff_receive_lookups_at,
            horner_e_send_lookups_at,
            horner_public_values,
        };

        let bytes = shake256_xof(b"libq/compose/multifold", 4096);
        let n = 32usize; // per-fold coefficient count (power of two)

        let ternary = generate_ternary_trace(&bytes, 2 * n).expect("ternary trace");
        let ternary_pubs = ternary_public_values(2 * n);

        let mut lifts: Vec<u64> = Vec::new();
        let mut i = 0usize;
        while lifts.len() < 2 * n {
            let two = bytes[i] & 0b11;
            i += 1;
            if two < 3 {
                lifts.push((i64::from(two) - 1).rem_euclid(Q as i64) as u64);
            }
        }
        let zeta = 313_131u64;
        let (fold0, e0) = generate_horner_trace(&lifts[0..n], zeta).expect("e0 fold");
        let (fold1, e1) = generate_horner_trace(&lifts[n..2 * n], zeta).expect("e1 fold");
        let fold_pubs = horner_public_values(zeta);

        // Two relations over [E_0, E_1] with distinct public coefficients (both hold by construction).
        let qq = Q as u128;
        let (ea, eb) = (e0 as u128, e1 as u128);
        let ca = ((qq - (ea + eb) % qq) % qq) as u64;
        let cb = ((qq - (2 * ea + 3 * eb) % qq) % qq) as u64;
        let rc = RelationCheckAir { num_terms: 2 };
        let base_a = 0u64;
        let base_b = 16u64;
        let build_rel = |a: &[u64], c: u64| {
            let (rm, pubs) = generate_relation_trace(a, &[e0, e1], c).expect("relation");
            let rww = rm.width;
            let mut rvals = Vec::with_capacity(64 * rww);
            rvals.extend_from_slice(&rm.values[0..rww]);
            for _ in 0..63 {
                rvals.extend_from_slice(&rm.values[rww..2 * rww]);
            }
            (RowMajorMatrix::new(rvals, rww), pubs)
        };
        let (rel_a, rel_a_pubs) = build_rel(&[1, 1], ca);
        let (rel_b, rel_b_pubs) = build_rel(&[2, 3], cb);

        let airs = [
            EncProofAir::Ternary(TernarySamplerAir { num_coeffs: 2 * n }),
            EncProofAir::HornerFold(HornerFoldAir), // e_0
            EncProofAir::HornerFold(HornerFoldAir), // e_1
            EncProofAir::RelationCheck(rc.clone()), // relation A
            EncProofAir::RelationCheck(rc.clone()), // relation B
        ];

        // Fold 0: join-2 receive (cols 0..4) + join-3 send to A term 0 (cols 4..8) + to B term 0 (8..12).
        let mut f0 = horner_coeff_receive_lookups_at(COEFF_E_BUS, 0);
        f0.extend(horner_e_send_lookups_at(FOLD_E_BUS, base_a, 0, 4));
        f0.extend(horner_e_send_lookups_at(FOLD_E_BUS, base_b, 0, 8));
        // Fold 1: receive at base n·4 (its coefficient half) + send to A term 1 + B term 1.
        let mut f1 = horner_coeff_receive_lookups_at(COEFF_E_BUS, (n as u64) * 4);
        f1.extend(horner_e_send_lookups_at(FOLD_E_BUS, base_a, 1, 4));
        f1.extend(horner_e_send_lookups_at(FOLD_E_BUS, base_b, 1, 8));

        let all_lookups = Vec::from([
            ternary_coeff_send_lookups_at(0, 0),
            f0,
            f1,
            rc.relation_w_receive_lookups_at(FOLD_E_BUS, base_a),
            rc.relation_w_receive_lookups_at(FOLD_E_BUS, base_b),
        ]);
        let traces = [&ternary, &fold0, &fold1, &rel_a, &rel_b];
        let pubs = [
            ternary_pubs,
            fold_pubs.clone(),
            fold_pubs,
            rel_a_pubs,
            rel_b_pubs,
        ];

        let config = test_batch_config();
        let common = CommonData::new(None, all_lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only: ProverOnlyData::empty(),
        };
        let instances: Vec<StarkInstance<'_, TestConfig, EncProofAir>> = airs
            .iter()
            .zip(traces.iter())
            .zip(pubs.iter())
            .zip(all_lookups.iter())
            .map(|(((air, trace), pv), lookups)| StarkInstance {
                air,
                trace,
                public_values: pv.clone(),
                lookups: lookups.clone(),
            })
            .collect();

        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch multifold");
        verify_batch(&config, &airs, &proof, &pubs, &prover_data.common).expect(
            "one sampler → two folds → (fan-out) two relations must verify (all buses balanced)",
        );
    }

    /// **Capstone: the WHOLE composition in one `prove_batch` (task #26).** Every layer and every join
    /// at once: sponge (Sends limbs) ⇒ squeeze-byte (Receives limbs, Sends bytes) ⇒ ternary sampler
    /// (Receives bytes [join 1], Sends `2n` coeff lifts [join 2]) ⇒ TWO folds (Receive their coeff
    /// halves [join 2], each fans its `E` out to TWO relations [join 3]) ⇒ two relations (Receive
    /// `[E_0, E_1]`). Seven instances across FOUR buses (SQUEEZE_LIMB, XOF_STREAM, COEFF_E, FOLD_E);
    /// `verify_batch` accepts iff ALL balance AND both relations hold. This is the exact instance/bus/
    /// aux-column shape the production proof runs at N=1024 (one `e`-sampler ⇒ `MU` folds ⇒ each fold
    /// ⇒ all relations), proven here end-to-end at reduced scale — the full-assembly wiring, complete.
    #[test]
    fn compose_full_stack_prove_batch() {
        use lib_q_plonky_keccak_air::{
            NUM_KECCAK_COLS,
            NUM_ROUNDS,
        };

        use crate::logup_join::{
            COEFF_E_BUS,
            FOLD_E_BUS,
        };
        use crate::sampler::ternary_coeff_send_lookups_at;
        use crate::sponge::RATE_BYTES;
        use crate::sponge_air::{
            encap_preimage,
            generate_provable_sponge_trace,
            sponge_limb_send_lookups,
            sponge_public_values,
        };
        use crate::squeeze_byte::{
            generate_squeeze_byte_trace_partial,
            squeeze_byte_limb_receive_lookup,
            squeeze_byte_send_lookup,
        };
        use crate::zq::{
            Q,
            RelationCheckAir,
            generate_horner_trace,
            generate_relation_trace,
            horner_coeff_receive_lookups_at,
            horner_e_send_lookups_at,
            horner_public_values,
        };

        let pk = [0x5Du8; 32];
        let mu = [0x2Bu8; 32];
        let input = encap_preimage(&pk, &mu);

        let n = 32usize; // per-fold coefficient count; sampler emits 2n
        let bytes = shake256_xof(&input, 4096);
        let ternary = generate_ternary_trace(&bytes, 2 * n).expect("ternary trace");
        let consumed = active_rows(&ternary, SAMPLER_WIDTH, 0);

        let sponge = generate_provable_sponge_trace(&input, consumed + RATE_BYTES);
        let height = sponge.values.len() / NUM_KECCAK_COLS;
        let blocks = (0..height)
            .filter(|r| r % NUM_ROUNDS == NUM_ROUNDS - 1)
            .count();
        let full_limbs = blocks * (RATE_BYTES / 2);
        let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, consumed);

        let mut lifts: Vec<u64> = Vec::new();
        let mut i = 0usize;
        while lifts.len() < 2 * n {
            let two = bytes[i] & 0b11;
            i += 1;
            if two < 3 {
                lifts.push((i64::from(two) - 1).rem_euclid(Q as i64) as u64);
            }
        }
        let zeta = 909_090u64;
        let (fold0, e0) = generate_horner_trace(&lifts[0..n], zeta).expect("e0 fold");
        let (fold1, e1) = generate_horner_trace(&lifts[n..2 * n], zeta).expect("e1 fold");
        let fold_pubs = horner_public_values(zeta);

        let qq = Q as u128;
        let (ea, eb) = (e0 as u128, e1 as u128);
        let ca = ((qq - (ea + eb) % qq) % qq) as u64;
        let cb = ((qq - (2 * ea + 3 * eb) % qq) % qq) as u64;
        let rc = RelationCheckAir { num_terms: 2 };
        let (base_a, base_b) = (0u64, 16u64);
        let build_rel = |a: &[u64], c: u64| {
            let (rm, pubs) = generate_relation_trace(a, &[e0, e1], c).expect("relation");
            let rww = rm.width;
            let mut rvals = Vec::with_capacity(64 * rww);
            rvals.extend_from_slice(&rm.values[0..rww]);
            for _ in 0..63 {
                rvals.extend_from_slice(&rm.values[rww..2 * rww]);
            }
            (RowMajorMatrix::new(rvals, rww), pubs)
        };
        let (rel_a, rel_a_pubs) = build_rel(&[1, 1], ca);
        let (rel_b, rel_b_pubs) = build_rel(&[2, 3], cb);

        let airs = [
            EncProofAir::Sponge(ShakeSpongeAir { height }),
            EncProofAir::SqueezeByte(SqueezeByteAir),
            EncProofAir::Ternary(TernarySamplerAir { num_coeffs: 2 * n }),
            EncProofAir::HornerFold(HornerFoldAir), // e_0
            EncProofAir::HornerFold(HornerFoldAir), // e_1
            EncProofAir::RelationCheck(rc.clone()), // relation A
            EncProofAir::RelationCheck(rc.clone()), // relation B
        ];

        let sponge_lookups = sponge_limb_send_lookups();
        let squeeze_lookups = Vec::from([
            squeeze_byte_send_lookup(),
            squeeze_byte_limb_receive_lookup(),
        ]);
        let mut ternary_lookups = Vec::from([ternary_receive_lookup()]); // byte Receive: col 0
        ternary_lookups.extend(ternary_coeff_send_lookups_at(0, 1)); // coeff Send: cols 1..5
        let mut f0 = horner_coeff_receive_lookups_at(COEFF_E_BUS, 0);
        f0.extend(horner_e_send_lookups_at(FOLD_E_BUS, base_a, 0, 4));
        f0.extend(horner_e_send_lookups_at(FOLD_E_BUS, base_b, 0, 8));
        let mut f1 = horner_coeff_receive_lookups_at(COEFF_E_BUS, (n as u64) * 4);
        f1.extend(horner_e_send_lookups_at(FOLD_E_BUS, base_a, 1, 4));
        f1.extend(horner_e_send_lookups_at(FOLD_E_BUS, base_b, 1, 8));

        let all_lookups = Vec::from([
            sponge_lookups.clone(),
            squeeze_lookups.clone(),
            ternary_lookups.clone(),
            f0.clone(),
            f1.clone(),
            rc.relation_w_receive_lookups_at(FOLD_E_BUS, base_a),
            rc.relation_w_receive_lookups_at(FOLD_E_BUS, base_b),
        ]);
        let traces = [&sponge, &squeeze, &ternary, &fold0, &fold1, &rel_a, &rel_b];
        let sponge_pubs = sponge_public_values(&pk);
        let ternary_pubs = ternary_public_values(2 * n);
        let pubs = [
            sponge_pubs,
            Vec::new(),
            ternary_pubs,
            fold_pubs.clone(),
            fold_pubs,
            rel_a_pubs,
            rel_b_pubs,
        ];

        let config = test_batch_config();
        let (global, prover_only) = build_preprocessed(&config, &airs);
        let common = CommonData::new(global, all_lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only,
        };
        let instances: Vec<StarkInstance<'_, TestConfig, EncProofAir>> = airs
            .iter()
            .zip(traces.iter())
            .zip(pubs.iter())
            .zip(all_lookups.iter())
            .map(|(((air, trace), pv), lookups)| StarkInstance {
                air,
                trace,
                public_values: pv.clone(),
                lookups: lookups.clone(),
            })
            .collect();

        let proof = prove_batch(&config, &instances, &prover_data).expect("prove_batch full stack");
        verify_batch(&config, &airs, &proof, &pubs, &prover_data.common).expect(
            "the full SHAKE⇒sample⇒multi-fold⇒fan-out⇒relations stack must verify (all buses balanced)",
        );
    }

    /// **Real-scale byte-provenance ⇒ R3b on a genuine ciphertext at N=1024 (task #26).** The `v`
    /// equation proven for a real `encapsulate_derand` ciphertext with the `e_r` fold coefficients
    /// **byte-bound to the SHAKE sponge**: sponge (over the real FO preimage `DOM ‖ pk_digest ‖ μ`,
    /// covering `e`'s bytes) ⇒ squeeze ⇒ e-sampler (`MU·N` coeffs, join 1) ⇒ `MU` `e_r` folds (join 2
    /// bind to the sampler at per-ring-element bases) ⇒ join 3 into the R3b relation (with `g`, encode,
    /// and the quotient fed directly). `verify_batch` accepts iff the sampler consumed the genuine
    /// SHAKE output AND those coefficients satisfy `v = Σ t0_r·e_r + g + encode(μ)` at ζ — the full
    /// byte-provenance⇒relation composition at PRODUCTION dimension (`N = 1024`), for the `e` component.
    /// (Only `e`'s ~8 KB is squeezed here to keep the sponge tractable; binding `f`/`g` needs the full
    /// ~90 KB sponge — the same structure, heavier.)
    #[test]
    fn compose_r3b_e_provenance_real_ciphertext() {
        use lib_q_dkg::lattice::bdlop::MU;
        use lib_q_dkg::lattice::ring::{
            N,
            Rq,
        };
        use lib_q_plonky_keccak_air::{
            NUM_KECCAK_COLS,
            NUM_ROUNDS,
        };
        use lib_q_plonky_lookup::Lookup;
        use lib_q_threshold_kem_lattice::kem::{
            encapsulate_derand,
            encode_msg,
            fo_expand_witness,
        };

        use crate::logup_join::{
            COEFF_E_BUS,
            FOLD_E_BUS,
        };
        use crate::relation_assembly::{
            derive_zetas,
            r3b_public_coeffs,
            r3b_quotient_poly,
            rq_coeffs_zq,
        };
        use crate::sampler::ternary_coeff_send_lookups_at;
        use crate::sponge::RATE_BYTES;
        use crate::sponge_air::{
            encap_preimage,
            generate_provable_sponge_trace,
            sponge_limb_send_lookups,
            sponge_public_values,
        };
        use crate::squeeze_byte::{
            generate_squeeze_byte_trace_partial,
            squeeze_byte_limb_receive_lookup,
            squeeze_byte_send_lookup,
        };
        use crate::zq::{
            EncodeMuFoldAir,
            RelationCheckAir,
            encode_mu_public_values,
            generate_encode_mu_trace,
            generate_horner_trace,
            generate_relation_trace,
            horner_coeff_receive_lookups_at,
            horner_e_send_lookups_at,
            horner_public_values,
        };

        let t0: Vec<Rq> = (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = (i as i64 * 31 + r as i64 * 7) % lib_q_dkg::lattice::ring::Q;
                }
                Rq::from_coeffs(c)
            })
            .collect();
        let mu = [0x6Bu8; 32];
        let ct = encapsulate_derand(&t0, &mu);
        let w = fo_expand_witness(&t0, &mu);
        let input = encap_preimage(&w.pk_digest, &mu);

        // e-sampler over the real XOF (MU·N ternary coeffs); sponge covers e's consumed bytes.
        let bytes = shake256_xof(&input, MU * N * 2 + 4096);
        let e_sampler = generate_ternary_trace(&bytes, MU * N).expect("e sampler");
        let consumed = active_rows(&e_sampler, SAMPLER_WIDTH, 0);
        let sponge = generate_provable_sponge_trace(&input, consumed + RATE_BYTES);
        let height = sponge.values.len() / NUM_KECCAK_COLS;
        let blocks = (0..height)
            .filter(|r| r % NUM_ROUNDS == NUM_ROUNDS - 1)
            .count();
        let full_limbs = blocks * (RATE_BYTES / 2);
        let squeeze = generate_squeeze_byte_trace_partial(&input, full_limbs, consumed);

        let zeta = derive_zetas(&ct.to_bytes(), 1)[0];

        // R3b assembly.
        let t0_cols_owned: Vec<Vec<u64>> = t0.iter().map(rq_coeffs_zq).collect();
        let t0_cols: Vec<&[u64]> = t0_cols_owned.iter().map(|v| v.as_slice()).collect();
        let e_lifts: Vec<Vec<u64>> = w.e.iter().map(rq_coeffs_zq).collect();
        let e_ref: Vec<&[u64]> = e_lifts.iter().map(|v| v.as_slice()).collect();
        let v_z = rq_coeffs_zq(&ct.v);
        let g_z = rq_coeffs_zq(&w.g);
        let encode_z = rq_coeffs_zq(&encode_msg(&mu));
        let (a, c) = r3b_public_coeffs(&t0_cols, &v_z, zeta, N);
        let hb =
            r3b_quotient_poly(&t0_cols, &e_ref, &g_z, &encode_z, &v_z, N).expect("R3b divisible");

        // e_r folds (byte-bound); g / encode / hb folds (fed directly).
        let mut e_fold_traces = Vec::new();
        let mut w_terms = Vec::new();
        for e in &e_lifts {
            let (t, ev) = generate_horner_trace(e, zeta).expect("e fold");
            e_fold_traces.push(t);
            w_terms.push(ev);
        }
        let (g_trace, g_ev) = generate_horner_trace(&g_z, zeta).expect("g fold");
        let (enc_trace, enc_ev) = generate_encode_mu_trace(&mu, zeta).expect("encode fold");
        let (hb_trace, hb_ev) = generate_horner_trace(&hb, zeta).expect("hb fold");
        w_terms.push(g_ev);
        w_terms.push(enc_ev);
        w_terms.push(hb_ev);
        let l = MU + 3;

        let rc = RelationCheckAir { num_terms: l };
        let (rm, rel_pubs) = generate_relation_trace(&a, &w_terms, c).expect("R3b relation holds");
        let rw = rm.width;
        let mut rvals = Vec::with_capacity(64 * rw);
        rvals.extend_from_slice(&rm.values[0..rw]);
        for _ in 0..63 {
            rvals.extend_from_slice(&rm.values[rw..2 * rw]);
        }
        let relation = RowMajorMatrix::new(rvals, rw);

        // AIRs: sponge, squeeze, e-sampler, MU e-folds, g, encode, hb, relation.
        let mut airs = Vec::from([
            EncProofAir::Sponge(ShakeSpongeAir { height }),
            EncProofAir::SqueezeByte(SqueezeByteAir),
            EncProofAir::Ternary(TernarySamplerAir { num_coeffs: MU * N }),
        ]);
        for _ in 0..MU {
            airs.push(EncProofAir::HornerFold(HornerFoldAir));
        }
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // g
        airs.push(EncProofAir::EncodeMuFold(EncodeMuFoldAir)); // encode
        airs.push(EncProofAir::HornerFold(HornerFoldAir)); // hb
        airs.push(EncProofAir::RelationCheck(rc.clone()));

        // Lookups.
        let mut lookups: Vec<Vec<Lookup<ConfigVal>>> = Vec::new();
        lookups.push(sponge_limb_send_lookups());
        lookups.push(Vec::from([
            squeeze_byte_send_lookup(),
            squeeze_byte_limb_receive_lookup(),
        ]));
        let mut e_samp = Vec::from([ternary_receive_lookup()]); // byte Receive (col 0)
        e_samp.extend(ternary_coeff_send_lookups_at(0, 1)); // coeff Send (cols 1..5)
        lookups.push(e_samp);
        for (r, _) in e_lifts.iter().enumerate() {
            // e_r fold: join-2 receive at base r·N·4 (cols 0..4) + join-3 send to R3b term r (cols 4..8).
            let mut fl = horner_coeff_receive_lookups_at(COEFF_E_BUS, (r as u64) * (N as u64) * 4);
            fl.extend(horner_e_send_lookups_at(FOLD_E_BUS, 0, r, 4));
            lookups.push(fl);
        }
        lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, 0, MU, 0)); // g → term MU
        lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, 0, MU + 1, 0)); // encode → term MU+1
        lookups.push(horner_e_send_lookups_at(FOLD_E_BUS, 0, MU + 2, 0)); // hb → term MU+2
        lookups.push(rc.relation_w_receive_lookups_at(FOLD_E_BUS, 0));

        // Traces + public values.
        let zeta_pubs = horner_public_values(zeta);
        let mut traces: Vec<&RowMajorMatrix<ConfigVal>> =
            Vec::from([&sponge, &squeeze, &e_sampler]);
        let mut pubs: Vec<Vec<ConfigVal>> = Vec::from([
            sponge_public_values(&[0u8; 32]),
            Vec::new(),
            ternary_public_values(MU * N),
        ]);
        // Note: the sponge's pk_digest public values are a *verifier obligation* (build from
        // ct.pk_digest); here they're arbitrary since we don't assert pk-binding in this composition
        // test — the join balances (byte provenance) are the property under test.
        pubs[0] = sponge_public_values(&w.pk_digest);
        for t in &e_fold_traces {
            traces.push(t);
            pubs.push(zeta_pubs.clone());
        }
        traces.push(&g_trace);
        pubs.push(zeta_pubs.clone());
        traces.push(&enc_trace);
        pubs.push(encode_mu_public_values(zeta));
        traces.push(&hb_trace);
        pubs.push(zeta_pubs.clone());
        traces.push(&relation);
        pubs.push(rel_pubs);

        let config = test_batch_config();
        let (global, prover_only) = build_preprocessed(&config, &airs);
        let common = CommonData::new(global, lookups.clone());
        let prover_data = ProverData {
            common,
            prover_only,
        };
        let instances: Vec<StarkInstance<'_, TestConfig, EncProofAir>> = airs
            .iter()
            .zip(traces.iter())
            .zip(pubs.iter())
            .zip(lookups.iter())
            .map(|(((air, trace), pv), lk)| StarkInstance {
                air,
                trace,
                public_values: pv.clone(),
                lookups: lk.clone(),
            })
            .collect();

        let proof =
            prove_batch(&config, &instances, &prover_data).expect("prove_batch e-provenance R3b");
        verify_batch(&config, &airs, &proof, &pubs, &prover_data.common).expect(
            "real-ciphertext R3b with e byte-bound to SHAKE must verify at N=1024 (all buses balanced)",
        );
    }
}
