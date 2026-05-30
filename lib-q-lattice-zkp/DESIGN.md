# Module-lattice ZKP (`lib-q-lattice-zkp`)

Concrete ring / NTT code is shared with ML-DSA via [`lib-q-ring`](../lib-q-ring). For how this differs from the STARK stack (`lib-q-zkp`), see [docs/zkp-implementation.md](../docs/zkp-implementation.md).

This crate is the integration surface for **BLNS-style** anonymous credentials over module lattices. **Wire v0** freezes profiles, canonical encodings, and exportable KAT fixtures for interoperable prove/verify: QROM committed-first-message Fiat–Shamir, issuer-keyed blind issuance, and PVTN Merkle-index / clearance privacy on the wire. External security review and explicit NIST security-category parameter pinning remain prerequisites for high-assurance production deployment; see [SECURITY.md](../SECURITY.md).

## 1. Public parameters

- **Ring / module:** degree-`n` negacyclic ring `R_q`, module rank `k`, modulus `q` matching the operational ML-DSA/ML-KEM deployment (composition is an engineering constraint, not a mathematical one).
- **Ajtai commitment:** public matrix `A ∈ R_q^{m×(k+ℓ)}`, message `m ∈ R_q^k`, randomness `r ∈ R_q^ℓ`, commitment `c = A · (r ‖ m)`.

Binding reduces to **Module-SIS**; hiding to **Module-LWE** for suitable noise widths.

## 2. Proof goals (sigma layer)

1. **Opening:** given `c`, prove knowledge of `(m, r)` consistent with the Ajtai relation.
2. **Linear relations in NTT domain:** prove inner products / linear maps applied to committed vectors without revealing witnesses—this is where NTT-domain linear algebra composes with ML-DSA’s internal representation.
3. **Norm / range certificates:** coefficient-wise bounds compatible with ML-DSA rejection analysis (γ₁, γ₂, β).

Challenges are drawn from a **FIPS 204–compatible** ternary distribution (fixed Hamming weight) so that Fiat–Shamir transcripts can be composed with ML-DSA challenge hashing where required.

**Security model:** Fiat–Shamir challenges use a **committed-first-message** transform (`fs_w_digest` over canonical `w` bytes before `SHAKE256(ctx ‖ w_digest)`). Security is stated in the **Quantum Random Oracle Model (QROM)** for this transform; see [SECURITY.md](../SECURITY.md#random-oracle-model-vs-quantum-random-oracle-model).

## 3. Amortisation (batch presentations)

The `AmortisationBudget` type models transcript growth for multi-attribute presentations. A concrete BLNS aggregator would:

- hash-commit to a batch of attribute openings,
- run a single permutation argument or aggregated Σ-protocol round,
- produce one `AmortisedProof` blob per batch instead of per attribute.

## 4. Implementation status

The stack below is implemented on wire v0 and covered by unit tests inside this
crate plus the cross-crate
[`privacy_protocol_integration_tests`](../lib-q/tests/privacy_protocol_integration_tests.rs).

| Layer | Module | Status |
|-------|--------|--------|
| Concrete `RingParams` (`n=256`, configurable `k`, `q` from `lib-q-ring`) | [`params.rs`](src/params.rs) | wire v0 |
| Serialized `AjtaiCommitmentKey` and deterministic `commit` | [`commitment.rs`](src/commitment.rs) | wire v0 |
| Σ-protocol opening prover/verifier with rejection sampling | [`sigma/opening.rs`](src/sigma/opening.rs) | wire v0 (QROM FS) |
| Σ-protocol linear-relation prover/verifier | [`sigma/linear.rs`](src/sigma/linear.rs) | wire v0 |
| Infinity-norm certificate (CRT-packed) | [`sigma/norm.rs`](src/sigma/norm.rs) | wire v0 |
| Challenge derivation hooked to SHAKE256 (FIPS 204 ternary ball) | [`challenge.rs`](src/challenge.rs) | wire v0 |
| Batch amortisation over multiple openings | [`sigma/amortise.rs`](src/sigma/amortise.rs) | wire v0 |
| Nullifier-bound openings + uniqueness amortisation labels | [`sigma/uniqueness.rs`](src/sigma/uniqueness.rs) | wire v0 |
| Witness-derived nullifier + witness-bound opening proofs | [`sigma/uniqueness.rs`](src/sigma/uniqueness.rs) | wire v0 |
| Hierarchical Merkle membership + level-tagged opening | [`sigma/hierarchical.rs`](src/sigma/hierarchical.rs) | wire v0 |
| PVTN private membership (hidden index + clearance on wire) | [`sigma/hierarchical.rs`](src/sigma/hierarchical.rs) | wire v0 |

### 4.1 PVTN private membership (v0 privacy)

[`prove_private_membership`](src/sigma/hierarchical.rs) / [`verify_private_membership`](src/sigma/hierarchical.rs) implement wire v0 PVTN with:

- **Hidden Merkle position:** wire carries `path_index_commitment` (32 B) instead of direction bits; verifiers recover the leaf index by search (`recover_path_index`, depth cap 16).
- **Hidden clearance:** wire omits plaintext `clearance_level` and margin; verifiers search `L ∈ [min_clearance, min_clearance + β]` via `recover_clearance_level` to match `leaf_digest`.
- A [`CrtPackedNormProof`](src/sigma/norm.rs) certifies the packed margin in coefficient 0; the decoded proof struct still exposes `clearance_level` for verifier-side opening checks (not on the wire).

## 5. Blind issuance ([`blind.rs`](src/blind.rs))

`BlindIssuance::request → issuer_sign → finalize → verify` orchestrates
issuer-keyed homomorphic blinding over Ajtai commitments (not Chaum blind RSA):

1. The user samples a blinding opening, computes
   `Com_blinded = Com(user_opening + blind_opening)`, and sends only
   `Com_blinded` to the issuer.
2. The issuer signs an attestation by running `prove_opening` on its own commitment
   under a Fiat-Shamir context that absorbs `Com_blinded` bytes. The issuer never
   sees the user's secret token fields.
3. `finalize` aggregates user and blind openings into the unblinded `token_opening`
   that opens `Com_blinded`.
4. `verify` re-checks `commit(token_opening) == Com_blinded` and the issuer
   attestation.

The construction is **not** Chaum-style blind RSA. [`BlindIssuerKeypair::sample_issuer_keyed`](src/blind.rs)
and [`BlindSignature`](src/blind.rs) bind [`blind_message_digest`](src/blind.rs) into the issuer
Fiat–Shamir context. Wire kind `0x08` carries `issuer_params_digest`. See
[`BLIND_ISSUANCE.md`](BLIND_ISSUANCE.md).

## 6. Anonymous tokens ([`token.rs`](src/token.rs))

`AnonymousToken` packages a public commitment, an opening proof, and three header
fields (32-byte serial, 16-byte origin tag, 8-byte little-endian epoch) that the
verifier can use for application-layer replay tracking. `opening_from_token_fields`
deterministically packs the header into the first message polynomial of an
`AjtaiOpening` so that a single Σ-protocol proof simultaneously certifies
"I know an opening for `Com`" and "the opening encodes header `(serial, origin,
epoch)`".

`SpendingProof = (serial, opening_proof)` is the on-the-wire spending payload.
`SpendingProof::verify` runs the opening verifier against the token's commitment
and rejects if the carried serial does not match the verifier's expected serial.
Application registries reject double-spends by serial, since `AnonymousToken::spend`
reuses the same opening proof and the same serial across calls.

## 7. Non-goals (this repository)

- Replacing or emulating **hash-based STARKs** (`lib-q-zkp`): lattice relations are
  native here; arithmetised hash FRI is out of scope.
- **Independent third-party audit** and **side-channel laboratory certification** of the full BLNS stack (see [SECURITY.md](../SECURITY.md)).
- Pinning a formal **NIST security category** (e.g. ML-DSA-65 equivalence) beyond the current ML-DSA-aligned field geometry — wire v0 uses frozen pilot dimensions until product policy selects a category.

## 8. Frozen wire profile (`LatticeZkpProfileV0`)

Frozen v0 profiles live in [`src/profile.rs`](src/profile.rs):

| Profile id | Use case | `(k, l)` | Merkle depth cap | Wire budget |
|-----------:|----------|----------|------------------|------------:|
| 1 | PVTN private membership | `(1, 1)` | 16 | 4096 B |
| 2 | Anonymous token spend | `(2, 1)` | — | 125 KiB |
| 3 | Selective disclosure / amortised openings | `(2, 1)` | — | 125 KiB |

Security target: **Module-SIS** binding and **Module-LWE** hiding over `R_q` with `n = 256`, `q = 8_380_417` (ML-DSA field). Opening Fiat–Shamir uses the committed-first-message transform analyzed in the **QROM** (see [SECURITY.md](../SECURITY.md)).

The legacy dev pilot `AjtaiParameters::new(2, 1)` with raw `i32` coefficient serialization in [`serialize.rs`](src/serialize.rs) remains for internal tests only; production wire traffic uses [`lattice_zkp_wire_v0`](src/wire/mod.rs).

## 9. Wire format (`lattice_zkp_wire_v0`)

Canonical on-wire layout:

```text
[version=0][profile_id][proof_kind][payload_len u16 LE][payload…]
```

Payloads use compact bit-packed polynomials (`23` bits per `R_q` coefficient for masks; bounded bias packing for `z`). `MAX_WIRE_BYTES` guards reject oversize or truncated input before parsing secrets.

PVTN bundles omit the credential commitment on the wire (verifier supplies it as a public input) and encode clearance margin as a bounded integer instead of a full witness polynomial.

KAT fixtures: [`tests/vectors/`](tests/vectors/) — copy into downstream conformance corpora when pinning a release.

### Amortisation budget (measured vs legacy pilot)

[`AmortisationBudget::selective_disclosure_v0_measured`](src/budget.rs) derives per-attribute bytes from real
`encode_opening_proof_v0` bodies under profile id 3. The legacy
[`AmortisationBudget::mldsa65_pilot`](src/budget.rs) constant (6304 B/attribute) is retained only for
regression tests; measured v0 sizes are strictly lower and gate the 3-attribute ≤ 125 KiB CI scenario.

## 10. Wire v0 freeze (2026-05)

Measured KAT sizes under profile ids 1–3: PVTN **2558 B** (budget 4096 B), token opening **3977 B**, spending **4009 B** (presentation budget 131072 B).

Regenerate vectors: `cargo test -p lib-q-lattice-zkp kat_regenerate_vectors -- --ignored`.

## 11. Prover secret hygiene

Sigma prover paths route sensitive material through [`src/sigma/secrets.rs`](src/sigma/secrets.rs):

| Material | Handling |
|----------|----------|
| Mask vector `y` | [`SecretPolyVec`](src/sigma/secrets.rs); matrix multiply borrows via [`ModuleMatrix::mul_vec_polys`](../../lib-q-ring/src/module.rs) |
| Witness copy `(r \|\| m)` | [`SecretWitnessVec`](src/sigma/secrets.rs) for the prover-local detachment from [`AjtaiOpening`](src/commitment.rs) |
| Successful / aborted `z` | Moved into the public proof via [`SecretPolyVec::into_public`](src/sigma/secrets.rs); aborted copies scrubbed between attempts |
| Amortised attribute batch | [`ProverMaskScratch`](src/sigma/secrets.rs) RAII; per-attribute `z_i` intermediates zeroized after aggregation; `agg_z` / `agg_w` canonicalized to `[0, q)` before export |
| Blind issuance openings | [`BlindOpeningSecrets`](src/blind.rs) `ZeroizeOnDrop` on abandoned [`BlindUserState`](src/blind.rs); [`UnblindedIssuance`](src/blind.rs) `ZeroizeOnDrop` on `token_opening` |

This is **memory hygiene** (volatile zeroization via the [`zeroize`](https://docs.rs/zeroize) crate).

### `hardened` feature (side-channel oriented)

With `hardened` enabled:

| Control | Implementation |
|---------|----------------|
| Branch-free norm / mod-q / scalar multiply | [`lib-q-ring`](../lib-q-ring/src/poly.rs) `Poly::infinity_norm`, `normalize_mod_q_assign`, `scalar_mul_by_u32_mod_q` |
| First-order witness masking | [`MaskedWitness`](src/sigma/secrets.rs): `c·wit = c·share_a + c·share_b` (SHAKE256-derived shares) |
| Structured prover loop | Always run `verify_*` per attempt; norm gate via [`polys_norm_within_bound`](../lib-q-ring/src/poly.rs); fixed `max_attempts` with CT first-accept merge |
| Mask RNG | [`hardened::new_secure_rng`](src/hardened.rs) (workspace CSPRNG) |

**Out of scope (this feature):** microarchitectural channels (cache/SMT/transient) and independent laboratory certification remain out of scope. Higher-order masking is a planned research milestone — see [docs/higher-order-masking-milestone.md](../../docs/higher-order-masking-milestone.md). Before a laboratory engagement, the hardened build is exercised by the internal [side-channel self-certification](../../docs/sca-self-certification.md) battery. See also [docs/hardened-attestation.md](../../docs/hardened-attestation.md).
