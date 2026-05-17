# Module-lattice ZKP (`lib-q-lattice-zkp`)

Concrete ring / NTT code is shared with ML-DSA via [`lib-q-ring`](../lib-q-ring). For how this differs from the STARK stack (`lib-q-zkp`), see [docs/zkp-implementation.md](../docs/zkp-implementation.md).

This crate is the integration surface for **BLNS-style** anonymous credentials over module lattices. The pilot proving systems (Σ-protocol opening, linear relations, infinity-norm certificates, batch amortisation, blind issuance, anonymous tokens, nullifier-bound openings, and hierarchical Merkle openings) are wired and exercised by unit and integration tests. **Production parameter sets** and a complete blind-signature security proof are still **research-grade** and require freezing against a target NIST security category before deployment.

## 1. Public parameters

- **Ring / module:** degree-`n` negacyclic ring `R_q`, module rank `k`, modulus `q` matching the operational ML-DSA/ML-KEM deployment (composition is an engineering constraint, not a mathematical one).
- **Ajtai commitment:** public matrix `A ∈ R_q^{m×(k+ℓ)}`, message `m ∈ R_q^k`, randomness `r ∈ R_q^ℓ`, commitment `c = A · (r ‖ m)`.

Binding reduces to **Module-SIS**; hiding to **Module-LWE** for suitable noise widths.

## 2. Proof goals (sigma layer)

1. **Opening:** given `c`, prove knowledge of `(m, r)` consistent with the Ajtai relation.
2. **Linear relations in NTT domain:** prove inner products / linear maps applied to committed vectors without revealing witnesses—this is where NTT-domain linear algebra composes with ML-DSA’s internal representation.
3. **Norm / range certificates:** coefficient-wise bounds compatible with ML-DSA rejection analysis (γ₁, γ₂, β).

Challenges are drawn from a **FIPS 204–compatible** ternary distribution (fixed Hamming weight) so that Fiat–Shamir transcripts can be composed with ML-DSA challenge hashing where required.

**Security model:** Fiat–Shamir security proofs for these sigma protocols assume the Random Oracle Model (ROM), not the Quantum Random Oracle Model (QROM). This limitation is shared with `lib-q-ring-sig`'s DualRing-LB–oriented pilot verifier and is documented in [SECURITY.md](../SECURITY.md#random-oracle-model-vs-quantum-random-oracle-model). Maintaining ROM consistency across both zero-knowledge components is deliberate; QROM upgrades would be applied uniformly when the research matures.

## 3. Amortisation (batch presentations)

The `AmortisationBudget` type models transcript growth for multi-attribute presentations. A concrete BLNS aggregator would:

- hash-commit to a batch of attribute openings,
- run a single permutation argument or aggregated Σ-protocol round,
- produce one `AmortisedProof` blob per batch instead of per attribute.

## 4. Implementation status

The pilot stack listed below is implemented and covered by unit tests inside this
crate plus the cross-crate
[`privacy_protocol_integration_tests`](../lib-q/tests/privacy_protocol_integration_tests.rs).

| Layer | Module | Status |
|-------|--------|--------|
| Concrete `RingParams` (pilot `n=256`, configurable `k`, `q` from `lib-q-ring`) | [`params.rs`](src/params.rs) | implemented |
| Serialized `AjtaiCommitmentKey` and deterministic `commit` | [`commitment.rs`](src/commitment.rs) | implemented |
| Σ-protocol opening prover/verifier with rejection sampling | [`sigma/opening.rs`](src/sigma/opening.rs) | implemented |
| Σ-protocol linear-relation prover/verifier | [`sigma/linear.rs`](src/sigma/linear.rs) | implemented |
| Infinity-norm certificate (CRT-packed) | [`sigma/norm.rs`](src/sigma/norm.rs) | implemented |
| Challenge derivation hooked to SHAKE256 (FIPS 204 ternary ball) | [`challenge.rs`](src/challenge.rs) | implemented |
| Batch amortisation over multiple openings | [`sigma/amortise.rs`](src/sigma/amortise.rs) | implemented |
| Nullifier-bound openings + uniqueness amortisation labels | [`sigma/uniqueness.rs`](src/sigma/uniqueness.rs) | implemented |
| Witness-derived nullifier + witness-bound opening proofs | [`sigma/uniqueness.rs`](src/sigma/uniqueness.rs) | implemented (pilot) |
| Hierarchical Merkle membership + level-tagged opening | [`sigma/hierarchical.rs`](src/sigma/hierarchical.rs) | implemented |
| Private membership pilot (digest-structured leaf + clearance margin norm) | [`sigma/hierarchical.rs`](src/sigma/hierarchical.rs) | implemented (pilot) |

### 4.1 ZK Merkle membership (position hiding)

[`prove_private_membership`](src/sigma/hierarchical.rs) / [`verify_private_membership`](src/sigma/hierarchical.rs) implement a **pilot** alternative to cleartext `HierarchicalAuthProof::leaf_payload`:

- Verifiers recompute the PVTN leaf digest from explicit `(clearance_level, role_tag, parent_digest)` instead of absorbing a raw `Vec<u8>` leaf in the opening transcript.
- A [`CrtPackedNormProof`](src/sigma/norm.rs) certifies the packed margin `clearance_level - min_clearance` in a single coefficient, composing the existing infinity-norm machinery for a lightweight range-style check.
- **Clearance level is still carried on the proof struct** for this pilot (soundness ties the norm certificate to the recomputed leaf digest). Fully hiding the exact level behind a ZK comparison gate (without publishing `clearance_level`) is a follow-on refinement.
- **Merkle directions are still published** on the proof object; hiding the leaf index inside the tree requires either a hash-path relation proved inside this sigma stack (depth-limited) or composition with the STARK pipeline in [`lib-q-zkp`](../lib-q-zkp). Treat position privacy as a follow-on milestone.

## 5. Blind issuance ([`blind.rs`](src/blind.rs))

`BlindIssuance::request → issuer_sign → finalize → verify` orchestrates a
homomorphic CRS-style blind issuance flow:

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

The construction is **not** Chaum-style blind RSA. In addition to the CRS path,
[`BlindIssuerKeypair`](src/blind.rs) and [`BlindSignature`](src/blind.rs) expose a **pilot**
issuer-keyed transcript that binds [`blind_message_digest`](src/blind.rs) into the issuer
Fiat–Shamir context (`issuer_sign_message` / `finalize_message` / `verify_message`). See
[`BLIND_ISSUANCE.md`](BLIND_ISSUANCE.md) for the CRS model, security goals (blindness,
one-more unforgeability), and production caveats for trapdoor Module-SIS families.

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
- Production parameters: PQCC and community review timelines still treat
  high-assurance lattice anonymous credentials as **research-grade**.
