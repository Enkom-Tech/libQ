# lib-q-threshold-kem-lattice (PROVISIONAL)

`lib-q-threshold-kem-lattice` is a provisional post-quantum **lattice threshold KEM** whose
decapsulation key is produced **dealerlessly** by [`lib-q-dkg`](../lib-q-dkg). It is the KEM analogue
of [`lib-q-threshold-raccoon`](../lib-q-threshold-raccoon) (which is the signature analogue): both
consume the same `lib-q-dkg` shares and the same BDLOP-committed group key.

Unlike the ML-KEM-based [`lib-q-threshold-kem`](../lib-q-threshold-kem) — a trusted-dealer scheme that
GF(256)-Shamir-shares an ML-KEM decapsulation key (a **non-linear** encoding no linear VSS can
produce) — this crate is a **dual-Regev / GPV** KEM over the shared ring `R_q = Z_q[X]/(X^1024+1)`,
`q ≈ 2^48`. Its decryption is a **linear** map of the secret, so a distributed dealerless DKG can
produce the key and a threshold of holders can decapsulate **without ever reconstructing it**.

The crate is `no_std + alloc`-capable, ships wasm bindings (`@lib-q/threshold-kem-lattice`), and
freezes its v1 wire with platform-exact KATs.

## Construction

The group public key is `t0 = B0·r ∈ R_q^MU` — the `t0` half of the DKG group key
`T = commit(s; r) = (B0·r, ⟨b1,r⟩ + s)`. The short commitment randomness `r` is the decryption key,
and `lib-q-dkg` already `t`-of-`n` Shamir-shares it (`Σ_{j∈S} λ_j·rand(j) = r`).

```text
encap:   μ ← {0,1}^256;  (e, f, g) = XOF(pk, μ)      [e ternary; f, g uniform [-2^20, 2^20]]
         p = B0ᵀ·e + f;   v = ⟨t0, e⟩ + g + encode(μ);   ct = (p, v);   K = KDF(pk, μ, ct)
decap:   ⟨r, p⟩ = Σ_{j∈S} λ_j·⟨rand(j), p⟩   (linear; each holder contributes λ_j·⟨rand(j), p⟩)
         w = v − ⟨r, p⟩;   μ' = decode(w)
         FO⊥: reject unless Enc(pk, μ') == ct;   K = KDF(pk, μ', ct)
```

Encryption is **derandomized from `μ` with integer-only sampling** (Fujisaki–Okamoto, explicit
rejection): re-encryption is bit-exact on every platform/build, so a malformed or mauled ciphertext
is rejected and never yields a key. Decapsulation is exact by worst-case arithmetic
(noise `≈ 2^44` incl. flooding vs `q/4 ≈ 2^46`), so the FO check never falsely rejects (δ = 0).

## Dealerless keygen (drop-in)

```rust
// dealerless: keys come from lib-q-dkg's DKG, no trusted dealer
let out = lib_q_dkg::dkg_run_honest(&lib_q_dkg::setup(), n, t, &mut rng)?;
let pk  = lib_q_threshold_kem_lattice::public_key_from_dkg(&out.public_key)?;
let shares: Vec<_> = out.secret_shares.iter()
    .map(lib_q_threshold_kem_lattice::share_from_dkg).collect();
```

`keygen_shares` is a fast centralized reference producing the identical share format.

## Threshold decapsulation

* Reference (trusted combiner): `partial_decap` + `combine`, or `decapsulate_reference`.
* Distributed (share-private): `threshold::partial_decap_masked` + `combine`, with a
  ciphertext-bound additive zero-share (uniform to outsiders; cancels exactly) **plus uniform
  flooding noise** (`2^40` per partial) protecting the share against an inside coalition.

## Status and scope (research-grade)

This crate is **PROVISIONAL** and awaits cryptographer sign-off.

* **Decapsulation-key hiding** (recover `r` from `t0 = B0·r`) is the *same* Module-LWE instance the
  DKG / `lib-q-threshold-raccoon` estimator-gated at **169-bit quantum** core-SVP (β = 636).
* **Ciphertext hiding** is estimator-gated too (2026-07-10): the distinct Module-LWE instance
  (`n = 6144`, uniform error) shows **no feasible attack** at any swept error bound (the easiest
  swept point costs ≈2^971 rop) — the key side binds.
* **Chosen-ciphertext posture:** FO⊥ re-encryption check + per-partial flooding + an enforceable
  per-key decapsulation budget (`DecapBudget`). The remaining boundary: an inside coalition probing
  with *malformed* ciphertexts can defeat flooding by amplification (~63 queries; the FO check fires
  only at `combine`). **A ciphertext *well-formedness* proof does NOT close this** — the minimal
  sufficient statement is a proof of *correct encryption* (knowledge of `μ`), whose only
  assumption-free realization is a heavy ZK-STARK of the SHAKE expansion. The deployable, sound
  closure is an **authenticated / identity-verified encapsulator** plus the enforceable budget +
  DKG key rotation (`DecapBudget::untrusted()` caps below the probe length for untrusted senders;
  `DecapBudget::authenticated()` uses the `2^20` honest-ciphertext budget). No formal threshold
  IND-CCA theorem is claimed (it is conditional on the closure in force). Full treatment — including
  the proof that a norm-only well-formedness proof is insufficient — in `THRESHOLD_SECURITY.md`.
* **Hardening pass (2026-07-10, adversarially-verified multi-dimension audit):** branchless
  message encode/decode and secret centering; hard (release-enforced) structural guards on every
  entry point (subset validation, ciphertext element count, distinct-partial threshold at
  `combine`); split `Encoding*` error variants so wire faults, caller errors, and FO rejections
  are distinguishable; zeroization of every heap-lived secret intermediate (decoded share, `w`,
  re-encryption, ephemeral `e`, pre-mask partials, keygen polynomial, buffered RNG entropy);
  profile blob now binds the exact prime `q`. Perf: NTT-domain accumulation for all
  matrix/inner-product ring math (~2.4× fewer transforms per encryption, KAT-verified
  wire-neutral); public-key digest hashed once per operation; allocation-free serialization and
  comparison paths.

See `dev/conformance/integration/lib-q-threshold-kem-lattice/LIBQ_API.md` (contract) and
`SECURITY_ANALYSIS.md` there (estimator runs, noise budget, the quantified insider probe, and the
constant-time posture) for the RED-zone review surface.
