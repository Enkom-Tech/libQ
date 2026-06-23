# lib-q-mve

**Multi-recipient verifiable encryption ("verifiable rekey")** for lib-Q, built on the in-tree
zk-STARK stack (`lib-q-zkp` / `lib-q-stark*`). A producer distributes a fresh group key `K` to many
recipients — each copy wrapped under that recipient's ML-KEM update key — together with a **single**
proof that **every** recipient receives the **same** `K`. The proof is checkable by an untrusted
relay **without** the relay learning `K`.

> ## ⚠️ RED — PENDING HUMAN CRYPTOGRAPHER SIGN-OFF
>
> This crate is **RED / experimental / research code**. It is **NOT proven sound, NOT audited, and
> NOT production-ready**, and it is pending human cryptographer sign-off (the construction was
> submitted to IACR ePrint and is under review). The in-circuit proof guarantees single-`K`
> consistency across the wraps; the binding of each ML-KEM shared secret `ss_i` to its KEM
> ciphertext `kem_ct_i` under `update_pk_i` (full ML-KEM-encaps-in-circuit) is **NOT** proven — it
> is backstopped by the recipient-side commitment check (mve-rekey-v0 §4.3, §6 fallback). The proof
> reuses the membership AIR's shared Poseidon-256 over GF(p²), whose round counts are not
> human-verified. **Do not treat any of this as load-bearing.** See
> [`docs/mve-freeze-gate-review.md`](docs/mve-freeze-gate-review.md) for the M1–M4 obligations and
> the freeze gate.

## The contract (verifiable rekey)

This is the **insider-robustness / anti-split** gate: a malicious producer cannot hand divergent key
material to different recipients to split the group, because no such envelope can produce a verifying
proof.

```text
Prove (K, r, {update_pk_i}, {ct_i})            -> π     # all ct_i deliver the same K
Verify(key_commitment, {ct_i}, {update_pk_i}, π) -> bool # relay-checkable, never learns K
```

## Construction (mVE-v0)

The contract follows the `mve-rekey-v0` spec (§4 / §7):

- **Commitment (outside the circuit).** `key_commitment = K12(libq.mve.commit.v0 ‖ key_len ‖ K ‖
  r_len ‖ r ‖ epoch_id)` — a canonical, length-prefixed (injective) §4.3 layout, squeezed to 32
  bytes. The label is a leading message prefix under empty K12 customization. This is the hiding +
  binding value every recipient recomputes and checks. It is a plain K12 hash and does **not** touch
  the AIR or any soundness obligation.
- **Per-recipient wrap.** For each recipient `i`: `ct_i = ML-KEM.Encaps(update_pk_i) → (ss_i,
  kem_ct_i)`, and the delivered wrap is the field-additive one-time pad `w_i = K + H_zk(ss_i)`, where
  `H_zk` is Poseidon-256 (`hash_suite_id = 5`). The recipient decapsulates `ss_i` from `kem_ct_i`,
  recovers `K = w_i − H_zk(ss_i)`, and checks `key_commitment`.
- **The proof (in zero knowledge).** A single STARK proof π asserts, in zero knowledge of
  `(K, r, {ss_i})`, that there is a **single** `K` with `w_i = K + H_zk(ss_i)` for every `i`. A
  divergent-key split cannot produce a verifying proof. The proof uses the **hiding (ZK) PCS** so the
  witness — `K` sits in constant trace columns — is not leaked by FRI openings; blinding seeds are
  drawn fresh from the OS CSPRNG per proof (reuse voids hiding).

## Prove / verify surface

The public API is re-exported at the crate root:

| Item | Description |
|------|-------------|
| `mve_prove(key, randomizer, epoch_id, recipient_ids, recipient_eks, encaps_coins) -> Result<MveRekeyEnvelopeV0>` | Encapsulate `K` to each recipient and emit the single consistency proof. `encaps_coins[i]` is the (RED-zone) ML-KEM encapsulation randomness for recipient `i`; production **must** pass fresh independent CSPRNG draws. |
| `mve_verify(key_commitment, envelope, update_pks) -> bool` | The relay gate: recipient-set / length checks plus the consistency proof. Returns `true` iff the envelope is well-formed and the proof shows every wrap carries a single `K`. Never panics, never learns `K`. |
| `MveEncapsulationKey` | The recipient ML-KEM update key — ML-KEM-768 (`kem_id`-negotiated). |
| `MveRekeyEnvelopeV0` | Producer → relay → recipients envelope: `epoch_id`, `recipient_ids`, `key_commitment`, per-recipient `ciphertexts`, and the single `proof`. |
| `RecipientCiphertext` | One recipient's wire ciphertext: `kem_ct` (ML-KEM) + `wrap` (`w_i`, serialized). |

Supporting value-level helpers — `key_commitment`, `wrap_key`, `unwrap_key`,
`mask_from_shared_secret`, `wrap_to_bytes` — are also public. Note that in `mve_verify` the
`key_commitment` and `update_pk_i` arguments are part of the §7 `Verify` contract but are **not**
consumed in-circuit: the commitment is the recipient-side binding (§4.3) and the
KEM-ciphertext ↔ shared-secret binding is the documented RED residual.

## Parameters

| Constant | Value | Meaning |
|----------|-------|---------|
| `KEY_ELEMS` | 5 | Field elements in `K` (5 × ~62-bit GF(p²) ≈ 310-bit key material ≥ 256-bit). |
| `KEY_BYTES` | — | Bytes per serialized key / wrap (5 × 8-byte `Complex<Mersenne31>`). |
| `SS_ELEMS` | 4 | GF(p²) elements the ML-KEM shared secret is packed into. |
| `COMMITMENT_BYTES` | 32 | K12 commitment output length. |
| `MAX_RECIPIENTS` | 1024 | DoS bound per envelope (trace height padded to a power of two). |
| `MVE_COMMIT_LABEL` | `b"libq.mve.commit.v0"` | K12 domain label for the distributed-key commitment. |

The value field is `Complex<Mersenne31>` = GF(p²); the proof is a FRI/AIR STARK over that field via
`lib-q-zkp`'s `StarkProver` / `StarkVerifier`.

## Availability

Crates.io-only — this crate ships **no** npm / wasm package.

## License

Apache-2.0 — see [LICENSE](../LICENSE).
