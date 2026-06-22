# FROZEN WIRE — libQ unlinkable set-membership proof (`libq.zkfri.membership.v0`)

**Crate:** `lib-q-zkp` · **Wire version:** `v0` (envelope version byte `0x01`) ·
**Status: FROZEN (byte layout) — TIER RED, PENDING HUMAN CRYPTOGRAPHER SIGN-OFF.**

> The **byte layout** in this document is frozen and interoperable: the public-statement
> encoding and the envelope header below MUST NOT change under wire version `v0`. Freezing the
> *bytes* is independent of the *security* sign-off — the soundness / zero-knowledge claims of
> the underlying proof remain **RED** and gated on the O1–O4 obligations in
> [`membership-adr113-freeze-gate-review.md`](membership-adr113-freeze-gate-review.md). A libQ
> consumer MAY pin these bytes for interop; it MUST NOT treat the privacy/soundness as
> load-bearing until O1–O4 are signed off by a human cryptographer.

This is the lib-Q side of `lib-q-zk-fri` per
[`libq-unlinkable-membership-v0.md`](../../../libQ-SPEC/spec/security/libq-unlinkable-membership-v0.md)
§5.2 / §7 / §9 and the PQ-hash duality contract (§9). It backs libQ modes **M1** (pseudonymous)
and **M2** (unlinkable).

---

## 1. Field and element encoding (normative)

- **In-circuit / digest field:** `PoseidonField = Complex<Mersenne31> = GF(p²)`, `p = 2³¹−1`.
  Each field element is the quadratic-extension pair `(real, imag)` of `Mersenne31`.
- **Element wire encoding (8 bytes):** `real ‖ imag`, each a **canonical** `Mersenne31` value
  in `[0, 2³¹−2]` encoded as **little-endian `u32`** (`as_canonical_u32().to_le_bytes()`).
  - Decode is **canonical-checked**: any limb `≥ 2³¹−1` is **rejected** (not reduced), so the
    byte encoding of every public value is **injective** (freeze-gate O6). Applies to
    `merkle_root_from_bytes`, `wide_digest_from_bytes`, `ctx_from_bytes`.

A "wide digest" (root / leaf / Merkle node / nullifier) is **5 field elements** =
`WIDE_DIGEST_ELEMS`, i.e. **40 bytes** (`WIDE_DIGEST_BYTES`). Five ~62-bit `GF(p²)` cells clear
the ≥256-bit digest / ≥128-bit-collision requirement of libq-unlinkable-membership §9.

---

## 2. Public statement — `PUBLIC_STATEMENT_BYTES = 96` (FROZEN)

The verifier-visible statement is `root ‖ ctx ‖ N`:

| Offset | Width | Field | Elements | Meaning |
|-------:|------:|-------|---------:|---------|
| `0`    | `40`  | `root` | 5 × `GF(p²)` | Published group commitment root `R_zk` (canonical Merkle root). |
| `40`   | `16`  | `ctx`  | 2 × `GF(p²)` | Context string (linkage domain); public input to the nullifier. |
| `56`   | `40`  | `N`    | 5 × `GF(p²)` | Nullifier `N = H(domain ‖ t ‖ ctx)`. |
| —      | `96`  | total  | 12 × `GF(p²)` | `root(40) ‖ ctx(16) ‖ N(40)`. |

Built/parsed by `membership::public_statement_bytes` / the byte decoders. This matches the
freeze-gate review's "Public values = `[root(5) ‖ ctx(2) ‖ N(5)]` (12 elements)".

### 2.1 `ctx` reconciliation with libQ (HANDOFF ITEM — libQ-side decision)

libQ derives `ctx` as a **32-byte K12 digest** under label `libq.member.ctx.v0`
(`group_id ‖ epoch ‖ topic`), per libq-unlinkable-membership §5.1/§9 and the K12 registry. The
lib-Q **circuit input is 2 `GF(p²)` elements = 16 bytes**, NOT 32. The mapping from libQ's 32-byte
K12 `ctx` into the circuit's `[2 × GF(p²)]` input is **libQ's to fix** and MUST be deterministic
and identical on prover and verifier.

**Effective ctx separation = ~124 bits (corrected; card t_bab219ba).** Each `GF(p²)` element is a
**pair** `(real, imag)` of canonical `Mersenne31` limbs (`< 2³¹−1`, ~31 bits *each*), so one
element ≈ 62 bits and the 2-element / 4-limb `ctx` domain is `(2³¹−1)⁴ ≈ 2¹²⁴`. The AIR ingests
`ctx` at **full width** — `field_from_canonical_le` fills both limbs; the nullifier sponge absorbs
both whole elements (`state[absorbed] += e` over the full extension element, RATE 2); and the row-0
binding `ctx_cols[i] == pub_ctx[i]` is full extension-field equality — so there is **no in-circuit
entropy reduction**. Consequently: **any-pair birthday ≈ 2⁶²**, **targeted de-link
(second-preimage, force a chosen context onto a victim's `ctx`) ≈ 2¹²⁴**. The verifier *pins* `ctx`
to the expected operation context (libq-unlinkable-membership §5.4 `BadContext`), so the operative
de-link attack is the **targeted ~2¹²⁴**, not the birthday. lib-Q's byte decode is **injective**
(O6), so two distinct accepted 16-byte `ctx` never collide in-circuit — the *only* collision surface
is libQ's own 32→16-byte compression into the 124-bit canonical domain.
> An earlier draft of this section said "~62 bits / ~2³¹ birthday" — that was an **undercount** (it
> counted one limb, ~31 bits, per `GF(p²)` element instead of the real+imag pair, ~62 bits). The
> correct figures are ~124 bits / ~2⁶² birthday / ~2¹²⁴ targeted.

**libQ mapping note (corrected rejection rate).** lib-Q's decoders **reject** any limb `≥ 2³¹−1`, and
a uniform 4-byte word is non-canonical with probability `(2³¹+1)/2³² ≈ ½` (NOT ~`2·2⁻³¹`), so a
naïve "decode the first 16 bytes" lands fully canonical only ~`1/16` of the time. libQ's mapping must
therefore land in the canonical domain — recommended: derive each of the 4 `Mersenne31` limbs by
reducing a fresh ≥40-bit K12 word mod `2³¹−1` (negligible ~`2⁻³³` bias) and serialize canonically
(`as_canonical_u32` LE), giving the full ~124-bit `ctx` with no rejection loop.

**Freeze decision.** `CTX_ELEMS = 2` / `CTX_BYTES = 16` is **frozen for `v0`**: ~2¹²⁴ targeted /
~2⁶² birthday is sufficient for the linkage-domain-separation role (`ctx` is not a security-bearing
collision target like the Merkle nodes, which are 5 elements / ≥128-bit by §9). If libQ later needs
full 256-bit in-circuit `ctx` separation, that requires a **wider `CTX_ELEMS`** at a future wire
revision (`v1`).

---

## 3. Domain separator (baked circuit constant)

`domain = first 2 cells of H("libq.zkfri.membership.v0")` (`MEMBERSHIP_DOMAIN_STR`), a baked
**constant** in the AIR — not a witness, not a public input. Nullifier preimage is exactly
`domain(2) ‖ t(3) ‖ ctx(2)` = 7 `GF(p²)` elements (rate-2 sponge, `10*1` padding). Leaf preimage
is `t` (3 elements). (O3 covers cross-preimage separation.)

---

## 4. Proof envelope — `MembershipProofEnvelopeV0` (FROZEN header)

The raw `postcard(StarkProof)` bytes carry **neither** the public statement **nor** the
`ProofMetadata{tree_depth, digest_width, zk}` the verifier needs to reconstruct the AIR and pick
the STARK config type. The envelope prepends an **8-byte frozen header** so a byte-only (FFI)
consumer can verify from `&[u8]` alone.

| Offset | Width | Field | Notes |
|-------:|------:|-------|-------|
| `0` | `1` | `envelope_version` | `= 0x01` (`MEMBERSHIP_ENVELOPE_VERSION`). `0x00` reserved. |
| `1` | `1` | `tree_depth` | Real Merkle path depth, `1..=MAX_DEPTH` (`MAX_DEPTH = 64`). |
| `2` | `1` | `digest_width` | `= 5` (`WIDE_DIGEST_ELEMS`). Other values rejected. |
| `3` | `1` | `flags` | bit `0` = `zk` (hiding/ZK proof); bits `1..7` **reserved = 0** (set ⇒ reject). |
| `4` | `4` | `proof_len` | `u32` little-endian = `proof_bytes.len()`. |
| `8` | `proof_len` | `proof_bytes` | `postcard(StarkProof)` — **opaque, NOT frozen** (proof math/length is a parameter of the proof system per libq-unlinkable-membership §7). |

`tree_depth` is **authenticated** at verify time against the proof's actual STARK trace height
(`1 << degree_bits == next_pow2(tree_depth)`; ZK path: `== 2·next_pow2(tree_depth)`) — the
depth-confusion guard (O5). `digest_width ≠ 5` and the `zk` flag mismatch both fail closed.

Codec: `membership::encode_membership_envelope` / `decode_membership_envelope`.

---

## 5. Byte-oriented FFI verify (the libQ seam)

```rust
// returns true iff the proof verifies against the canonical root in the statement.
// never panics; any malformed input → false. uses the PRODUCTION STARK config.
pub fn verify_membership_envelope(
    public_statement_bytes: &[u8],   // 96-byte root‖ctx‖N (§2)
    proof_envelope_bytes: &[u8],     // MembershipProofEnvelopeV0 (§4)
) -> bool
```

This is the single entry point a libQ `Verify(root, ctx, nullifier, proof) → bool` FFI seam needs.
Internally: `decode_membership_envelope` → `verify_unlinkable_membership_bytes` →
transparent/hiding verifier (selected by the `zk` flag) on the production config.

Provers emit the wire with `prove_unlinkable_membership` (transparent) or
`prove_unlinkable_membership_zk_auto` (hiding; OS-CSPRNG seeds) → `encode_membership_envelope`.

---

## 6. What is frozen vs. not

- **FROZEN (`v0`):** element encoding (§1), the 96-byte public statement (§2), the domain
  constant string (§3), the 8-byte envelope header + field semantics (§4), `verify_*` byte
  contract (§5). `WIDE_DIGEST_ELEMS = 5`, `CTX_ELEMS = 2`, `MAX_DEPTH = 64`.
- **NOT frozen:** the opaque FRI/STARK proof body bytes and their length; the Poseidon-256
  parameters (round counts) pending O1; the concrete FRI parameters (a `lib-q-zk-fri` parameter
  row per §7 "suite agility"). A change to any frozen item requires a new wire version byte.

## 7. Tier / sign-off status

**RED — PENDING HUMAN CRYPTOGRAPHER SIGN-OFF.** Byte interop may be pinned now; the
soundness (O1 Poseidon round counts over `GF(p²)`, O2 capacity-5 truncation), domain-separation
(O3), and zero-knowledge (O4) claims are **not** discharged and remain blocking for GREEN. See
[`membership-adr113-freeze-gate-review.md`](membership-adr113-freeze-gate-review.md) §5.
