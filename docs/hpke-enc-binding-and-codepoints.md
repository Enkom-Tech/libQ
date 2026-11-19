# lib-q-hpke: `enc`-binding gap and IANA codepoint choice

Status: **write-up only — no wire change in this pass.** This document exists to give the
crypto/RED reviewer the evidence and a recommendation; it does not itself change
`HpkeKem`/`HpkeKdf`/`HpkeAead::algorithm_id()`, `hpke_core::key_schedule`, or any other wire-visible
code. See [`independent_key_schedule_kat_tests.rs`](../lib-q-hpke/tests/independent_key_schedule_kat_tests.rs)
and its fixtures for the independent-implementation KAT this same card also froze.

## 1. `enc` is not bound into the key schedule

### What RFC 9180 does for classical DHKEM

RFC 9180's only implemented KEM family is DHKEM (Section 4.1). `DHKEM.Encap(pkR)` does not feed
the raw Diffie-Hellman output `dh` into `KeySchedule` directly — it derives the KEM shared secret
via

```
shared_secret = ExtractAndExpand(dh, kem_context)
kem_context   = concat(enc, pkRm)                  # concat(enc, pkRm, pkSm) in Auth/AuthPSK
```

`enc` (the sender's ephemeral public key, i.e. the KEM ciphertext) and the recipient's public key
are therefore cryptographically mixed into the shared secret *before* `KeySchedule` ever sees it.
`KeySchedule` itself (Section 5.1) never takes `enc` as a parameter — the binding is entirely
internal to `DHKEM.Encap`/`Decap`, not something `KeySchedule` (or Base mode) provides on its own.

### What lib-q-hpke does for ML-KEM

lib-q-hpke has no DHKEM — it is ML-KEM only (`HpkeKem::MlKem512/768/1024`,
[`lib-q-hpke/src/kem/ml_kem.rs`](../lib-q-hpke/src/kem/ml_kem.rs)). `MlKemImpl::encapsulate`
returns ML-KEM's own `(ciphertext, shared_secret)` unmodified:

```rust
// lib-q-hpke/src/kem/ml_kem.rs, Kem::encapsulate
let (ciphertext, shared_secret) = self.provider.encapsulate(algorithm, &pk, None)?;
Ok((ciphertext, Zeroizing::new(shared_secret)))
```

`hpke_core::setup_sender_with_mode` then feeds that `shared_secret` straight into `key_schedule`
with no intermediate `ExtractAndExpand(shared_secret, concat(enc, pkRm))` step
([`lib-q-hpke/src/hpke_core.rs:589-590`](../lib-q-hpke/src/hpke_core.rs)):

```rust
let (encapsulated_key, mut main_shared_secret) =
    provider.encapsulate(kem_algorithm, recipient_pk.as_bytes(), rng)?;
// main_shared_secret goes into key_schedule() as-is; encapsulated_key ("enc") is never mixed in.
```

`key_schedule` (RFC 9180 Section 5.1 pseudocode, matched by
[`hpke_core::key_schedule`](../lib-q-hpke/src/hpke_core.rs)) takes `(mode, shared_secret, info,
psk, psk_id)` — no `enc`, no recipient public key. Base mode has nothing else that could supply
this binding: no PSK, no sender authentication. **In Base mode, `enc` is authenticated by nothing
inside lib-q-hpke's key schedule.**

### What this actually means

This is not "no security at all" — ML-KEM's own FO-transform (FIPS 203 `ML-KEM.Decaps`) is
IND-CCA2, so a decapsulation failure or ciphertext mismatch is still detected at the KEM layer, and
`shared_secret` still authenticates possession of `skR` via ML-KEM's own construction. What is
missing specifically is the **DHKEM-style transcript binding**: RFC 9180's classical suites derive
`shared_secret` as a function of `enc` and `pkR` together, so a downstream consumer of `key_schedule`'s
output (the AEAD key, base_nonce, exporter_secret) gets a shared secret that is cryptographically
tied to exactly which `enc`/`pkR` pair produced it. lib-q-hpke's ML-KEM path does not provide that
same tie *at the HPKE layer* — the guarantee, if any, is entirely inside ML-KEM's own internal FO
transform and is not re-derived or reinforced by `key_schedule`. Concretely, nothing in
`key_schedule`'s inputs changes if `enc` were substituted for a different valid encapsulation to the
same recipient key that happens to produce the same shared secret (not possible for a correctly
implemented IND-CCA2 KEM against ML-KEM's own contract, but the HPKE layer does not independently
enforce or re-verify this — it trusts the KEM layer entirely, with no defense-in-depth).

### Existing, partial mitigation — and why it doesn't close this

[`HpkePskWireFormat::LibQCommitmentSuffix`](../lib-q-hpke/src/types.rs) is a libQ extension that
appends `labeled_extract(..., "psk_commitment", psk ‖ psk_id ‖ enc_kem)` after the KEM output,
binding `enc_kem` into an explicit commitment the receiver can check before decapsulation. This is
real, and it is a step in the right direction — but:

- it only applies to `HpkeMode::Psk` / `HpkeMode::AuthPsk`, and only when both peers opt in (it is
  **not** the default `HpkePskWireFormat::Rfc9180`);
- it does not apply to `HpkeMode::Base`, which is the common case and the one the RFC 9180 DHKEM
  binding covers unconditionally for every mode;
- it binds `enc` into a wire-visible **commitment check**, not into the **key schedule secret**
  itself — the AEAD key/nonce/exporter_secret RFC 9180's `KeySchedule` produces are unaffected by
  whether the commitment matches, whereas DHKEM's binding changes the derived `shared_secret` itself.

### Recommendation

Add an explicit KEM-context binding step for the ML-KEM path, mirroring DHKEM's own construction:
before calling `key_schedule`, both sender and receiver should compute

```
bound_shared_secret = labeled_extract(kdf, raw_ml_kem_shared_secret, suite_id, "kem_context",
                                       concat(enc, pkRm[, pkSm]), provider)
```

(exact label/context naming is a design decision for the follow-up, not fixed here) and feed
`bound_shared_secret` into `key_schedule` in place of the raw ML-KEM output, for **every** mode
including Base — not only as an opt-in PSK-mode extra. This requires cryptographer review (same
bar as the currently-disabled Auth/AuthPSK gap in `SECURITY.md`) before it ships, since it changes
what `key_schedule`'s first input actually is. **Not done in this pass** — see "Compatibility
impact" below for why this is deliberately deferred to its own reviewed change.

## 2. IANA codepoint choice

### What lib-q-hpke currently uses

| Field | libQ value | libQ name |
|---|---|---|
| KEM | `0x0022` | ML-KEM-512 |
| KEM | `0x0023` | ML-KEM-768 |
| KEM | `0x0024` | ML-KEM-1024 |
| KDF | `0x0004` | HKDF-SHAKE128 |
| KDF | `0x0005` | HKDF-SHAKE256 |
| KDF | `0x0006` | HKDF-SHA3-256 |
| KDF | `0x0007` | HKDF-SHA3-512 |
| AEAD | `0x0004` | Saturnin-256 |
| AEAD | `0x0005` | SHAKE256-based AEAD |
| AEAD | `0x0006` | Duplex-sponge AEAD (non-standard mode) |
| AEAD | `0xFFFF` | Export-only |

(`lib-q-hpke/src/types.rs`, `HpkeKem`/`HpkeKdf`/`HpkeAead::algorithm_id()`.)

### What the IANA "Hybrid Public Key Encryption (HPKE)" registry actually says

Fetched live from <https://www.iana.org/assignments/hpke/hpke.xhtml> (registry "Last Updated
2026-04-16"; verified by reading the page directly, not inferred):

- **KEM `0x0022` is no longer unassigned.** It is now registered to
  **`DHKEM(X25519+Elligator, HKDF-SHA256)`** (`draft-schanzen-hpke-elligator-kem-01`). This is a
  **real, live codepoint collision**, not merely "squatting on space someone could claim later": a
  conforming HPKE stack that reads a `kem_id = 0x0022` suite negotiation from a peer now has two
  contradictory readings — libQ's ML-KEM-512, or the registered X25519+Elligator DHKEM — with no
  way to disambiguate from the wire bytes alone. `0x0023`/`0x0024` (libQ's ML-KEM-768/1024) remain
  in the registry's `0x0023-0x002F Unassigned` block for now, but that block is Specification
  Required, not reserved or held for libQ.
- **The IANA registry already has an official ML-KEM assignment, and it is not this one.**
  `draft-connolly-cfrg-hpke-mlkem-04` registers ML-KEM-512/768/1024 at **`0x0040`/`0x0041`/`0x0042`**
  — a different, non-colliding block, already reserved for exactly the algorithm libQ implements.
  Any future interop with another ML-KEM-over-HPKE implementation that follows this draft (which,
  as the codepoint owner, is the natural convergence point for the ecosystem) will use `0x0040`
  onward, not `0x0022`.
- **KDF `0x0004`-`0x0007`** sit inside the registry's `0x0004-0x000F Unassigned` block — not
  currently colliding with anything registered, but also not reserved for libQ, and adjacent to
  `draft-ietf-hpke-pq-04`'s own SHAKE128/SHAKE256 KDF assignments at `0x0010`/`0x0011` (a
  different pair of values from libQ's `HkdfShake128`/`HkdfShake256` at `0x0004`/`0x0005`). libQ's
  `HkdfSha3_256`/`HkdfSha3_512` have no path to an official assignment under this or any other
  known draft — SHA3-based HKDF is not part of any published HPKE KDF proposal libQ's KDF
  construction matches, and (see the independent-KAT provenance note above) it is not even RFC 5869
  HKDF to begin with, which would disqualify it from a literal "HKDF-SHA3" registration regardless.
- **AEAD `0x0004`-`0x0006`** sit inside the registry's `0x0004-0xFFFE Unassigned` block — same
  situation as the KDF IDs: not colliding today, not reserved. **AEAD `0xFFFF` (`Export`) is
  correct as-is** — it matches the registry's own reserved `Export-only` codepoint exactly, so no
  change is needed there.

### Why this happened: RFC 9180 has no "Private Use" carve-out to squat in instead

Checked directly against RFC 9180 Section 11 (fetched from
<https://www.rfc-editor.org/rfc/rfc9180.txt>): all three HPKE registries ("HPKE KEM Identifiers",
"HPKE KDF Identifiers", "HPKE AEAD Identifiers") are administered under a flat **Specification
Required** policy (RFC 8126) — there is no distinct "Private Use" range carved out anywhere in the
KEM/KDF/AEAD tables the way many other IANA registries reserve (for example) a high sub-block for
unregistered experimentation. So there is no officially blessed "safe" range to occupy without
registering.

In practice, the safer informal convention other unregistered HPKE implementations have used is to
pick numerically **high** values (close to `0xFFFF`, which IANA tends to assign last, versus the
low end which IANA has been filling in incrementally as this registry snapshot shows) — not because
IANA promises anything about that range, but because it is empirically far less likely to be the
*next* codepoint IANA assigns. libQ instead chose **low** values immediately following the last
RFC-9180-native assignment (`0x0021`/`0x0003` for KEM/KDF) — precisely the range IANA has been
filling in fastest, as this pass's own findings (`0x0022`, `draft-connolly`'s `0x0040-0x0042`,
`draft-ietf-hpke-pq-04`'s `0x0010`-`0x0013`) demonstrate.

### Recommendation

1. **KEM: migrate to `0x0040`/`0x0041`/`0x0042`** (`draft-connolly-cfrg-hpke-mlkem-04`'s ML-KEM
   assignments) rather than `0x0022`-`0x0024`. This fixes the active `0x0022` collision and aligns
   libQ with the codepoints any other ML-KEM-over-HPKE implementation is most likely to converge
   on, since they are the ones an actual draft has claimed for this exact algorithm.
2. **KDF/AEAD (SHA3-256/512, Saturnin-256, duplex-sponge): move off the low `0x0004`-`0x0007`
   range.** These have no adopted draft to align with (SHA3 HKDF and Saturnin/duplex-sponge AEAD
   are libQ-specific choices with no external standardization path today), so "migrate to the
   standard codepoint" is not available the way it is for the KEM. Two real options, not mutually
   exclusive:
   - Pick numerically high values (following the informal high-range convention above) to reduce
     collision probability with future IANA assignments, and document plainly in
     `docs/interoperability.md` that these remain unregistered/non-standard regardless of numeric
     value — moving them does not make them official.
   - File a genuine `Specification Required` request with IANA (contact: Christopher Wood, Richard
     Barnes, per the registry's own "Expert(s)" field) for the algorithms libQ actually intends to
     keep long-term, which is the only way to get a codepoint IANA will not hand to someone else
     later. This is the durable fix; it is an operator/standards-process decision, not something
     this pass can complete.
   - `AEAD 0xFFFF` (`Export`) needs no change.
3. Whichever numeric values are chosen, this is a **wire-format-breaking change**: `suite_id`
   (`HPKE || I2OSP(kem_id,2) || I2OSP(kdf_id,2) || I2OSP(aead_id,2)`) is mixed into every
   `LabeledExtract`/`LabeledExpand` call, so renumbering any of `kem_id`/`kdf_id`/`aead_id` changes
   every derived key schedule output for that suite. It must ship as a coordinated, versioned
   change — not silently — and requires updating the independent KAT fixtures this same card
   freezes (`lib-q-hpke/tests/fixtures/independent_key_schedule_kat/vectors.json`), which pin the
   *current* `suite_id` bytes and will correctly fail once the codepoints move, exactly as
   intended.

### Compatibility impact

- `lib-q-hpke` currently ships with `publish = false` commented as "Temporarily disabled publishing
  to avoid CI issues" (`lib-q-hpke/Cargo.toml`) — it is not live on crates.io today. This bounds
  (but does not eliminate) the blast radius: any Enkom-Tech-internal consumer pinning this crate by
  git/path dependency and already exchanging HPKE ciphertexts under the current `0x0022`-`0x0024`/
  `0x0004`-`0x0007` suite IDs would need to renumber in lockstep — there is no silent/compatible
  path, because the suite_id is baked into every derived secret.
- `docs/interoperability.md` already documents these AEAD/KDF IDs as "lib-Q–assigned where not yet
  on an IANA registry — treat third-party interop as profile-gated, not 'generic RFC 9180 DHKEM'"
  and anticipates a future rename ("When IANA or NIST publishes ML-KEM HPKE test vectors aligned
  with this wire layout, prefer replacing or extending rows here") — i.e. the crate already
  expected this kind of realignment might be needed, just not yet that `0x0022` had already been
  claimed by something else.
- No wire bytes are changed by this pass. This section is the recommendation and impact assessment
  the card asked for; the actual renumbering is left to a follow-up change with explicit
  crypto/RED sign-off, per the routing on this card.

## 3. Two adjacent findings surfaced while building the independent KAT (flagged, not fixed)

Neither of these was named in the card; both surfaced while independently reimplementing the key
schedule for task 1 and are recorded here so they are not lost, per the "no code change yet"
posture of this write-up.

- **libQ's `HkdfSha3_256`/`HkdfSha3_512` "HKDF" is not RFC 5869 HKDF.** `HkdfImpl::extract`
  (`lib-q-hpke/src/kdf/hkdf.rs`) computes `Extract(salt, ikm) = Hash(salt || ikm)` — a plain hash
  concatenation, not RFC 5869's `HMAC-Hash(salt, ikm)`. `Expand` is a custom hash-chaining
  construction, not RFC 5869's HMAC-based `T(i)` feedback loop either. This means "HKDF-SHA3-256"
  is a materially different (and less analyzed) construction from what its name claims, independent
  of the codepoint-collision issue above.
- **`HkdfImpl::expand`'s length-prefix is `usize`-width, not fixed-width.** The live extract/expand
  path (`HkdfImpl::expand`, used via `KdfProvider`) absorbs `output_len.to_le_bytes()` — 8 bytes on
  the 64-bit hosts this crate is built and tested on, but 4 bytes on any 32-bit target, notably
  `wasm32-unknown-unknown`, which this crate explicitly supports via its `wasm` feature. A native
  sender and a wasm recipient (or vice versa) using `HkdfSha3_256`/`HkdfSha3_512` would derive
  **different** key schedule outputs for identical inputs, silently. (The separate `extract_static`/
  `expand_static` associated functions in the same file, reachable via the `Kdf` trait but not via
  the live `KdfProvider::extract`/`expand` path, have a related but distinct defect: they truncate
  rather than loop for outputs longer than one hash digest, which would zero-pad rather than derive
  real key material if ever exercised for `output_len` beyond `Nh` — confirmed by reading the code.
  The `Kdf` trait that reaches `extract_static`/`expand_static` is exercised only by `hkdf.rs`'s
  own unit tests (`&dyn Kdf` cast, `#[cfg(test)]`), not by `PostQuantumProvider`/`key_schedule`'s
  live call path, which goes through `HkdfImpl::extract`/`expand` directly — but the buggy
  functions remain `pub` and are one refactor away from becoming reachable.)

Both are real, wire-relevant defects and both are out of scope for this pass's "do not change wire
yet" instruction — recorded here so the reviewer has them, not fixed silently alongside the
in-scope work.
