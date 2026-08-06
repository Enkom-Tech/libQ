# Security notes — Romulus AEAD (`lib-q-romulus`)

## Decrypt / verify schedule (facade)

`RomulusNAead` / `RomulusMAead` delegate to `romulus_n_decrypt` / `romulus_m_decrypt` in this crate. Both perform in-place decryption of the ciphertext body, derive the expected tag from the internal state, then **constant-time compare** (`subtle`) to the received tag. On mismatch, the plaintext buffer is **zeroed** before returning an error (Layer A) or before reporting `DecryptSemanticOutcome::AuthenticationFailed` (Layer B).

## Layer B

`lib_q_core::AeadDecryptSemantic` is implemented on the facade types using the same single-pass `romulus_n_decrypt_core` / `romulus_m_decrypt_core` as the in-place APIs—no second decrypt of the message.

## Key commitment (CMT-1)

**`SaturninQcb` now applies a committing transform (CTX); no other libQ AEAD is key-committing, and
none of the rest claims to be.** CMT-1 asks whether one ciphertext can be made to decrypt
successfully under two *distinct* keys, with the nonce and associated data free on each side. That
property is not part of the AEAD security goal most of these modes were designed for; outside
`SaturninQcb`, libQ does not provide it.

**Do not use any libQ AEAD other than `SaturninQcb` for multi-recipient encryption, key wrapping /
envelope encryption, or password-based decryption as an identification or authorization signal
without binding the key externally** — e.g. put `H(key ‖ context)` in the associated data, or carry
an explicit key commitment beside the ciphertext (`lib-q-mve` does the latter: see
`MVE_COMMIT_LABEL`). Even for `SaturninQcb`, treat this as **claimed, not proven**: see the table row
and the sign-off obligations in `lib-q-saturnin/src/commit.rs`.

One mode, `SaturninShortAead`, has a **demonstrated** break: a test produces one ciphertext that
decrypts successfully under two distinct keys. `SaturninQcb` had a break of the same class; it is
retained verbatim as a regression test (`lib-q-saturnin/tests/key_commitment.rs`) and now fails tag
verification on every one of 200 independent instances (see the table). For the other seven a
bounded search found nothing, which is **not** evidence that they commit — read the box under the
table before quoting any row of it.

| Mode | Key / tag | CMT-1 status |
|---|---|---|
| `SaturninQcb` | 256 / 256-bit | **CTX applied** (Chan and Rogaway, *On Committing Authenticated-Encryption*, ESORICS 2022; IACR ePrint 2022/1260), instantiated with Saturnin-Hash: the transmitted tag is `T' = SaturninHash(label ‖ K ‖ N ‖ T ‖ A)`, replacing the raw, XOR-decomposable `T`. **Claimed** CMT-4, bounded by Saturnin-Hash's own designer-claimed collision resistance — **2^112 classical, ~2^75 quantum** (not 2^128) — and marked **RED**, pending human cryptographer sign-off on three named obligations (`lib-q-saturnin/src/commit.rs`). The closed-form attack below (mean **270** padding-search tries ≈ **~546 Saturnin block calls**, median 191, min 2, max 2492, **0** tag searches, over 200 independent key pairs, all of which broke pre-CTX) is retained as a regression test and now fails on every instance. |
| `SaturninShortAead` | 256-bit / no tag | **BROKEN.** ~2^8 random keys at any nonce length, including the 16-byte default — the nonce *is* the redundancy and CMT-1 lets the adversary choose it. Measured acceptance **78 / 20 000** random keys (0.0039, predicted 2^-8). **Not committing and will not be made so:** any fix adds bytes, and a committing Short is size-dominated by `SaturninQcb` at the same ciphertext length with strictly more payload room (see `lib-q-saturnin/src/aead_short.rs`). |
| `SaturninAead` (CTR-Cascade) | 256 / 256-bit | no cheap break found — **not shown to commit**; not given a committing transform by this change (open follow-up, card `t_16ddf21c`) |
| `Shake256Aead` | 256 / 256-bit | no cheap break found — **not shown to commit** |
| `DuplexSpongeAead` | 256 / 256-bit | no cheap break found — **not shown to commit** |
| `TweakAead` | 256 / 256-bit | no cheap break found — **not shown to commit**. Its tag is a sponge hash of `key ‖ nonce ‖ ad ‖ ct`, which is the *shape* a committing mode has; that is an argument for looking here first, not a result. |
| `RoccaSAead` | 256 / 256-bit | no cheap break found — **not shown to commit** |
| `RomulusN` / `RomulusM` | 128 / **128-bit** | no cheap break found — **not shown to commit**. With a 128-bit tag the *generic* CMT-1 cost is only ~2^64, the weakest margin in the set. |

> **The "no cheap break found" rows are not evidence of key commitment and must never be quoted as
> if they were.** Each comes from 20 000 random `(key, nonce, associated-data)` trials against a
> fixed ciphertext. Against a 256-bit tag the expected yield of that search is ~2^-242 hits, so it
> returns zero *whether or not* the mode commits — and it would return zero just the same against
> a mode with a 2^40 structural break the search does not model. All those rows rule out is the
> class of break the two Saturnin modes fell into: one cheap enough for ~2^14 trials to stumble
> onto.
>
> Demonstrating the positive — that a mode *is* committing — is not achievable by search at these
> tag sizes at all, however many trials are run. It needs a proof, or a committing transform (bind
> `H(key ‖ nonce ‖ associated data)` into the tag) that changes the construction. `SaturninQcb` now
> has one (above — claimed, and RED pending sign-off); the rest of libQ does not, which is why no
> other row above reads "committing".

Reproduce (each prints its own measurements with `--nocapture`):

```sh
# the retained (now-defeated) QCB attack, and the CTX byte-layout / binding gate
cargo test -p lib-q-saturnin --test key_commitment -- --nocapture
cargo test -p lib-q-saturnin --test qcb_ctx_spec -- --nocapture
# the still-live SaturninShortAead break
cargo test -p lib-q-saturnin --features aead-short --lib key_commitment_tests -- --nocapture
# the bounded searches for the registry modes
cargo test -p lib-q-aead \
  --features "saturnin,duplex-sponge-aead,tweak-aead,romulus-n,romulus-m,rocca-s" \
  --test key_commitment -- --nocapture
```

Sources: `lib-q-saturnin/src/commit.rs`, `lib-q-saturnin/tests/key_commitment.rs`,
`lib-q-saturnin/tests/qcb_ctx_spec.rs`, `lib-q-saturnin/src/aead_short.rs`
(`key_commitment_tests`), `lib-q-aead/tests/key_commitment.rs`. Card `t_16ddf21c`.

### Nonce extension (XChaCha-style) — evaluated and deliberately not pursued

Every libQ AEAD uses a **128-bit nonce**. XChaCha20-Poly1305 exists to stretch a 96-bit nonce to
192 bits so that *random* nonces stop colliding around 2^32 messages per key; at 128 bits the
birthday bound is already 2^64, beyond any realistic message volume. Nonce extension therefore buys
nothing here and is not planned — please do not re-raise it. The adjacent gap that *is* real is key
and context commitment, above.

### Romulus specifics

Romulus-N and Romulus-M carry a **128-bit** tag (`AeadCore::TagSize = U16`), where every other
libQ AEAD carries 256 bits. The generic cost of a CMT-1 collision is therefore ~2^64, not ~2^128.
If you are choosing Romulus-M for its nonce-misuse resistance, be aware you are simultaneously
choosing the weakest key-commitment margin in the suite, and bind the key into the associated data.
