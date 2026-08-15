# lib-q-saturnin

Rust implementation of the Saturnin post-quantum symmetric algorithm suite.

Saturnin is the primary symmetric suite for HPKE/AEAD tiers in this workspace (see [`lib-q-hpke`](../lib-q-hpke), [`lib-q-aead`](../lib-q-aead)).

## Overview

Saturnin is a lightweight block cipher designed for post-quantum security. This implementation provides AEAD, block cipher, hash, and stream cipher modes.

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
lib-q-saturnin = "0.0.11"
```

### AEAD

```rust
use lib_q_saturnin::{
    Aead,
    AeadKey,
    Nonce,
    Result,
    SaturninAead,
};

fn main() -> Result<()> {
    let aead = SaturninAead::new();
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);

    let ciphertext = aead.encrypt(&key, &nonce, b"data", Some(b"ad"))?;
    let plaintext = aead.decrypt(&key, &nonce, &ciphertext, Some(b"ad"))?;
    assert_eq!(plaintext, b"data");
    Ok(())
}
```

### Saturnin-QCB (one-pass AEAD)

`SaturninQcb` is the one-pass, parallelizable AEAD from "An Update on Saturnin", built on the
Saturnin tweakable block cipher (`SaturninTbc` = `Saturnin16^d_{K⊕T}`). It follows Algorithm 1 of
the QCB paper (Bhaumik et al., ASIACRYPT 2021; IACR ePrint 2020/1304) and that paper's
*Instantiation with Saturnin* paragraph, which fixes the five domain separators: **9** full
message block, **10** final padded message block, **11** full associated-data block, **12** final
padded associated-data block, **13** tag/checksum. Every block — associated data included — is
encrypted with a tweak binding the nonce and the block index, so encryption is rate-one and
embarrassingly parallel.

```rust
use lib_q_saturnin::{
    Aead,
    AeadKey,
    Nonce,
    Result,
    SaturninQcb,
};

fn main() -> Result<()> {
    let aead = SaturninQcb::new();
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);

    let ciphertext = aead.encrypt(&key, &nonce, b"data", Some(b"ad"))?;
    let plaintext = aead.decrypt(&key, &nonce, &ciphertext, Some(b"ad"))?;
    assert_eq!(plaintext, b"data");
    Ok(())
}
```

> ⚠️ **Spec-faithful interpretation, not a byte-compatible reference.** The update note only gives
> a high-level description of Saturnin-QCB; the full mode lives in the separate QCB paper
> (`[BBC+20]`), and no official QCB known-answer tests are published. This implementation follows
> everything the note specifies and documents every gap-filling choice (padding, tweak encoding,
> AD folding) in the [`qcb` module docs](src/qcb.rs). It is verified by round-trip, tamper, and
> pinned self-consistency vectors — not by designer KATs. See [SECURITY.md](SECURITY.md).

### Hash

```rust
use lib_q_saturnin::{Result, SaturninHash};

fn main() -> Result<()> {
    let hash = SaturninHash::new();
    let output = hash.hash(b"data")?;
    assert_eq!(output.len(), 32);
    Ok(())
}
```

### Block Cipher

```rust
use lib_q_saturnin::{Result, SaturninBlockCipher};

fn main() -> Result<()> {
    let cipher = SaturninBlockCipher::new();
    let key = vec![0u8; 32];
    let block = vec![0u8; 32];
    let encrypted = cipher.encrypt_block(&key, &block)?;
    let decrypted = cipher.decrypt_block(&key, &encrypted)?;
    assert_eq!(decrypted, block);
    Ok(())
}
```

### Stream Cipher

```rust
use lib_q_saturnin::{Result, SaturninStream};

fn main() -> Result<()> {
    let stream = SaturninStream::new();
    let key = vec![0u8; 32];
    let nonce = vec![0u8; 16];
    let plaintext = b"Hello, World!";
    let ciphertext = stream.encrypt(&key, &nonce, plaintext)?;
    let decrypted = stream.decrypt(&key, &nonce, &ciphertext)?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}
```

## Features

- `aead` - Authenticated encryption (default)
- `aead-short` — **Saturnin-Short** (spec section 2.3): single `Saturnin^6` block over `pad(nonce ‖ plaintext)`; fixed 32-byte ciphertext, no associated data, plaintext strictly under 128 bits. This is not CTR-Cascade (`aead`). Supports the update note's **shorter-nonce tweak** via `SaturninShortAead::with_nonce_len` (a shorter nonce frees room for longer plaintext: max plaintext = `31 - nonce_len` bytes).
- `qcb` — **Saturnin-QCB** (default): one-pass, parallelizable TBC-based AEAD from the update note. Exposes `SaturninQcb` and the reusable tweakable block cipher `SaturninTbc`. See the caveat above.
- `block-cipher` - Block cipher operations
- `hash` - Hash function
- `stream` - Stream cipher
- `zeroize` - Secure memory zeroization

### Performance features

- `simd` enables runtime SIMD dispatch.
- `simd-avx2` enables AVX2 backend support on `x86_64` (runtime detected).
- `simd-neon` enables NEON backend support on `aarch64` (runtime detected).
- `parallel` enables multi-block parallel helpers on non-WASM targets.

Scalar `core` and `bs32_core` remain the audited reference implementations. SIMD paths are optimized implementations that must remain byte-for-byte equivalent to scalar outputs.

### WebAssembly

The crate builds for `wasm32-unknown-unknown`. Enable the `wasm` feature so that the `getrandom` dependency (via lib-q-core) compiles with `wasm_js`; otherwise the build will fail on that target. The `parallel` feature is not available on `wasm32` (the module is omitted on that target).

Example: `cargo build --target wasm32-unknown-unknown --features wasm`

## Security

- **Designers' security claims** (NIST LWC submission §1.2). These are the designers' *claimed
  floors*, deliberately set below the best-known generic bounds for margin — not measured attack
  costs, and not a flat "256-bit" level:
  - Block cipher, single-key (§2.1): no classical attack with `T/p < 2^224`; no quantum attack
    with `T^2/p < 2^224` (equivalently `T/√p < 2^112`; at success probability `p = 1` this is the
    familiar `T < 2^112`). `p` is the adversary's success probability (spec §1.2). Earlier
    revisions of this file wrote the quantum claim as `T/p < 2^112`, which is a strictly smaller
    region than the designers claim — conservative, but not their inequality.
  - Saturnin-CTR-Cascade (§2.2) and Saturnin-Short (§2.3), single-key: no classical and no quantum
    attack meeting the `2^224` bound of the respective claim box. The submission states verbatim:
    "None of the AE schemes in Saturnin provides security in nonce-misuse, nonce repetition or
    nonce-superposition scenarios."
  - **The spec's IND-qCCA claim for CTR-Cascade rests on a citation that has since been disproved
    — open obligation Q-2** (opened 2026-08-07; applies to plain `SaturninAead`, the frozen mode
    every consumer uses, and to `SaturninAeadCtx`). Spec §4.3 says the modes "are intended to
    provide quantum security against chosen message superposition attacks and superposition
    verification queries (IND-qCCA security)", and §4.3.1 supplies the load-bearing step:
    "Soukharev, Jao and Seshadri have revisited these results [SJS16], and proved that the
    encrypt-then-MAC composition offers IND-qCCA security, assuming that the encryption scheme is
    IND-qCPA, and the MAC is SUF-qCMA." IACR ePrint 2025/387 disproves exactly that: "we disprove
    a claim made by Soukharev et al. at PQCrypto 2016"; "[SJS16, Theorem 3.6] … is inconclusive".
    The conclusion looks **repairable** — 2025/387's own Theorem 3 (EatM of an IND-qCPA scheme
    and a qPRF *is* IND-qCCA), carried to EtM by its Theorem 4 and Corollary 1, needs the MAC to
    be a *qPRF*, and the spec argues precisely that for Cascade via "Theorem 5.1 in [SY17]"
    (§4.3.3), a *stronger* hypothesis than the plus-one one the counterexample defeats — but the
    citation swap is unratified, with the spec's own caveats (constant block count; "This proof
    seems not tight"). **Do not restate the spec's IND-qCCA claim for CTR-Cascade without this
    footnote.** It does not apply to `SaturninQcb`, which is an integrated TBC mode rather than a
    generic composition. Full statement: `src/aead_ctx.rs`; a pointer also sits on the frozen
    mode's own module docs, `src/aead.rs`.
  - Saturnin-Hash (§2.4): no classical collision attack with `T < 2^112`, no classical preimage
    attack with `T < 2^224`, no quantum preimage attack with `T < 2^112`. The quantum *collision*
    claim is not a flat number — verbatim it is "There exists no quantum collision attack
    verifying `T^5 × M_q < 2^448`", where `M_q` is the quantum memory measured in 256-qubit
    registers. `~2^75` is the designers' own worst-corner corollary of that inequality ("In
    particular, the claim for quantum collision attack implies that there is no such attack with
    `T < 2^75`, because we necessarily have `M_q < T`"); at the other corner a memoryless quantum
    attacker (`M_q = 1`) is claimed secure to `T < 2^(448/5) = 2^89.6`. Quote `~2^75` as the
    conservative corner it is, never as the whole claim.
- **Saturnin-QCB's security is an ideal-cipher-model claim, with classical tweaks.** It is not a
  standard-model result and must not be reported as one — Saturnin update note §5: "*In the
  ideal-cipher model*, we can prove the indistinguishability and unforgeability of QCB under
  quantum chosen-plaintext attacks"; QCB paper §6.3: "the first statement holds in the standard
  model, the second in the ideal cipher model", where the second is the one covering a
  block-cipher instantiation like this one. The quantum claim covers superposition *messages*
  only: superposition *tweak* or nonce queries recover the key in `O(256)` queries via Simon's
  algorithm, because in this construction the tweak is the key offset (Rötteler–Steinwandt, IACR
  ePrint 2013/378). And the whole thing assumes Saturnin16 is related-key secure, where the best
  published attack already reaches 10 of its 16 super-rounds. Full statement, quotes and scope:
  `src/qcb.rs` (*Security model*) and [SECURITY.md](SECURITY.md).
- Constant-time operations; AEAD tag verification uses constant-time comparison (see [SECURITY.md](SECURITY.md)).
- **No masked or threshold implementation.** Saturnin has no published DPA- or fault-resistant
  implementation and this crate does not provide one. Do not read "constant-time" as covering
  power or EM side channels — it does not, and it does not cover fault injection either. Two
  published ciphertext-only attacks recover Saturnin's full 256-bit key under faults: 656 faults
  on the block cipher (Li et al., IEEE TIFS 18 (2023) 1487–1496) and 1 097 ineffective faults on
  Saturnin-Short (*Journal on Communications* 44(4) (2023) 167–175). Both need physical access to
  the encrypting device; both are simulation-only; neither proposes a countermeasure. Scope and
  caveats: [SECURITY.md](SECURITY.md) (*Fault injection*).
- Validated against the designers' NIST LWC submission: the scalar core reproduces their generated
  hash, CTR-Cascade and Short KAT vectors. The AVX2 and NEON backends have **not** been compared
  against that reference — see [docs/HARDWARE.md](docs/HARDWARE.md) §6.

## Implementing Saturnin in hardware

[docs/HARDWARE.md](docs/HARDWARE.md) collects what building this twice taught us: the one-core /
one-datapath property and its evidence, why the round constants must be generated rather than
ROMed, the RC packing convention written as normative prose, the fact that the S-box and MDS are
**not** involutions (so an inverse datapath is real area), and a catalogue of the four defects that
survived a green test suite here.

## Performance

Typical throughput on modern hardware:
- AEAD: ~200-400 MB/s
- Hash: ~400-600 MB/s
- Block cipher: ~150-300 MB/s
- Stream cipher: ~250-450 MB/s

### `SaturninQcb`'s CTX overhead (card `t_16ddf21c`)

The CTX committing transform (see the Key commitment section below) adds a fixed number of
Saturnin permutation calls per message — asymptotically free, but a real cost on small messages,
where it is most of the total work. It is measured by the checked-in
`benches/qcb_ctx_overhead.rs` criterion suite, which compares the shipped committing path against
a `#[doc(hidden)]`, bench-only uncommitted path. There is deliberately no Cargo feature that
disables the commitment: a published crate with a "turn the security property off" flag is a
footgun, so the two arms exist only inside the benchmark.

**No percentage is published here, on purpose.** Two things reproduce and one does not:

- **Reproduces — direction and separability at packet sizes.** At the networking shape (64 B
  message, 16 B AD), every one of five independent runs put the committing arm above the
  uncommitted arm with non-overlapping criterion confidence intervals. The effect is real and it
  is measurable.
- **Reproduces — no measurable cost at blob sizes.** At the data-at-rest shape (1 MiB message,
  32 B AD) the two arms are *not* separable from noise; the sign of the difference flips between
  runs. Read that as "below this harness's resolution", not as "zero".
- **Does not reproduce — the magnitude.** Across those same five runs the encrypt overhead at the
  networking shape ranged **+37% to +103%**, and decrypt **+28% to +123%**. Criterion's per-
  benchmark interval measures variance *within* a sampling window and does not capture drift
  *between* windows, which is why each individual run looks tight and the set of runs does not.
  Any single number taken from one run — including the `+~95%` this section used to print — is
  inside that envelope and is not evidence for a band.

The AD-sweep growth is structural, not a measurement artefact: CTX hashes the associated data a
**second** time (once in QCB's own AD pass, once again inside the CTX tag), so it is the one part
of this transform's cost that is not O(1) in the associated-data length.

Do **not** reach for the "cheap CMT-1-only variant" that earlier notes on card `t_16ddf21c`
suggested this motivates. The obvious construction — one extra tweakable-Davies–Meyer Saturnin
call for short AD — is refuted twice over: Saturnin's TBC is `Saturnin16^d_{K ⊕ T}`, so one call
absorbs at most 512 bits while the hash input needs 80 bytes before any AD; and the `K ⊕ T`
encoding is not injective, which combined with QCB's invertible tag is an O(1) CMT-4 break rather
than the 2^128 it appears to offer.

Also measured by the same suite, and relevant to any decision about which mode to default to:
QCB is **slower than `SaturninAead` (CTR-Cascade) at packet sizes** and faster only from ~1 KiB
up, before CTX is considered at all. Criterion reports throughput in MiB/s; do not re-label those
figures MB/s when quoting them.

## Testing

```bash
cargo test --all-features
cargo bench
```

### SIMD validation matrix

```bash
# Scalar reference path
cargo test -p lib-q-saturnin --features "alloc,aead,aead-short,block-cipher,hash,stream"

# AVX2-enabled path (x86_64)
cargo test -p lib-q-saturnin --features "alloc,aead,aead-short,block-cipher,hash,stream,simd-avx2"

# NEON-enabled path (aarch64)
cargo test -p lib-q-saturnin --features "alloc,aead,aead-short,block-cipher,hash,stream,simd-neon"
```

### Benchmark protocol

- Run on an otherwise idle machine with fixed CPU frequency governor when possible.
- Collect scalar baseline first, then collect SIMD-enabled results on the same machine.
- Use identical workload sizes and warmup/sample settings for all runs.
- Report bytes/second and relative speedup (`simd / scalar`) for each workload.

Recommended commands:

```bash
# Scalar baseline
cargo bench -p lib-q-saturnin --features "alloc,aead,block-cipher,hash,stream"

# AVX2 benchmark run
cargo bench -p lib-q-saturnin --features "alloc,aead,block-cipher,hash,stream,simd-avx2"
```

### Performance acceptance gates

When evaluating SIMD changes, use these minimum expected speedups against scalar baseline on the same host:

- Hash throughput: `>= 1.30x`
- Stream throughput: `>= 1.25x`
- Block single-block encryption: `>= 1.05x`

If a change does not meet these thresholds, keep it behind feature gates until further optimization or analysis is completed.

## License

See the main [lib-q license](../LICENSE).

## Contributing

See the main [lib-q contributing guide](../CONTRIBUTING.md).

## Key commitment (CMT-1)

**`SaturninQcb` and `SaturninAeadCtx` apply a committing transform (CTX); no other libQ AEAD is
key-committing, and none of the rest claims to be.** CMT-1 asks whether one ciphertext can be made
to decrypt successfully under two *distinct* keys, with the nonce and associated data free on each
side. That property is not part of the AEAD security goal most of these modes were designed for;
outside those two types, libQ does not provide it — and in particular plain `SaturninAead`
(CTR-Cascade), the mode every real consumer uses, still does not provide it on its own.

**Do not use any libQ AEAD other than `SaturninQcb` or `SaturninAeadCtx` for multi-recipient
encryption, key wrapping / envelope encryption, or password-based decryption as an identification
or authorization signal without binding the key externally** — e.g. put `H(key ‖ context)` in the
associated data, or carry an explicit key commitment beside the ciphertext (`lib-q-mve` does the
latter: see `MVE_COMMIT_LABEL`). Even for `SaturninQcb`/`SaturninAeadCtx`, treat this as **claimed,
not proven**: see the table rows and the sign-off obligations in `lib-q-saturnin/src/commit.rs`
(shared H-1) and `lib-q-saturnin/src/aead_ctx.rs` (Q-1′ and Q-2, and why S-2 does not apply
there). **On 2026-08-07 the primary sources were read and the register moved in both directions,
but nothing closed**: S-2 narrowed (Chan–Rogaway's Theorem 2 consumes only injectivity, not the
length-preserving bijectivity their §4 prose asserts), Q-1/Q-1′ *widened* (CTX's nAE-preservation
proof is not merely *stated* classically — its authenticity reduction recovers the base tag by
replaying a recorded table of the adversary's hash queries, which superposition queries forbid,
and no QROM treatment of CTX exists in the committing-AE literature through 2026), and three new
obligations were opened: **L-1** (Chan–Rogaway's Theorem 3 is single-user and
single-verification-query — Bellare–Hoang, IACR ePrint 2024/875 p.12; applies to both types),
**RK-1** (`SaturninQcb` only), and **Q-2** (CTR-Cascade's own IND-qCCA claim; applies to the
frozen `SaturninAead` too). Read none of Q-1/Q-1′ as a formality.

One mode, `SaturninShortAead`, has a **demonstrated** break: a test produces one ciphertext that
decrypts successfully under two distinct keys. `SaturninQcb` had a break of the same class; it is
retained verbatim as a regression test (`lib-q-saturnin/tests/key_commitment.rs`) and now fails tag
verification on every one of 200 independent instances (see the table). For the other seven a
bounded search found nothing, which is **not** evidence that they commit — read the box under the
table before quoting any row of it.

| Mode | Key / tag | CMT-1 status |
|---|---|---|
| `SaturninQcb` | 256 / 256-bit | **CTX applied** (Chan and Rogaway, *On Committing Authenticated-Encryption*, ESORICS 2022; IACR ePrint 2022/1260), instantiated with Saturnin-Hash: the transmitted tag is `T' = SaturninHash(label ‖ K ‖ N ‖ T ‖ A)`, replacing the raw, XOR-decomposable `T`. **Claimed** CMT-4, bounded by Saturnin-Hash's own designer-claimed collision resistance — **2^112 classical, ~2^75 quantum** — the designers' claimed floor. The quantum figure is not a flat claim but the worst corner of a time–memory one, verbatim "There exists no quantum collision attack verifying `T^5 × M_q < 2^448`" with `M_q` the quantum memory in 256-qubit registers; `~2^75` is the designers' own `M_q → T` corollary, and a memoryless attacker (`M_q = 1`) gets 2^89.6 from the same inequality — quote 2^75 as the conservative corner, never as the whole claim. Best-known generic classical cost is 2^128 by the birthday bound (spec §5.4.1), claimed below that for margin ("additional constant factors that these bounds do not take into account, which is why our final security claims are reduced"), not a NIST-LWC floor; the claim sits below all three generic quantum collision costs at n = 256: 2^85.3 = 2^(n/3) with 2^85.3 qRAM (Brassard–Høyer–Tapp, LATIN '98), 2^102.4 = 2^(2n/5) with no qRAM but 2^51.2 classical memory (Chailloux–Naya-Plasencia–Schrottenloher, 2017), and 2^128 memoryless — and marked **RED**, pending human cryptographer sign-off on **five** named obligations, H-1, S-2, Q-1, L-1 and RK-1 (`lib-q-saturnin/src/commit.rs`). The 2026-08-07 primary-source review narrowed **S-2** (Chan–Rogaway's Theorem 2 consumes only injectivity, not the length-preserving bijectivity their §4 prose asserts; the residual is a reviewer confirmation, and it also surfaced a *second* violated syntactic requirement, Chan–Rogaway's constant expansion `τ`, which our padding breaks by 33–64 bytes), widened **Q-1** (Theorem 3's authenticity reduction is classical transcript replay, not merely a classically-stated proof — see the row note above), and opened **L-1** (Theorem 3 is single-user and single-verification-query) and **RK-1** (QCB's key-tweak insertion uses `Φ_⊕` over up to 2^95 related keys, while the designers claim Saturnin16 related-key security only "against related-key attacks involving a small number of keys"). Nothing closed. The closed-form attack below (mean **270** padding-search tries ≈ **~546 Saturnin block calls**, median 191, min 2, max 2492, **0** tag searches, over 200 independent key pairs, all of which broke pre-CTX) is retained as a regression test and now fails on every instance. |
| `SaturninShortAead` | 256-bit / no tag | **BROKEN.** ~2^8 random keys at any nonce length, including the 16-byte default — the nonce *is* the redundancy and CMT-1 lets the adversary choose it. Measured acceptance **78 / 20 000** random keys (0.0039, predicted 2^-8). **Not committing and will not be made so:** any fix adds bytes, and a committing Short is size-dominated by `SaturninQcb` at the same ciphertext length with strictly more payload room (see `lib-q-saturnin/src/aead_short.rs`). |
| `SaturninAead` (CTR-Cascade) | 256 / 256-bit | no cheap break found — **not shown to commit**; wire format is **frozen** (data-at-rest: My-Grid vault, My-Grid recovery, GIP `bitlink-wrapkey-argon2id-v1` all decrypt through this type) and left unmodified. Its committing sibling is the opt-in `SaturninAeadCtx` (below), a *separate, wire-incompatible type* — never a flag on this one. Separately from commitment, and new on 2026-08-07: the Saturnin spec's **IND-qCCA** claim for this mode rests on the Soukharev–Jao–Seshadri composition theorem, which IACR ePrint 2025/387 disproves — open obligation **Q-2**, see the Security section above. |
| `SaturninAeadCtx` (CTX on CTR-Cascade) | 256 / 256-bit | **CTX applied** (Chan and Rogaway, ESORICS 2022; IACR ePrint 2022/1260), instantiated with Saturnin-Hash: `T' = SaturninHash(label ‖ K ‖ N ‖ T ‖ A)` over CTR-Cascade's own tag `T`. **Claimed** CMT-4, bounded by the same Saturnin-Hash collision-resistance claim as `SaturninQcb` (2^112 classical, ~2^75 quantum) — **RED**, pending sign-off on **H-1** (shared with `SaturninQcb`), **Q-1′** (CTX's nAE-preservation proof is classical-ROM — *structurally*, not just notationally: its authenticity reduction replays a recorded table of the adversary's hash queries, which no-cloning forbids under superposition; whether it preserves CTR-Cascade's own quantum-adversary claims is open), **L-1** (Chan–Rogaway's Theorem 3 is single-user and single-verification-query — "Chan and Rogaway [16] only consider a restricted setting where the adversary attacks just a single user, and it can only make a single verification query", Bellare–Hoang, IACR ePrint 2024/875 p.12; shared with `SaturninQcb`) and **Q-2** (the Saturnin spec's IND-qCCA claim for CTR-Cascade cites Soukharev–Jao–Seshadri [SJS16], whose EtM composition theorem was *disproved* in IACR ePrint 2025/387; the conclusion looks repairable via that paper's Theorem 3, carried to EtM by its Theorem 4 and Corollary 1, since the spec argues the stronger qPRF hypothesis for Cascade rather than mere plus-one unforgeability — but that citation swap is unratified, and Q-2 lands on the frozen `SaturninAead` too). **S-2 does not apply to this instantiation**: CTR-Cascade is a stream mode (`|C| == |M|` exactly, no message padding), which satisfies Chan–Rogaway Theorem 2's length/bijectivity hypothesis natively — on that axis this instantiation rests on *firmer* ground than CTX-on-QCB. Ciphertext from this type is never interchangeable with plain `SaturninAead`'s (see `tests/cascade_ctx_spec.rs::cross_mode_ciphertexts_rejected`); adopting it for stored data means minting a new format tag, not switching the AEAD under an existing one. **The two types are wire-incompatible but not keystream-independent:** only the tag differs, and CTR-Cascade's keystream depends on `(K, N)` alone, so encrypting different plaintexts under the same key and nonce with the two types is a two-time pad. A migration re-encrypt MUST draw a **fresh nonce**. See `src/aead_ctx.rs` for the full argument. |
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
# the SaturninAead wire-format freeze guard, and the CTX-on-CTR-Cascade byte-layout / binding gate
cargo test -p lib-q-saturnin --test aead_kat_pin --features aead -- --nocapture
cargo test -p lib-q-saturnin --test cascade_ctx_spec --features "aead,hash" -- --nocapture
# the still-live SaturninShortAead break
cargo test -p lib-q-saturnin --features aead-short --lib key_commitment_tests -- --nocapture
# the bounded searches for the registry modes
cargo test -p lib-q-aead \
  --features "saturnin,duplex-sponge-aead,tweak-aead,romulus-n,romulus-m,rocca-s" \
  --test key_commitment -- --nocapture
```

Sources: `lib-q-saturnin/src/commit.rs`, `lib-q-saturnin/src/aead_ctx.rs`,
`lib-q-saturnin/tests/key_commitment.rs`, `lib-q-saturnin/tests/qcb_ctx_spec.rs`,
`lib-q-saturnin/tests/aead_kat_pin.rs`, `lib-q-saturnin/tests/cascade_ctx_spec.rs`,
`lib-q-saturnin/src/aead_short.rs` (`key_commitment_tests`), `lib-q-aead/tests/key_commitment.rs`.
Card `t_16ddf21c`.

### Nonce extension (XChaCha-style) — evaluated and deliberately not pursued

Every libQ AEAD uses a **128-bit nonce**. XChaCha20-Poly1305 exists to stretch a 96-bit nonce to
192 bits so that *random* nonces stop colliding around 2^32 messages per key; at 128 bits the
birthday bound is already 2^64, beyond any realistic message volume. Nonce extension therefore buys
nothing here and is not planned — please do not re-raise it. The adjacent gap that *is* real is key
and context commitment, above.

### Saturnin specifics — who actually gets which mode

`SaturninQcb` and `SaturninShortAead` were the two modes with a **demonstrated** CMT-1 break, both
proven by tests in this crate. `SaturninQcb`'s break is now closed by the CTX transform above (RED,
pending sign-off); `SaturninShortAead`'s is not, and will not be (see the table). Their exposure is
**not** symmetric:

- **`aead-short` is opt-in.** `SaturninShortAead` is compiled only if you ask for it
  (`Cargo.toml:27`; not in `default`).
- **`qcb` is a DEFAULT feature** (`Cargo.toml:21`: `default = ["std", "aead", "block-cipher",
  "hash", "stream", "qcb", "alloc"]`), and now **implies `hash`** (`Cargo.toml`: `qcb =
  ["dep:zeroize", "hash"]`) because the CTX tag is computed with `SaturninHash`. Any crate that
  depends on `lib-q-saturnin` without `default-features = false` compiles `SaturninQcb` (CTX
  included) and can call it — no opt-in required. Inside this workspace that is `lib-q-aead`
  (`Cargo.toml:24`) and `lib-q-hpke` (`Cargo.toml:45`), both of which omit
  `default-features = false`; `cargo tree -p lib-q-aead --features saturnin -e features` lists
  `lib-q-saturnin feature "qcb"`. (Neither crate re-exports the type, so the mode is compiled but
  not reachable through their APIs.) `lib-q-random` (`Cargo.toml:28`) and GIP's
  `sdk/Cargo.toml:197` do pass `default-features = false` and are unaffected.

**Superseded:** a prior revision of this README recorded an open decision on whether `qcb` should
remain a default feature *because of the demonstrated break*. CTX closes that specific reachability
risk — any crate compiling `SaturninQcb` by default now compiles the committing version — so that
question is resolved for the break itself. A narrower question remains open: whether it is
acceptable for a **RED** (unsigned) cryptographic claim to ship on a default feature path at all,
pending the sign-off obligations in `lib-q-saturnin/src/commit.rs`. `SaturninShortAead` carries no
such transform and stays opt-in and documented as non-committing.
