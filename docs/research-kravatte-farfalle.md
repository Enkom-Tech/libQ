# Kravatte-SANSE and Kravatte-WBC (Farfalle) for lib-Q — research note

Status: research note, no code changed. Question: should lib-Q carry the Keccak team's Farfalle
constructions — Kravatte-SANSE (nonce-misuse-resistant session AEAD) and Kravatte-WBC (tweakable
wide-block cipher) — for the places in the downstream ecosystem where nonce uniqueness is hard or a
wide block would help? Keyak is out of scope (CAESAR finalist, not in the final portfolio, nothing it
does that the TurboSHAKE duplex AEAD does not).

Legend: **[V]** verified here by reading source, fetching the cited page or running the command
shown; **[I]** inferred or taken from the literature without re-derivation here. Every number
below is tagged one way or the other.

## 1. Answer

**Do not implement Kravatte-SANSE or Kravatte-WBC now.** Neither closes a gap lib-Q actually has:

1. **Misuse resistance already exists at the 256-bit level.** [V] `lib-q-aead/src/saturnin_siv.rs`
   (`SaturninSiv`, feature `saturnin-siv`) is a Rogaway–Shrimpton SIV composition of KMAC256 and
   Saturnin-CTR with a 256-bit key and tag. Kravatte-SANSE is the same security class — an SIV mode
   over a deck function — and under nonce repetition leaks exactly what every deterministic AE leaks:
   plaintext *equality*, nothing else (§3). Swapping one SIV for another buys no security.
2. **The misuse-resistant mode's real gap is review and registration, not the primitive.** [V]
   `SaturninSiv` is not in the `AeadRegistry` ("registration is keyed on a `lib_q_types::Algorithm`
   variant, and adding one is a change to `lib-q-types`", `lib-q-aead/src/lib.rs`), has no row in
   `docs/crypto-signoff-register.md` (`rg SaturninSiv docs/crypto-signoff-register.md` → no match),
   and its KATs are self-generated (`kats-manifest.toml`, entry for
   `lib-q-aead/tests/vectors/saturnin_siv_kat.txt`, `origin = "self-generated"`). A downstream
   search-index crate already consumes it. Kravatte would arrive in the same unreviewed state and
   would then be the *second* unreviewed misuse-resistant mode.
3. **There is no wide-block consumer.** [V] The appliance OS has no at-rest cryptography in its
   current version (its state-database decision records "no at-rest cryptography in v0"; disk
   encryption is deferred to a storage layer that does not exist yet). The backup/sync product
   deduplicates on plaintext chunk hashes before encryption and seals blobs with an existing
   chunked envelope. Nothing today needs length-preserving encryption of a sector or a block.
4. **Cryptanalytic margin is the thinnest in the Keccak family and the designers have moved on.**
   [V] Kravatte uses Keccak-p[1600] reduced to **6 rounds** in every layer; the 2018 attacks reached
   the full pre-tweak function and were stopped only by the Achouffe tweak (§2). The designers' own
   AE work since 2022 is built on SHAKE / TurboSHAKE (12 rounds) duplex and deck ciphers, i.e. the
   family lib-Q's `aead_id = 17` TurboSHAKE duplex already belongs to.

What *would* justify revisiting (§5): a bulk at-rest path (disk, backup streams) that needs
Keccak-only, parallel, misuse-resistant or length-preserving encryption at high throughput. Farfalle's
parallel compression/expansion is its genuine advantage over a duplex, and Kravatte-SANSE at
0.92 cycles/byte on an AVX-512 core (designers' figure, §2.3) is roughly an order of magnitude
faster than lib-Q's Saturnin in software. When that consumer appears, compare Kravatte against the
designers' current deck-based wide-block work (double-decker, §2.3), not against Saturnin.

## 2. Kravatte: construction, the 2018 attacks, the Achouffe tweak, and since

### 2.1 What it is [V, abstracts and keccak.team pages fetched 2026-11-23]

Farfalle (Bertoni, Daemen, Hoffert, Peeters, Van Assche, Van Keer; ePrint 2016/1188, ToSC 2017(4))
is a construction for a *deck function* — a keyed function with variable-length inputs and
arbitrary-length output — with a parallel compression layer, a parallel expansion layer, and
LFSR-like rolling functions for the input masks and the expansion state. Kravatte is its
Keccak-p[1600] instance: "the permutations in the compression and expansion layers of Kravatte have
only 6 rounds apiece and the rolling functions are lightweight" (abstract). On top of Kravatte the
designers define (ePrint 2018/1012, and keccak.team/kravatte.html):

- **Kravatte-SANE** — session AEAD, nonce-respecting;
- **Kravatte-SANSE** — session AEAD "using the synthetic initial value (SIV) technique, robust under
  nonce repetitions";
- **Kravatte-WBC** — "a wide-block cipher for authenticated encryption with minimal expansion"
  (a four-round Feistel over two large branches, generalised later as *double-decker*).

The reference implementation is in XKCP (`lib/high/Kravatte/Kravatte.c`, `KravatteModes.h`). [V]
`KravatteModes.h` defines `Kravatte_SANE_TagLength 16` and `Kravatte_SANSE_TagLength 32`.

### 2.2 Cryptanalysis [V, from keccak.team/third_party.html and ePrint abstracts; complexities quoted as published]

| Year | Result | Target | Complexity | Status against Kravatte Achouffe |
|---|---|---|---|---|
| 2017 | Guo, Song, *Cube Attack against Full Kravatte* (ePrint 2017/1026) | "the current version of full Kravatte" at the time; and v1 | 2^136.01 data+time; v1: 2^38.04 ("could be carried out in practice") | pre-tweak versions |
| 2018 | Chaigneau, Fuhr, Gilbert, Guo, Jean, Reinhard, Song, *Key-Recovery Attacks on Full Kravatte* (ToSC 2018) | Kravatte 6644, and the variant with 6 rounds in all four permutations | key recovery by higher-order differential and algebraic attacks on the expansion phase | designers: "their attacks do not extend to the final version of Kravatte, namely Kravatte Achouffe. The authors … communicate[d] their results to us during the review process of our Farfalle paper submission to ToSC, allowing us to tweak Kravatte accordingly." |
| 2019 | Bonnetain, Hosoyamada, Naya-Plasencia, Sasaki, Schrottenloher, *Quantum Attacks Without Superposition Queries: The Offline Simon's Algorithm* (Asiacrypt 2019) | Kravatte, Xoofff | "would cost 2^533 data and time" (Kravatte) and "2^128 data" (Xoofff) | far above any claim; of structural interest only |
| 2020 | Zhou, Zong, Dong, Jia, Meier, *Interpolation Attacks on Round-Reduced Elephant, Kravatte and Xoofff* (ePrint 2020/781) | Kravatte 6644 and **round-reduced** Kravatte / Xoofff | "cover 8 rounds of the underlying permutation", 2^78 blocks data (Kravatte), 2^90–2^112 operations | reduced-round only; designers list it as "the most efficient method for these ciphers thus far" |
| 2020 | Cui, Grassi, *Algebraic Key-Recovery Attacks on Reduced-Round Xoofff* (SAC 2020) | Xoofff with expansion reduced to 4 of 6 rounds; 9 of 12 total | 2^106 time, 2^70 memory | Xoofff, not Kravatte; same family, same shape of weakness ("non-ideal interaction between the expanding rolling function and the … permutation") |

No attack on full Kravatte Achouffe is listed on the designers' third-party page as of the fetch
date. [V]

**The Achouffe tweak** is the designers' response to the 2018 attacks. [V] From the XKCP source
(`Kravatte.c`): the expansion rolling function `Kravatte_Rolle` works over ten lanes and is
non-linear — its update is `x9 = ROL64(t, 7) ^ ROL64(x0, 18) ^ (x1 & (x0 >> 1))` — while the
compression roll `Kravatte_Rollc` is a five-lane linear LFSR, and the expansion permutation is
`KeccakP1600_Permute_Nrounds(&state, 6)`. [I] The pre-tweak Kravatte 6644 used a *linear* rolling
function in the expansion layer and fewer rounds in the inner permutations; the 2018 attacks
exploited the low algebraic degree of the expansion phase, and the non-linear roll is what breaks the
algebraic structure they used. The published version of ePrint 2016/1188 describes the tweaked
function (its abstract already says "only 6 rounds apiece"); the PDFs were not readable from this
environment (HTTP 403), so the pre-tweak parameters are stated from memory and marked [I].

**Margin, honestly stated.** Kravatte's security rests on 6-round Keccak-p and on the Farfalle
construction's *claim* (no proof reduces it to the permutation). The best published attacks reach
8 of the rounds across the expansion path at 2^78 data on a reduced variant; the full function has
12 rounds on that path (6 + 6). For comparison [V, same third-party page], the best keyed-mode
results on Keccak-p[1600] constructions with more rounds are KMAC256 reduced to 9 rounds at 2^139
(Li et al., ToSC 2019) and "a general attack on the full-state keyed duplex with Keccak-p[1600,
n_r=9] of complexity 2^90" (Song et al., Asiacrypt 2018); TurboSHAKE and the `aead_id = 17` duplex use
12 rounds. Kravatte therefore has about one third the round margin of the TurboSHAKE family for
roughly the same attack reach, which is the price of its speed.

### 2.3 Standardisation and deployment since 2018 [V unless marked]

- **No standard.** Kravatte is not in FIPS 202, SP 800-185 or RFC 9861, was not a NIST LWC
  submission (Xoodyak was), and no IETF/CFRG or ISO document specifies it. The NIST "accordion
  cipher mode" effort (workshop, June 2024; csrc.nist.gov) is defined as a mode "with a reduction
  proof to the security of the underlying block cipher" — an AES-based wide-block path, not a
  permutation-based one.
- **Deployment is reference-code only.** XKCP ships SANE/SANSE/WBC. PyPI `kravatte` 1.2.0, last
  upload 2018-12-02, 5 releases. crates.io has no `kravatte`, `farfalle` or `kravatte-sanse` crate
  (a third-party `xoofff` 0.1.3 exists, updated 2023-11-25). No mainstream library (libsodium,
  Botan, OpenSSL, Go x/crypto, RustCrypto) carries it [I — absence checked only via crates.io and
  PyPI here].
- **Designers' direction.** The Keccak team's later AE work is *Jammin' on the deck* (ePrint
  2022/531: deck-function AE modes with "varying levels of robustness", the "jammin cipher" ideal),
  *Committing authenticated encryption based on SHAKE* (ePrint 2023/1494: confidentiality,
  integrity and commitment "provably reduce[d] … to the security of an underlying sponge function",
  instantiated with SHAKE and TurboSHAKE) and *Shaking up authenticated encryption* (ePrint
  2024/1618: session AE over SHAKE128/256 and their Turbo counterparts, CMT-4 committing, "do not
  suffer from a 64-bit birthday bound"). Wide-block work moved to deck-based *double-decker* and
  *docked-double-decker* (Gunsing, Daemen, Mennink, ePrint 2022/247: "double-decker is a direct
  generalization of Farfalle-WBC", with a proof in the blinded-keyed-hashing model and SSD-sector
  encryption as a named use case) and to *Mystrium* (ePrint 2024/1474: double-decker with a new deck
  function, 6.8 c/B for 4096-byte sectors on Cortex-A7 versus 11.5 for Adiantum). Farfalle itself
  is also the ancestor of MPC-oriented PRFs (Ciminion, Hydra) — unrelated to this question.
- **Performance (designers' table, keccak.team/sw_performance.html, cycles/byte, long messages, XKCP
  with AVX-512 on "SkylakeX"):** Kravatte MAC 0.30, keystream 0.41, SANE plaintext 0.92, **SANSE
  0.92**, **WBC 1.28**; AES-128-GCM 1.55 on the same machine; on Haswell (AVX2) SANSE 1.63, WBC
  2.42. lib-Q's own README gives Saturnin AEAD at "~200–400 MB/s" (`lib-q-saturnin/README.md`,
  machine unspecified), i.e. roughly 8–15 c/B at 3 GHz [I — unit conversion, not measured here].

## 3. What lib-Q already has, measured

All lib-Q registry AEADs take a 32-byte key and 16-byte nonce; the misuse-degradation probe was run
here [V]:

```
cargo test -p lib-q-aead --features romulus-m,duplex-sponge-aead,saturnin,saturnin-siv \
  --test nonce_misuse -- --nocapture --test-threads=1
# 22 passed; 0 failed
```

| Mode (lib-Q) | Class | Repeated nonce, 600-byte message | Repeated nonce, 64-byte message |
|---|---|---|---|
| `SaturninAead` (CTR-Cascade, `aead_id = 1`) | keystream | leak **592/592** bytes (100%) | 56/56 |
| `Shake256Aead` | keystream | 592/592 (100%) | 56/56 |
| `DuplexSpongeAead` (`aead_id = 2`) | duplex | **128/592** (21%; bounded by the 136-byte rate) | **56/56** — total below one rate block |
| `RomulusMAead` (SIV/MRAE, 128-bit) | SIV | 1/592 (chance level) | 0/56 |
| `SaturninSiv` (256-bit) | SIV | not in this probe; same class as Romulus-M by construction | — |

The TurboSHAKE duplex (`aead_id = 17`, `lib-q-duplex-aead::turboshake`) is documented
nonce-respecting ("a (key, nonce) pair MUST NOT be used twice") and has the same rate, so the duplex
row is the expected shape for it [I — not in the probe's registry set].

What this says about the card's alternatives:

- **"Duplex AEAD with a synthetic nonce"** means deriving the nonce from the message (a PRF over
  key, AD and plaintext). That *is* the SIV construction: two passes, deterministic output, equality
  leak. Done with K12/TurboSHAKE as the PRF and the `aead_id = 17` duplex as the cipher it is a
  Keccak-only SIV with the same security class as Kravatte-SANSE and as `SaturninSiv`. It needs the
  same review as any new mode. Its one advantage over `SaturninSiv` is staying inside the Keccak
  family the second mandatory AEAD already requires.
- **Kravatte-SANSE versus `SaturninSiv`**: equal misuse behaviour (equality leak only), both
  256-bit key and tag, both unreviewed as modes in lib-Q; SANSE is a *session* scheme (tag chains
  over the session), which none of the candidate consumers below needs; SANSE is parallel and
  roughly an order of magnitude faster in software on wide-SIMD cores (§2.3) but on 6-round
  Keccak-p; `SaturninSiv` is on SP 800-185 KMAC plus a NIST LWC round-2 cipher with a 224-bit
  designer claim. Neither is key-committing [V for `SaturninSiv`, "Not key-committing" in its
  docs; I for SANSE — no commitment claim in the 2018/1012 note's abstract].
- **Kravatte-WBC versus anything in lib-Q**: lib-Q has no wide-block or length-preserving mode at
  all. This is the only genuinely new capability Kravatte would bring. It has no consumer (§4).

## 4. Candidate consumers

Described generically here; the named survey with file and line references is on the tracking
card. Each row answers: is nonce uniqueness actually hard, would SANSE/WBC beat what is in place
or `SaturninSiv`, and by how much.

| Consumer | Today [V from the downstream specs/code] | Is nonce uniqueness hard? | SANSE / WBC better? |
|---|---|---|---|
| **Identity vault, several devices writing one encrypted log** | Each store entry: Saturnin, 16 *random* nonce bytes per entry from the OS RNG, and the spec says explicitly "never a counter: a device restored from a backup can reuse a `writer_seq`"; one-shot KEM envelopes also use a 16-byte random nonce. | **No.** 128-bit random nonces collide at ~2^64 entries per key; the designers of the vault already chose random over counter for exactly the restore case. The one real cross-device reuse hazard found in the ecosystem was a *key-schedule* defect (one message key and nonce per epoch for all senders in a group protocol), fixed structurally by per-sender chains and an interim ban on "nonce-misuse-fragile" AEADs. | An SIV mode would have contained that defect's damage to an equality leak instead of `P1 xor P2`. That is an argument for an MRAE *option in the registry* as defence in depth — which `SaturninSiv` can be once it has an `Algorithm` variant and a review — not for Kravatte. Gain from SANSE over `SaturninSiv`: none in security; speed irrelevant at entry sizes. |
| **File sync / backup with deduplication** | Content-addressed store keyed on *plaintext* chunk hashes; at-rest sealing of blobs with an existing chunked KEM envelope (random nonce, per-blob key); a one-shot backup mode and a streaming envelope (STREAM construction, counter nonces under a fresh per-stream key). | **No** for the current design — dedup happens before encryption, so encryption needs no determinism. It would become relevant only for *convergent* encryption (dedup of ciphertext across devices or tenants), which is deterministic encryption under a content-derived key. | Convergent encryption is an SIV use, and `SaturninSiv` already does it; its own docs warn that equality of plaintexts becomes public, which is the whole point of convergent dedup and must be a product decision. SANSE adds nothing but speed on bulk data; WBC adds nothing (backup blobs are not length-constrained). |
| **Key wrapping** | One-shot: a 32-byte key sealed under a KEM-derived or KDF-derived key with a fresh random 16-byte nonce, AD binding `kem_id ‖ aead_id ‖ purpose`; the key is used once. | **No.** A key used once cannot repeat a nonce. | The documented gap for key wrap in lib-Q is **key commitment**, not misuse resistance (`lib-q-aead/README.md` § Key commitment: only `SaturninQcb` applies a committing transform). SANSE is not committing either; the designers' committing designs are the 2023/1494 and 2024/1618 SHAKE modes. Deterministic wrap (SIV) would additionally give byte-equal wraps for equal keys — undesirable for a key-grant log. Gain: none. |
| **Appliance OS disk / sector encryption** | None. The state database keeps "no key material … There is therefore no at-rest cryptography in v0"; the root filesystem is dm-verity-protected and immutable; sector encryption is deferred to a storage layer not yet designed. | Not applicable yet. When it exists, sector encryption is the textbook wide-block case: fixed-size, no room for a tag or nonce, tweak = sector number. | **Yes, in principle, and only here.** A tweakable wide-block cipher (Kravatte-WBC, or double-decker over a deck function) is the right tool; the alternatives are an AES-based accordion mode (not Keccak-only) or storing a tag per sector (changes the block layout). Nothing in lib-Q covers this today. But with no consumer and no design, implementing it now would be a mode with no caller and no review budget. |

## 5. Recommendation

1. **Do not add Kravatte-SANSE.** The misuse-resistant slot is filled by `SaturninSiv`. Spend the
   review budget there: give it a `lib_q_types::Algorithm` variant and a registry row, add it to the
   crypto sign-off register with the two stated premises (KMAC256 as PRF; Saturnin-CTR as a secure
   stream cipher) as named obligations, and have the one downstream consumer pin it through the
   registry rather than the standalone type. If the GIP wire registry wants a 256-bit MRAE row next
   to the 128-bit Romulus-M1 row, this is the candidate.
2. **Do not add Kravatte-WBC now.** Open a tracked design question instead: "sector/disk
   encryption for the appliance OS — tweakable wide-block (deck-based: Kravatte-WBC /
   double-decker / Mystrium-class) versus per-sector AEAD with stored tags". Decide the primitive
   when the storage layer that needs it is designed, against the designers' *current* wide-block
   work, not against the 2017 mode.
3. **If a Keccak-only misuse-resistant AEAD is ever wanted for alignment with the TurboSHAKE
   mandatory AEAD**, prefer an SIV built from K12/TurboSHAKE (tag) and the `aead_id = 17` duplex
   (cipher) over Kravatte: it reuses 12-round primitives lib-Q already ships and already has KATs
   for, adds no new permutation variant or rolling function, and lands in the same RED review the
   duplex is already queued for. Kravatte's only advantage over that is parallel throughput, which
   none of the current consumers is bounded by.
4. **Revisit trigger.** A bulk at-rest or disk path that is Keccak-only and throughput-bound. At
   that point benchmark XKCP's Kravatte against lib-Q's AVX2 Keccak-p paths on the target
   hardware before deciding; the designers' 0.92 c/B is an AVX-512 number.

## 6. What was verified versus inferred, in one place

Verified here [V]: the absence of Kravatte/Keyak/Farfalle anywhere in this repository
(`rg -il "kravatte|farfalle|keyak"` → no files; `git log --all -S"Kravatte"` → empty); the
`SaturninSiv` construction, feature, registry status and KAT provenance; the nonce-misuse probe
output above; the XKCP rolling-function and round-count source; the keccak.team pages (kravatte,
farfalle, third_party, sw_performance, specifications), the ePrint abstract pages for 2016/1188,
2017/1026, 2018/1012, 2020/781, 2022/247, 2022/531, 2022/1711, 2023/1494, 2024/1474, 2024/1618; XKCP
headers via raw.githubusercontent.com; crates.io and PyPI metadata; the NIST 2024 accordion-mode
workshop page; the downstream specifications and source summarised in §4.

Inferred or unverified here [I]: the exact pre-tweak Kravatte 6644 parameters (PDFs returned HTTP
403 behind a bot challenge from this environment); the MB/s-to-cycles conversion for Saturnin;
absence from libraries other than crates.io/PyPI; the SANSE commitment status; the expected
misuse behaviour of the TurboSHAKE duplex (same rate and structure as the probed Keccak-f duplex,
but not in the probe).
