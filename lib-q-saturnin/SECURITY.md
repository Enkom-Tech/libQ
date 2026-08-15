# Security

## Constant-time requirements

Full AEAD (`aead.rs`) tag verification uses constant-time comparison (`lib_q_core::Utils::constant_time_compare`). No secret-dependent branches or short-circuit comparisons on tags or keys in that path. The `constant_time` test binary exercises tag accept/reject behavior for full AEAD and Short. **Layer B:** use `lib_q_core::AeadDecryptSemantic::decrypt_semantic` on `SaturninAead` (or `SaturninShortAead` when the `aead-short` feature is enabled) for a semantic outcome without plaintext on authentication failure; `lib_q_core::Aead::decrypt` remains the default `Result` mapping. See workspace ADR `docs/adr/003-aead-decrypt-layers.md`.

### Saturnin-Short (spec Section 2.3)

Short mode is a single 32-byte block: there is no separate authentication tag. Validity is established by constant-time nonce binding and padding validation over the decrypted block, then fixed-layout assembly of a candidate plaintext buffer. The public decrypt API maps that result to `Ok` or `Err(VerificationFailed)` only after the symmetric inverse and parsing work complete—the same structural pattern as full Saturnin AEAD (full symmetric decrypt work before returning plaintext versus authentication failure at the API boundary). `AeadDecryptSemantic::decrypt_semantic` is implemented for Short as well. Remote timing analyses should assume verification can influence control flow at that API boundary; callers with stricter separation requirements must mediate timing above this layer.

### Saturnin-CTR-Cascade (`SaturninAead`, the default) — open obligation Q-2

**This is the mode with the widest blast radius on this page, and until 2026-08-15 this file did
not mention it.** Everything below about QCB concerns opt-in types; `SaturninAead` is the frozen
wire every consumer of this crate decrypts through.

Nothing here says the mode is broken. It says the published *argument* for one of its advertised
properties has a hole. The Saturnin LWC spec §4.3 claims IND-qCCA security for the CTR-Cascade
AEAD and argues it at §4.3.1 via Soukharev–Jao–Seshadri \[SJS16\]: that IND-qCPA encryption
composed with a quantum-secure MAC yields IND-qCCA. IACR ePrint 2025/387 (Lang, Leuther, Lucks)
disproves exactly that implication. That preprint has since **cleared peer review** — it appears as
\[LLL26\] "Generic composition: from classical to quantum security", *Post-Quantum Cryptography*,
LNCS 16491, pp. 37–70, Springer 2026, doi `10.1007/978-3-032-22695-2_2` (observed in the
bibliography of Fischlin–Schmalz, ToSC 2026(2) p.20) — so Q-2's premise is **firmer** than when the
obligation was opened, not weaker.

The repair looks available but is unratified: 2025/387's own Theorem 3 (carried to EtM by Theorem 4
and Corollary 1) gives IND-qCCA when the MAC is a **qPRF**, strictly stronger than the hypothesis
shown insufficient, and the Saturnin spec argues the qPRF property separately at §4.3.3. **Whether
§4.3.3 discharges 2025/387's hypothesis is the open question, and nobody has ratified it.**

Two scope notes a reader should not over-read. First, Fischlin–Schmalz diagnose GCM's quantum
failure as coming from a universal-hash-with-pseudorandom-masking MAC ("it is exactly this MAC
property which renders GCM insecure in the quantum setting", ToSC 2026(2) p.3), and CTR-Cascade's
MAC has no such structure — its running tag is the block-cipher *key* and the data block its input
(`src/aead.rs`), with no polynomial evaluation. That is **our** reading of **our** code, not their
claim, and the same paper lists CBC and PMAC among the period-finding casualties, neither of which
is universal-hash-based. "The GCM cause does not apply" is therefore not "no Q2 attack applies".
Second, Q-2 concerns nonce-respecting adversaries with classical nonces; the designers already
disclaim nonce-misuse and nonce-superposition security (spec §4.3), and so does this crate.

Classical AE security is unaffected either way. Full statement and the proposed citation chain:
`src/aead.rs` ("Open obligation Q-2") and `src/aead_ctx.rs`. Repo-wide gate: `docs/crypto-signoff-register.md`
Gate E. `scripts/ci-guard-standards-claims.sh` fails CI if `IND-qCCA` appears anywhere outside this
crate, so the claim cannot leak away from this caveat.

### Saturnin-QCB (`qcb` feature)

Saturnin-QCB (`qcb.rs`) is the one-pass AEAD from "An Update on Saturnin", built on the Saturnin
tweakable block cipher `SaturninTbc` (`tbc.rs`): `TBC_d(K,T)(M) = Saturnin16^d_{K⊕T}(M)`. Tag
verification uses the constant-time `lib_q_core::Utils::constant_time_compare`, and the full
ciphertext body is decrypted before the authentication outcome is mapped to `Ok` vs
`Err(VerificationFailed)` (Layer A) / `AuthenticationFailed` (Layer B), matching the contract of
the other Saturnin AEAD paths.

**Security model — ideal cipher, classical tweaks. Not standard model.** Every published security
result for this construction is an ideal-cipher-model result. The Saturnin designers' own update
note, Section 5: "*In the ideal-cipher model*, we can prove the indistinguishability and
unforgeability of QCB under quantum chosen-plaintext attacks as defined in the specification of
Saturnin. The proof assumes that nonces are not controlled by the adversary and not reused." The
QCB paper, Section 6.3: "the first statement holds in the standard model, the second in the ideal
cipher model" — the *second* is the one that covers a block-cipher instantiation such as this one
(Proposition 1, and Corollary 2 / Theorem 5's second statement built on it). QCB's standard-model
statements are about an *abstract* TBC assumed (S)TPRP-secure and do not reach `E(K ⊕ T, ·)`.
Mennink (*Insuperability of the Standard Versus Ideal Model Gap for Tweakable Blockcipher
Security*, CRYPTO 2017; IACR ePrint 2017/474, Theorem 4 / Corollary 1) gives a heuristic
impossibility — under his Assumption 1 — for *optimal* standard-model security of tweak-rekeyable
TBCs of exactly this shape; quote his scope with it ("the result does not imply that the generic
standard-to-ideal reduction is unavoidable, nor that optimal security cannot be achieved"). Never
write "QCB is proven secure" without naming the model.

**Where the quantum claim stops.** The proof lets the adversary put the *message* in
superposition; it fixes a set of *classical, pre-declared* tweaks (QCB §4.1). Superposition
*tweak* queries are a polynomial-time total break, because the tweak is the key offset: Simon's
algorithm recovers `K` in `O(256)` queries (Rötteler–Steinwandt, IACR ePrint 2013/378 — cited for
exactly this purpose by the QCB paper §4.2 and by the Saturnin update note, footnote 1). The
Saturnin claim box concedes the same for the bare cipher: "Saturnin does not provide security
against related-key superposition attacks (as is the case of all known block ciphers)." Generic to
all block ciphers; still the boundary of what this crate may claim. Note also that the tag this
mode actually transmits is the CTX tag `T'`, not Algorithm 1's `T`, and whether CTX preserves any
of QCB's Q2 properties is open obligation **Q-1** — widened, not closed, by the 2026-08-07
source review (`src/commit.rs`).

**The CTX AE-preservation result is single-user and single-verification-query (obligation L-1).**
Even classically, Chan–Rogaway's Theorem 3 — the theorem that says CTX does not *break* the base
scheme's AE security — is proved in a restricted setting. Bellare–Hoang, IACR ePrint 2024/875
p.12: "Chan and Rogaway [16] only consider a restricted setting where the adversary attacks just a
single user, and it can only make a single verification query. Translating this result to the
general setting via a hybrid argument will lead to a very poor bound." Both `SaturninQcb` and
`SaturninAeadCtx` inherit Theorem 3, so both inherit this. Any multi-user or multi-verification
deployment claim for either type rests on a hybrid argument nobody here has performed. This is
orthogonal to the committing bound (Theorem 2 has no oracles) and to Q-1 (query counts, not oracle
model). Full statement: `src/commit.rs`.

**The related-key assumption is the thin one.** QCB §5: "This construction motivates further
inquiry of related-key attacks, as it needs Saturnin16 to be related-key secure." The designers'
own *A note on related-key attacks on Saturnin* (Note-RK-1) reaches **10 of 16 super-rounds**
classically at `2^236` time; Bao et al. (IACR ePrint 2021/703 §5.3) reach the same 10-super-round
boundary with a quantum multi-collision distinguisher. No claim is violated (`2^236 > 2^224`), but
the related-key margin behind QCB is **6 super-rounds of 16** (10 attacked). The Saturnin-Hash
literature that the CTX tag rests on counts in the same units, and the margin there is larger
*in-model* — the best in-model **classical collision** attack is 6 of 16 super-rounds, leaving 10 at
that goal — but not by as much as it first appears. Two qualifiers are load-bearing and were both
missing here until 2026-08-15. First, "classical collision" is not "attack": the best in-model
*quantum* collision reaches **7 of 16** at `2^113.5` (2021/1119 Table 1, under Hash/Collision), and
there is an in-model *classical preimage* at 7 of 16 at `2^232` ([17] in the same table). So the
deepest in-model result of any kind is 7 of 16 and **the in-model margin is 9, not 10**; an
unqualified "6 of 16 is the best in-model attack" is false. Second, free-start **quantum** collision attacks on
the Saturnin-Hash compression function reach 10 of 16 super-rounds at `2^127.2` (Dong, Guo, Li and
Pham, IACR ePrint 2022/731 §5.2) — the best *classical* free-start is 6 of 16 at `2^80` — and they
are only out of scope because MMO fixes `IV = 0`. An earlier revision of this file compared "10/16" against
"6-of-32-rounds"; that mixed units and understated the hash-side cryptanalysis by a factor of two
in depth. Round-count table and sources: `src/commit.rs`, obligation H-1. The designers also scope their related-key
claim to "a small number of keys" with "[BK03]"-conforming deriving functions, while this mode's
95-bit index admits up to `2^95` related keys under `Φ_⊕`. That gap is a new open cryptographer
question, **RK-1**, tracked with the obligations in `src/commit.rs`.

**Mode definition.** The update note describes only the TBC and the encryption path (its Figure 1
is captioned "Saturnin-QCB, *encryption*" and shows neither the tag nor the associated data). The
complete mode is **Algorithm 1** of the QCB paper (Bhaumik, Bonnetain, Chailloux, Leurent,
Naya-Plasencia, Schrottenloher and Seurin, *QCB: Efficient Quantum-secure Authenticated
Encryption*, ASIACRYPT 2021; full version IACR ePrint 2020/1304), whose *Instantiation with
Saturnin* paragraph fixes the five domain separators used here: **9** full message block, **10**
final padded message block, **11** full associated-data block, **12** final padded
associated-data block, **13** tag/checksum. `tests/qcb_spec.rs` checks `SaturninQcb::encrypt`
against an independent transcription of Algorithm 1 over a 63-case length sweep.

Every tweak carries the nonce, associated data included. The paper requires this explicitly
(Section 5, *Avoiding Quantum Attacks*: "It is important to include the IV in the tweak when
processing the AD. Otherwise, there is a quantum forgery attack based on Deutsch's algorithm.").
Releases up to and including 0.0.8 zeroed the nonce in the AD tweak, which additionally allowed a
purely classical cross-nonce associated-data-relabelling forgery under nonce reuse; both are
closed, and the change is a **wire break** — no 0.0.8 QCB ciphertext decrypts under the current
code.

**Interpretation caveat — the tweak's byte 16 is a reading, not a confirmed fact.** **No official
QCB known-answer test vectors exist** (the round-2 NIST-LWC package ships ctr-cascade, short and
hash, and no QCB). The paper says only that "the IV and the block number are simply concatenated"
into the 256-bit tweak, and Algorithm 1 line 1 says only "Pad the initialization vector if
necessary" — no padding direction, no field widths, no endianness stated anywhere in the document.

This module builds `N ‖ 0x80 ‖ 0·7 ‖ block_index_be`, i.e. **byte 16 = `0x80`** — the `10*` pad bit
closing a 161-bit IV field, leaving a 95-bit index. **Until 2026-08-06 it built `0x00`** (a 160-bit
zero-padded IV field, 96-bit index); the change was made because `0x80` is the better-supported
reading and because the Saturnin hardware was at trace design, where the switch costs nothing today
and becomes impossible once silicon exists. The Saturnin submission states `10*` as the general rule
for padding any sub-256-bit value into a 256-bit block, covering "our proposed modes", and works
this exact shape byte by byte: a 128-bit nonce gives "the 16 bytes of the nonce, followed by a byte
of value `0x80` … followed by one byte of value `0x01`".

An earlier version of this note said the paper's limits "are simultaneously tight only under a
160/96 split". **That was backwards** — a 96-bit index field addresses 2^96, leaving the stated 2^95
bound slack by a factor of two. Both numbers are exactly tight under 161/95. The paper's own
TRAX-QCB accounting ("3 bits … for domain separation, 80 bits of IV and 45 bits of block numbering
… at most 2^45 − 1 blocks") shows fields summing exactly to the tweak width; here 160 + 95 = 255
leaves one bit unaccounted for, and the `10*` pad bit is exactly it.

**The designers have not confirmed this** (card `t_7123c738`); one sentence or one KAT from them
could still overturn it. Byte compatibility with a paper-conformant Saturnin-QCB is in any case
unreachable, because this mode emits the CTX tag `T'` rather than Algorithm 1's `T`. There is no
security consequence either way: byte 16 is a constant under both readings and the tweak is XORed
into the key, so they differ by a fixed key offset — a bijection on the related-key family.
Ciphertexts produced before the change do not decrypt under it; nothing had produced any. Decision
and full evidence: card `t_5d1460b7`.
Decision: card `t_5d1460b7`. Question to the designers: card `t_7123c738`. If/when they publish
QCB KATs, pin them and reconcile before treating this mode as a standard.

## Fault injection

**This crate implements no fault countermeasure of any kind, and two published attacks recover
Saturnin's full 256-bit key under fault injection.** Both are ciphertext-only. Neither is a break of
the cipher as software: both require an attacker who can physically induce faults in the device
performing the encryption. If your threat model excludes that — a server, a phone app, anything the
attacker cannot hold — neither result applies to you. If it includes it, this section is the whole
of what is known, and the answer today is that nothing here defends against it.

Recorded 2026-08-15, when both papers were read. Until then `docs/HARDWARE.md` asserted that no
fault work existed for Saturnin at all, which was false.

| Target | Attack | Faults | Model | Source |
|---|---|---|---|---|
| Saturnin block cipher | SDFA (statistical *differential* fault analysis) | 656 | random faults at the fourth-to-last single round, ciphertext-only, ≥99% reliability | Li, Liu, Gu, Gao, Sun, IEEE TIFS **18** (2023) 1487–1496, doi `10.1109/TIFS.2023.3244083` |
| **Saturnin-Short** (`aead-short`) | SIFA (statistical *ineffective* fault analysis) | 1 097 | random single-byte, ciphertext-only, ≥99% success | Li, Liu, Gu, Sun, Gao, Qin, *Journal on Communications* **44**(4) (2023) 167–175, doi `10.11959/j.issn.1000-436x.2023084` |

Both quote full 256-bit key recovery. Verbatim from the TIFS abstract (p.1487): "it recovered the
256-bit secret key using 656 faults in the fourth-to-last round of Saturnin". Verbatim from the
Journal on Communications abstract (p.167): "最少仅需 1 097 个无效故障并以不低于 99% 的成功率恢复
Saturnin-Short 算法的 256 bit 原始密钥 … 因此，Saturnin-Short 算法不能抵抗统计无效故障分析的攻击"
("as few as 1 097 ineffective faults recover Saturnin-Short's 256-bit original key with no less than
99% success … therefore Saturnin-Short cannot resist statistical ineffective fault analysis").

**Four caveats, all of which narrow the results, none of which dismisses them.**

1. **Both are software simulations on a laptop CPU**, not hardware experiments. Neither paper
   analyses the trigger precision a real attacker needs to hit one round boundary, and the SIFA
   paper additionally needs the attacker to observe the mode's own reject verdict.
2. **Both model a cipher with half the S-box layers this crate implements.** The TIFS paper's
   Algorithm 1 (p.1489) applies `SL` **once** per iteration of `r = 1..R` super-rounds; the Journal
   on Communications paper's Algorithm 2 (p.170) does the same. Specification-correct Saturnin
   applies two, and `src/core.rs`'s `apply_round` calls `apply_sbox` twice. This is the design
   report's own pseudocode typo, documented by Hou, Cui and Zhang (*The Computer Journal* 66(2),
   p.479 fn.1: "Its pseudocode only contains one S-layer per super-round, but the code contains
   two"). Neither paper states whether its C++ implementation followed its pseudocode or the
   reference code. **Quote 656 and 1 097 as the best published figures; do not report them as
   measured against a specification-correct implementation.**
3. **Round indices are in mixed units and must not be over-translated.** The TIFS paper gives the
   fault position as "the (2R−3)-th single round with R ∈ [10, 31]" (p.1491) — i.e. protection
   would have to cover the last four *single* rounds, not the last one or two. The SIFA paper's
   position is one super-round from the end. In their cipher one super-round remaining means one
   S-box layer remaining; in ours it means two.
4. **Neither paper proposes a countermeasure.** TIFS p.1494 offers only "it is more challenging to
   take counter measurements against fault analysis for the deeper round of fault injections"; the
   SIFA paper recommends "necessary effective measures" and names none. A fault-resistance position
   for silicon must therefore come from elsewhere — and SIFA is the harder half, because the
   obvious first move, detection or redundancy, is precisely the class SIFA is defined to defeat.

**Reachability.** `aead-short` is **not** a default feature (`default = ["std", "aead",
"block-cipher", "hash", "stream", "alloc"]`), so the SIFA result reaches only callers who opt in.
The SDFA result is against the bare block cipher and therefore underlies every mode here.

**Do not mistake the workspace's flags for a control.** `lib-q-aead` and `lib-q-hpke` expose a
`fault_injection_protection` boolean. It is advisory: callers set it and read it back, and no call
site anywhere in the workspace consumes it. It enables no redundancy, recomputation, detection or
infective countermeasure. Both modules said otherwise until 2026-08-15.

Hardware consequences, including what a protected datapath would have to cover, are in
`docs/HARDWARE.md` §8.6.

## KAT validation

Implementation is validated against the reference KAT vectors (AEAD, hash, block cipher) in `tests/kat_tests.rs`. KATs are the authoritative correctness check.

Saturnin-QCB has no published designer KATs (see above); it is instead pinned to **derived
self-consistency vectors** (`qcb::tests::pinned_kat_vectors`) plus round-trip, tamper-detection,
nonce/AD-binding, and block-independence (parallelism) tests. These lock byte-level behavior so
the construction cannot drift silently, but they do **not** establish agreement with an external
reference.

## Implementation notes

The reference, KAT-validated code path is the scalar implementation (`core`, `bs32_core`).

The SIMD features (`simd`, `simd-avx2`, `simd-neon`) provide optimized paths with runtime capability detection. These optimized paths are required to remain output-equivalent to the scalar reference path and are treated as separate review scope.

## SIMD security review checklist

Before accepting SIMD changes as production-ready:

1. Run all KAT tests on scalar and SIMD feature sets and verify byte-for-byte parity.
2. Run equivalence tests (`simd_equivalence`) across randomized vectors and edge-length inputs.
3. Confirm no secret-dependent branches are introduced in S-box/MDS/round logic.
4. Confirm no secret-dependent memory access patterns are introduced (table lookups indexed by secret data are forbidden in SIMD code paths).
5. Review each `unsafe` block in SIMD modules for documented invariants (feature gating, pointer validity, load/store bounds).
6. Re-run constant-time tests for AEAD tag verification and any modified comparison code.

## Constant-time observations for current SIMD path

- SIMD kernels are implemented with fixed-latency bitwise/arithmetic and lane-shift operations.
- Runtime dispatch branches only on CPU capabilities, not on key/plaintext/ciphertext content.
- AEAD tag verification remains in `lib_q_core::Utils::constant_time_compare`.

## No formal audit

This implementation has not undergone a formal third-party security audit. Use in production should consider your threat model (e.g. exposure to timing or other side-channel adversaries) and applicable certification or compliance requirements.

## Vulnerability reporting

Report vulnerabilities per the main [lib-Q SECURITY](../SECURITY.md) or the project contact.
