# Perf handoff — ML-KEM NTT is the bottleneck (~6× slower than reference)

> ## ⚠️ CORRECTION (2026-06-20, perf follow-up) — the headline below is a MEASUREMENT ARTIFACT.
>
> The "309/445/610 µs … ~6–15× slower than RustCrypto" numbers were measured with the **`hardened`
> feature silently unified ON**. `cargo test`/`cargo bench -p lib-q-ml-kem` builds the dev-dependency
> `lib-q-sca-test`, which depends on `lib-q-ml-kem` with `features = ["std","hardened","random"]`
> (see `lib-q-sca-test/Cargo.toml:26`). Cargo feature unification then turns `hardened` ON for the
> whole package build — so the bench measured the **hardened NTT** (per-layer Fisher-Yates RNG shuffle
> + multiplicative blinding, slow *by design* for side-channel resistance), not the default scalar NTT.
>
> **Real default (non-hardened) ML-KEM-768 on this machine: keygen 67 µs / encaps 59 µs / decaps 70 µs**
> — competitive with RustCrypto's 30–50 µs, NOT 6× off. With `hardened` unified on you reproduce
> 342/469/617 µs ≈ the "baseline" below. The default NTT is ~1.8 µs/transform and a *small* slice of
> the total; a Montgomery rewrite buys ~14% on the NTT (~2–4% end-to-end), not 6×.
>
> A clean Montgomery + lazy-reduction NTT/INTT *was* implemented for the default path (ACVP-validated,
> byte-identical) — see `algebra.rs` `fqmul`/`ZETA_MONT`/`montgomery_reduce`. It is a modest real win,
> kept for that reason, but it is NOT the 6× this doc predicted.
>
> **Two takeaways:** (1) the "same root cause as the ML-DSA-vs-`fips204` 7× gap" is almost certainly
> the SAME artifact — `lib-q-sca-test` also pulls `lib-q-ml-dsa` with `hardened`
> (`lib-q-sca-test/Cargo.toml:27`). Re-measure ml-dsa with `hardened` provably OFF before chasing it.
> (2) The default non-hardened NTT/ACVP path is **under-tested in CI** because of this same unification
> — `cargo test -p lib-q-ml-kem` exercises the hardened path. Worth a dedicated `--no-default-features`
> ACVP job. The original (still-useful) analysis follows; read it through this correction.

**From:** libQ-side perf pass, 2026-06-20. **To:** whoever owns lib-q performance.
**Status:** localized + diagnosed, NOT fixed. Safe micro-opts already falsified (see below) — do **not** redo them.

## Headline

`lib-q-ml-kem` is fully scalar and ~12–15× slower than same-lineage RustCrypto `ml-kem`
(ML-KEM-768 measured here: keygen 309µs / encaps 445µs / decaps 610µs; RustCrypto pure-Rust ≈30–50µs).
**The cost is the NTT/INTT transforms, not Keccak, sampling, or matmul.**

## Where it is (sub-op micro-bench, ML-KEM-768)

| sub-op                         | cost     |
|--------------------------------|----------|
| matrix_gen (3×3 sampler+SHAKE) | 19.8 µs  |
| vector_gen                     | 7 µs     |
| matmul (Â·v̂)                   | 3.8 µs   |
| **intt (×3)**                  | **84 µs**|
| **ntt (×3)**                   | **82 µs**|

→ **~27 µs per single 256-pt NTT vs ~3–5 µs for RustCrypto's (≈6×).** Each keygen/encaps/decaps
runs 6–15 NTTs, so transforms dominate. Keccak is only ~20–30 µs of the ~600 µs — the Keccak×4 /
parallel-SHAKE work in flight (lib-q-keccak/lib-q-sha3) is worth doing but will **not** touch this.

## What it is NOT (already ruled out — don't repeat)

- **Not codegen/inlining:** fat-LTO + 1 codegen-unit made no change (81 vs 84 µs). Field ops already inline.
- **Not AVX2-absence as first move:** `target-cpu=native` is a no-op here (647 vs 610 µs); the scalar
  loop can't auto-vectorize. Default NTT path is the plain Kyber NTT (`algebra.rs:~448-460`); the
  shuffled/RNG NTT is `#[cfg(feature="hardened")]`, off by default.
- **Not branchy `small_reduce`:** branchless conditional-subtract gave no win — LLVM already `cmov`s it.
- **Not `hybrid_array` bounds checks:** `split_at_mut` + zipped-iterator butterflies (safe, no `unsafe`)
  gave no win.

Both micro-opts above kept the 26 KATs green but moved nothing → the ~6× is **arithmetic
dependency-chain latency**: butterflies serialize on Barrett's 64-bit multiply (~5 cyc/op) instead of
pipelining.

## The actual fix

**Rewrite NTT/INTT to Montgomery + lazy reduction** (RustCrypto-style): keep coefficients in Montgomery
form across layers, defer reductions, only normalize at `base_case_multiply` / final scaling. This
shortens the per-butterfly dependency chain and lets layers pipeline. Benefits **all** platforms
(it's the portable path) and is the same root cause as the ML-DSA-vs-`fips204` 7× gap — likely one
NTT-quality fix lifts both.

### Correctness landmines (this is why I didn't rush it)

- Interacts with the **twiddle tables**, `base_case_multiply`'s **GAMMA** factors, and the final
  **n⁻¹ = 3303** scaling. Montgomery form changes the constants — recompute them, don't just wrap ops.
- **The 26 unit KATs are not sufficient.** A Montgomery rewrite can pass them yet break interop. Gate
  the change on the **full ACVP KAT suite** before landing.
- **Bench on a quiet host.** This machine swings the NTT bench 82–105 µs run-to-run — too noisy to
  confirm a win below ~20%. Use a pinned/quiesced box.

---

# Second, unrelated finding: per-packet AEAD key/nonce alloc (lib-q-core + AEAD engines) — ✅ DONE

**Resolved 2026-06-20** (don't redo). Implemented as inherent slice methods on the engines rather
than a `lib-q-core` trait change — smaller blast radius, fully backward-compatible, no wire/KAT change:

- `lib-q-saturnin` `SaturninAead`: added `encrypt_bytes`/`decrypt_bytes(&self, key: &[u8], nonce: &[u8], …)`;
  `decrypt_core` now takes slices; `Aead::{encrypt,decrypt}` + `decrypt_semantic` forward via `as_bytes()`.
- `lib-q-romulus` `RomulusMAead`: same `encrypt_bytes`/`decrypt_bytes` pair; trait methods forward.
- `libq-crypto` `SaturninEngine`/`RomulusM1Engine` now call the slice methods → the two per-packet
  `to_vec()`s (and the redundant key-material copy) are gone on every record seal AND open.

Scope note: only Saturnin (production default) and Romulus actually wrapped; DuplexSponge/AEGIS/AES-GCM
already took `&[u8]`. Tests green: lib-q-saturnin (AEAD KAT + round-trip), lib-q-romulus (24),
libq-crypto (125 lib, incl. `saturnin_/romulus_round_trip_via_record_api`), libq-session/libq-packet.
A `lib-q-core` `Aead` trait borrowing method is still a reasonable future cleanup for *all* impls, but
isn't needed for the libQ hot path.

> **✅ COMMIT STATUS (libQ-PERF agent, 2026-06-20) — libQ side is committed + pushed.** The
> `lib-q-saturnin` + `lib-q-romulus` `encrypt_bytes`/`decrypt_bytes` changes landed as their own commit
> **`ae6ebeb`** ("feat(romulus,saturnin): allocation-free encrypt_bytes/decrypt_bytes APIs") and are on
> `origin/main` (tip `eef5f7b`), fmt/clippy/audit-clean. **So: do NOT re-commit the libQ files** — they
> are no longer in the working tree. Answer to the open question: the libQ and libQ halves are already
> split — `ae6ebeb` is the libQ commit; the **`libq-crypto`** edits (the `SaturninEngine`/`RomulusM1Engine`
> call-site switch to the slice methods) are in the libQ repo and remain **yours to commit** there. The
> trait-promotion cleanup below is now a refactor on *committed* code, not on uncommitted working-tree
> changes.

### ➡️ Remaining cleanup — HANDED TO THE libQ-PERF AGENT (2026-06-20)

The libQ hot path is fully covered by the two engines above; this last item is **libQ-internal polish,
not on any libQ critical path** — handed over so it lives with the trait owner, not libQ:

1. **Lift the borrowing entry point into the `lib-q-core` `Aead` trait itself.** Right now
   `encrypt_bytes`/`decrypt_bytes(&self, key: &[u8], nonce: &[u8], …)` exist only as *inherent* methods
   on `SaturninAead` and `RomulusMAead`. Promote them to default trait methods on `Aead` (the existing
   `encrypt`/`decrypt` become thin forwarders that call them via `as_bytes()`), so **every** impl —
   DuplexSponge, AEGIS-256, AES-256-GCM — exposes the alloc-free path uniformly without each one
   re-implementing it. DuplexSponge/AEGIS/AES-GCM already operate on `&[u8]` internally, so for them
   it's a pure signature lift with no body change.
2. **Then collapse the two inherent methods** on Saturnin/Romulus into the trait default (or keep them
   as inherent shadows for ergonomics — caller-visible behavior is identical either way).
3. **No new vectors needed** — this is a signature/forwarding refactor; the existing AEAD KATs + the
   libq-crypto `*_round_trip_via_record_api` tests already pin byte-for-byte behavior. Just keep them green.

Reason it's a *cleanup* and not a fix: the only two AEADs libQ actually wraps per-packet (Saturnin
default, Romulus interop) are already alloc-free. Promoting to the trait removes the asymmetry and
prevents a future AEAD from silently regressing back to wrapper-allocs, but buys no measurable libQ win
today. Low risk, no wire/KAT change.

Original write-up retained below for context.

---

Separate, much simpler win — surfaced while auditing the libQ data-plane seal/open hot path.

**`lib-q-core`'s `Aead` trait takes `&AeadKey` / `&Nonce` (`traits.rs:249,268`), both `Vec<u8>`-backed
under `alloc`.** So every record seal *and* open on the libQ side does two throwaway heap allocations
just to wrap fixed-size arrays into those structs — e.g. `libq-crypto`'s `SaturninEngine::encrypt`:

```rust
let key   = AeadKey { data: key32.to_vec() };   // 32-byte alloc, every packet
let nonce = Nonce   { data: nonce16.to_vec() };  // 16-byte alloc, every packet
aead.encrypt(&key, &nonce, plaintext, Some(ad))  // + the returned ct Vec
```

At the 1M pkt/s SLO that's ~2M throwaway small allocs/s on the data plane, for both seal and open,
across **every** AEAD (Saturnin/Romulus/AEGIS/duplex/AES-GCM) — they all wrap the same way.

**Fix (libQ-side, low risk):** give the `Aead` trait borrowing entry points that take `key: &[u8]` /
`nonce: &[u8]` directly (or `&[u8; N]`), so callers pass the array without heap-wrapping. Keep the
`AeadKey`/`Nonce` API as a thin forwarding layer for back-compat. This removes 2 allocs/packet from
**every** AEAD at once with no wire/KAT change — purely an internal API ergonomics fix.

libQ can't fix this from its side without either this trait change or threading cached `AeadKey`
structs through the deliberately-stateless `record_aead_encrypt/decrypt` free functions (and the
nonce must still be fresh per counter, so caching only saves one of the two). Hence: libQ.

libQ-proper data-plane shape is otherwise already optimal — the sender datagram builder pre-sizes the
whole buffer (`Vec::with_capacity`) and appends the sealed record in place with no intermediate
record buffer; the relay forward path was reduced to a single alloc this same pass (libQ `master`
8d9441c). The remaining per-packet costs are all in libQ: the NTT compute above and this wrapper alloc.

---

## Reproducing the sub-op numbers

The micro-bench scaffolding was reverted (kept libQ clean). To re-add: a `bench-internals` feature
that does `#[cfg(feature="bench-internals")] #[allow(missing_docs)] pub mod algebra;` in `lib.rs`,
plus a `benches/mlkem_subops.rs` Criterion bench calling matrix_gen/vector_gen/matmul/ntt/intt
directly. `B32` is behind the `deterministic` feature — build seeds with `Array::from_fn` instead.
