# lib-q-transcript

> **RED / EXPERIMENTAL — PENDING HUMAN CRYPTOGRAPHER SIGN-OFF.**
> This is a **new** foundational Fiat-Shamir layer. The duplex construction and the exact
> domain-separation label strings are **engineering drafts** that have **not** been reviewed or
> signed off by a human cryptographer. It is **not proven sound, not audited, and not
> production-ready**. Treat it as research-grade: suitable for new proof code that wants the shared
> discipline, **not** a certified Fiat-Shamir transform — without hiding residual implementation
> risk. Do not rely on it for anything load-bearing until sign-off lands.

One shared **Fiat-Shamir transcript discipline** for lib-Q zero-knowledge proofs: a single,
hash-agnostic **duplex transcript** in the CFRG sigma-protocol / Fiat-Shamir style (cf.
[`draft-irtf-cfrg-fiat-shamir`], [`draft-irtf-cfrg-sigma-protocols`], and the `spongefish`
reference implementation).

## Overview

A prover/verifier *absorbs* labelled messages into a running state and *squeezes* labelled
challenges from it, so the whole interaction is bound into every challenge. The goal is **one**
audited Fiat-Shamir layer shared by future proving code, instead of a bespoke transform per proof
system.

Two interoperable instantiations of the same `DuplexTranscript` discipline are provided:

- **`k12::K12Transcript`** (`Unit = u8`) — the **out-of-circuit** instantiation over the
  KangarooTwelve XOF ([`lib-q-k12`](../lib-q-k12)). This is the layer prover/verifier code uses to
  derive challenges on the wire.
- **`poseidon::PoseidonTranscript`** (`Unit = PoseidonField`) — the **in-circuit** instantiation
  over the Poseidon-256 sponge (`hash_suite_id = 5`, the same permutation the membership / mVE AIRs
  constrain). Field-native, so it is the value-level reference an AIR can re-derive.

## Construction (chaining-value duplex)

Both instantiations realise the duplex with the same construction. A fixed-width **chaining value**
`cv` summarises everything absorbed so far. Each operation is an injective, length-prefixed,
domain-separated hash of `(domain-tag ‖ cv ‖ label ‖ payload)`:

```text
absorb(label, msg):   cv  ← H(ABSORB  ‖ cv ‖ lp(label) ‖ lp(msg))
challenge(label, n):  out ← H(SQUEEZE ‖ cv ‖ lp(label) ‖ lp(n))[..n]
                      cv  ← H(CHAIN   ‖ cv ‖ lp(label) ‖ lp(n))   // bind the squeeze into cv
```

`lp(x)` is an injective length-prefixed encoding and `H` is the instantiation hash (the
KangarooTwelve XOF, or the truncated Poseidon-256 sponge). The Keccak/Poseidon sponges have
non-zero capacity, so the construction is not length-extendable, and the distinct domain tags
(`DOMAIN_ABSORB = 0x01`, `DOMAIN_SQUEEZE = 0x02`, `DOMAIN_CHAIN = 0x03`) keep the absorb / squeeze /
chain images disjoint.

All operations are deterministic in the absorbed sequence: a verifier that replays the same
labelled absorbs derives the same challenges as the prover. No RNG/entropy is pulled in here —
challenges are derived deterministically from the hash; randomness lives in
[`lib-q-random`](../lib-q-random).

## K12 label discipline

The K12 instantiation follows the lib-Q KangarooTwelve domain-separation discipline used by the
frozen commitments (`lib-q-mve`, membership): the protocol label is a **leading message prefix**
under an **empty** customization string (`Kt128::default()` then `update(label)`) — *not* the cSHAKE
customization argument. See the `labels` module.

## Not retrofitted into frozen wire formats

This layer is deliberately **not** retrofitted into the already-frozen `lib-q-mve` / membership
wire formats. Those predate this crate and ship their own challenger/commitment transcripts.
Adopting this layer there would change proof bytes and require a wire-version bump plus a fresh
freeze / sign-off, which is out of scope here. Use it for **new** proving code only.

## Features

The crate is `#![no_std]` (`#![forbid(unsafe_code)]`).

| Feature | Default | Effect |
|---------|:-------:|--------|
| `alloc` | via `std` | Enables the heap (`Vec`); required by both transcripts. |
| `std`   | yes | Links the standard library on std-capable targets (host, `wasm32`) so a `#[panic_handler]` is present; propagates `std` into `lib-q-k12` / `lib-q-poseidon`. Implies `alloc`. |
| `poseidon` | yes | The in-circuit `PoseidonTranscript`. Optional only to keep the K12-only dependency surface small; it does **not** require `std`. |

Default features are `std, poseidon`.

### `no_std`, `alloc`, and WASM

Both transcripts build on a bare-metal `no_std` target (e.g. `thumbv7em-none-eabi`), where the
firmware provides the panic handler:

```bash
# K12 transcript only, bare-metal no_std
cargo build -p lib-q-transcript --no-default-features --features alloc

# Both K12 and Poseidon transcripts, bare-metal no_std
cargo build -p lib-q-transcript --no-default-features --features alloc,poseidon
```

The full crate also builds for `wasm32-unknown-unknown`.

## API reference

| Item | Role |
|------|------|
| `DuplexTranscript` (trait) | Hash-agnostic duplex: `absorb(label, message)` + `challenge(label, count) -> Vec<Unit>`. |
| `K12Transcript` | Out-of-circuit instantiation (`Unit = u8`) over KangarooTwelve. |
| `PoseidonTranscript` | In-circuit instantiation (`Unit = PoseidonField`) over Poseidon-256 (feature `poseidon`). |
| `labels` (module) | The domain-separation label strings (draft, RED). |
| `DOMAIN_ABSORB` / `DOMAIN_SQUEEZE` / `DOMAIN_CHAIN` | One-byte domain-separation tags (`0x01` / `0x02` / `0x03`). |

## Testing

```bash
cargo test -p lib-q-transcript
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE-APACHE](LICENSE-APACHE) for details.

[`draft-irtf-cfrg-fiat-shamir`]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/
[`draft-irtf-cfrg-sigma-protocols`]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/
