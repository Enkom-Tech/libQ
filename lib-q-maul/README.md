# lib-q-maul

**RED — NOT FOR PRODUCTION. `publish = false`. No cryptographer has reviewed this instantiation.**
Read [`SECURITY.md`](SECURITY.md) before doing anything with this crate.

Maul, the compact lattice **double-KEM** (2K-KEM) of

> Hugo Beguinet, Céline Chevalier, Guirec Lebrun, Thomas Legavre, Thomas Ricosset, Maxime Roméas,
> Éric Sageloli. *DAKE: Bandwidth-Efficient (U)AKE from Double-KEM.* IACR ePrint **2025/1755**.
> Local copy: `reference/DAKE/DAKE Bandwidth-Efficient (U)AKE from Double-KEM.pdf`.

A double-KEM encapsulates **one** shared key under **two** public keys at once, and needs **both**
secret keys to open it. Maul gets its bandwidth saving from the shape of ML-KEM ciphertexts: they
are `(u, v)` where the vector `u` is large (1056 B at k=3) and the scalar `v` is small (192 B).
Maul factors out one shared `u` and emits two small `v`s.

## What is implemented, and where it comes from

| Component | Paper reference | Module |
|---|---|---|
| `Maul_PKE`, the `[IND-CPA, IND-CPA]` 2K2M-PKE | **Fig. 8**, §5.2 p19 | [`pke`] |
| The CK-FO transform to a `[IND-CK-CCA, IND-CCA]` 2K-KEM | **Fig. 6**, §4.2 pp16-17 | [`kem`] |
| Concrete parameters | **Table 5**, §5.3 p20 | [`params`] |
| Security estimates | **Table 6**, §5.5 p21 | [`params`] |

Nothing here is reconstructed from the abstract. Every algorithm is transcribed from the figure it
cites, and the figure is quoted verbatim in that module's documentation.

## Sizes — measured, not restated

The ciphertext size is reproduced from the parameters (`k*n*du/8 + 2*n*dv/8`) and asserted against the wire in
`kem::tests::ciphertext_length_matches_table_5`:

| Set | NIST cat. | measured ct | Table 5 ct | vs 2x ML-KEM | vs 1x ML-KEM |
|---|---|---|---|---|---|
| Maul512  | 1 |  896 |  896 | 1536 -> **-41.7%** |  768 -> **+16.7%** |
| Maul768  | 3 | 1440 | 1440 | 2176 -> **-33.8%** | 1088 -> **+32.4%** |
| Maul1024 | 5 | 1856 | 1856 | 3136 -> **-40.8%** | 1568 -> **+18.4%** |

**Both comparisons are stated on purpose.** Maul is smaller than two parallel ML-KEM ciphertexts
and *larger* than one. It is only a win where you genuinely need a key bound to two public keys —
an AKE handshake, which is what DAKE is. It is **not** a win for a transport that needs one
independent key per hop; see `SECURITY.md` "Where this does and does not fit".

The public-key size is the one number that does not reproduce Table 5, and the reason is arithmetic, not a bug:
Table 5's 826 / 1240 / 1691 are `n*k*log2(q)/8` — the information-theoretic bound with the
`A`-seed excluded — which no byte-aligned encoding can hit. This crate emits `ceil(log2 q)` bits
per coefficient plus a 32-byte seed: **864 / 1280 / 1824**.

## Post-quantum security

Basis: §5.4 core-SVP, applied to Table 6's `PrimalLWE_SigmaHints` column (the residual blocksize
*with* the Hint-MLWE hint), with the standard quantum sieve exponent `0.265*beta`.

| Set | `bikz` (hints) | quantum core-SVP | paper's own lower bound | classical core-SVP | >= 128-bit PQ? |
|---|---|---|---|---|---|
| Maul512  | 353 |  93 bits |  89 bits | 103 bits | **NO** |
| Maul768  | 589 | **156 bits** | 148 bits | 171 bits | **YES** |
| Maul1024 | 811 | 214 bits | 204 bits | 236 bits | **YES** |

**Use `MAUL768` or `MAUL1024`.** `MAUL512` is NIST category 1 in the paper's framing but does not
clear a literal 128-bit quantum figure — the same property ML-KEM-512 has (~107 bits). This is
enforced, not merely documented: [`ParamSet::meets_128_bit_quantum_core_svp`] returns `false` for
it, and `tests/pq_parameters.rs` asserts the whole table.

## Both legs contribute secrecy

libQ previously shipped and then **withdrew** a double-KEM (`lib-q-double-kem`) whose second leg
contributed nothing: its `ss_b` was recomputable from transmitted bytes plus the *public* `ek_b`.
`tests/both_legs_contribute.rs` is the standing proof that this one is different. It runs a
full attacker who holds `sk_L`, both public keys and every transmitted byte, and requires that
every derivation available to it — including the exact broken derivation of the old crate — fails
to produce the shared secret; and it includes a deliberately-broken control construction against
which that same attack **succeeds**, so the test is known able to catch the defect.

## Example

```rust
use lib_q_maul::{MAUL768, PublicParams, keygen_left, keygen_right,
                 encapsulate_with_messages, decapsulate};

let pp = PublicParams::standard(&MAUL768);
let fo_l = vec![0x11u8; MAUL768.nu_bytes()];
let fo_r = vec![0x22u8; MAUL768.nu_bytes()];
let (pk_l, sk_l) = keygen_left(&pp, &[1u8; 32], &fo_l);
let (pk_r, sk_r) = keygen_right(&pp, &[2u8; 32], &fo_r);

let (ct, ss) = encapsulate_with_messages(&pp, &pk_l, &pk_r, &[0x5a; 32], &[0xa5; 32]);
assert_eq!(ct.as_bytes().len(), 1440);

// BOTH secret keys are required.
let got = decapsulate(&pp, &pk_l, &pk_r, &sk_l, &sk_r, &ct).unwrap();
assert_eq!(got, ss);
```

Production callers use [`encapsulate`] (draws both messages from a CSPRNG);
[`encapsulate_with_messages`] is the derandomised entry point used by the KATs and the evidence
tests.

## Performance

The ring arithmetic is **schoolbook**, not NTT: ~15 polynomial products per encapsulation at
`k = 3`. Every Table 5 modulus is NTT-friendly and an NTT would be roughly two orders of magnitude
faster. That is deliberate — this crate is unreviewed, and the arithmetic is written to be
obviously correct and obviously branch-free rather than fast. Optimise it after sign-off, not
before.
