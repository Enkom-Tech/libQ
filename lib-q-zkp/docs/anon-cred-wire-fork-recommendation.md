# Anon-cred wire: the three-way fork, measured — and the recommendation

Board card `ENK-266`. This is the third acceptance item of that card ("an explicit comparison
against the FRI number and against `t_0aa1a2c8`'s, with a recommendation"), written down here so a
reviewer can check the reasoning rather than take it from a card comment thread. Items 1 and 2 of
that card — expressing **our** relation and deriving **our** size — are **not** done; §5 says
exactly what is left and why the recommendation does not wait on them.

Nothing here is a security claim. Every construction named is RED until a cryptographer reviews it.

## 1. The numbers

All three measured, none estimated.

| Candidate | Presentation size | Revocation / membership | Host |
|---|---:|---|---|
| **FRI/STARK (Arm B)** — shipped, merged, ours | 947 600 – 1 211 498 B | included in that figure | any |
| **LNP22/ABDLOP** (LaZer `python/anon_cred`) | **29 093 B** | not included — see §3 | Zen 3, AVX2 |
| **LaBRADOR** membership argument (`t_0aa1a2c8`) | — | **~7.56 KB** for a height-64 Merkle path (16 simultaneous paths: 10.00 KB) | Intel SDE (AVX-512 emulation) |

Provenance:
- FRI: `cargo test -p lib-q-zkp --release --lib stark_baby_bear::tests::measure_arm_b -- --ignored
  --nocapture`, matching `membership-arm-b-measurement.md`.
- LNP22: `python3 anon_cred.py` in `lazer/python/anon_cred` on a Ryzen 9 5900X. Issue 0.105 s, show
  0.202 s, all steps verified OK. The credential is 8 message polynomials.
- LaBRADOR: measured under Intel SDE on `t_0aa1a2c8`, the AVX-512 emulation route.

**Do not add 29.1 KB and 7.56 KB.** They are different proof systems in the same family, measured on
different statements. The defensible statement is **"tens of KB versus ~1 MB"** — roughly two orders
of magnitude — not "36.7 KB".

## 2. Two corrections that this comparison rests on

Both were mistakes made while working these cards, and the conclusion changes if either is
forgotten.

1. **"The lattice direction needs AVX-512" is false for this branch.** LaZer has two backends.
   ABDLOP + LNP22 (`src/abdlop.c`, `src/lnp.c`) contain no AVX-512 at all and run on ordinary AVX2
   hardware; only the LaBRADOR submodule is AVX-512-only. The 29.1 KB figure was produced on a Zen 3
   host with no emulation. The earlier claim that AVX-512 gated the whole lattice direction was an
   over-generalisation from `t_0aa1a2c8`.
2. **The 29.1 KB figure already includes selective disclosure.** The demo's default is
   `pub_mvec=[0,4,5]` — 3 of 8 attributes revealed, 5 hidden — so it is not a "no predicates"
   baseline. Measured across the range on the same host and parameters: 0-of-8 revealed (maximum
   privacy) is 29 107 B. Disclosure is free, and it is implemented rather than something we would
   add: revealed attributes move out of the witness and into the statement
   (`m_priv = self.m.zero_out_pols(pub_mvec)`).

## 3. What the 29.1 KB does *not* include

Revocation. The LNP22 presentation proves knowledge of a signature on a committed message vector;
it does not prove non-membership of a revocation list or membership of an accumulator. LaZer's
Merkle machinery (`python/succinct_zkp/membership_proof.py`) is built on LaBRADOR — the AVX-512
backend — so the branch that is cheap to measure lacks revocation and the code that prices
revocation needs hardware we do not have. That was the open worry.

It has since been priced (`t_0aa1a2c8`, under SDE) and **the worry does not survive**: ~7.56 KB for
a height-64 path, against 947 600 – 1 211 498 B for the same job on the FRI arm. Neither axis an
accumulator loads is expensive — constraint count was flat over the 1..15 range measured, and a 64×
witness increase cost ~33% proof size.

## 4. Security, and the margin that actually worries me

LaZer's generated `anon_cred_params.h` declares:

```
protocol is simulatable under MLWE(26,29,[-1,1])
protocol is knowledge-sound with knowledge error <= 2^(-127.0) under MSIS(17,79,2^33.599457)
MSIS root hermite factor 1.0043951 / MLWE root hermite factor 1.0043734
ring degree d = 64, modulus q = 2199023255717 (log q ~ 41.0)
```

Independently re-run through malb/lattice-estimator under SageMath (`sagemath/sagemath:latest`),
treating MLWE(26,29,[-1,1]) at d = 64 as an LWE instance of dimension 1664, m = 1856, q ≈ 2^41,
ternary secret and error, reporting the **minimum** over all attacks (bkw and arora-gb denied — they
hang at these parameters and are not the relevant attacks; known gotcha for this tooling):

```
REAL:    best attack 2^129.2  ->  129.2 bits.  Declared >= 128: HOLDS.
CONTROL: best attack 2^41.1   ->   41.1 bits.  Below 128: YES.
```

The control is load-bearing, not decoration: a deliberately weak instance at the same q and d was
run **first** and observed to report below 128, because an estimator invocation that returns a large
number for every input looks rigorous and proves nothing. This board has already had a verdict moved
by the ADPS16-vs-MATZOV spread once (`t_c972f73f`).

**129.2 bits is ~1 bit of margin, and only on the MLWE side.** The MSIS / knowledge-soundness side is
unestimated. A parameter set with real headroom will be *larger* than 29.1 KB, and that eats into
§1's numbers. This is the single biggest reason to treat the comparison as order-of-magnitude.

## 5. What remains, and why the recommendation does not wait for it

Card items 1 and 2 — express libQ's own anon-cred relation and derive its size — are open. They are
now **sizing work against a toolchain known to build and run**, not an open feasibility question,
which is the change that lets the recommendation be written. Specifically still needed:

- Our attribute count and predicate set, versus the demo's 8 message polynomials. This is a design
  input we do not yet have fixed, and it is the real blocker on item 1 — not tooling.
- Parameters with genuine security headroom rather than ~1 bit, then a re-measure. Expect growth.
- The MSIS-side estimator run.
- A constraint count representative of a real Poseidon-256 relation. The measured flatness tops out
  at 15 constraints because of an integer-overflow bug in labrador's test fixture
  (`test_proofsystem_setup.c:77`, `MIN(1<<(i+1), 32)` with i up to 2*nconst). Flat over 1..15 is
  genuine, and it is **not** evidence about 10 000.
- The hash measured is LaZer's degree-512 construction, not Poseidon-256.

**The LaZer working tree used for these measurements no longer exists on this host** (cleaned up
after the runs). Reproducing §1 means re-cloning `github.com/lazer-crypto/lazer`, building
`liblazer.a` (7 080 760 B on the recorded run) and the Python bindings, and running
`python3 anon_cred.py` in `python/anon_cred`. Only the LaBRADOR row additionally needs AVX-512, via
Intel SDE.

## 6. Recommendation

**Pursue the lattice branch (LNP22/ABDLOP for presentation, LaBRADOR-class for the accumulator).
The FRI/STARK arm's ~1 MB is not competitive on size for an anon-cred wire, and the gap is two
orders of magnitude — far wider than the uncertainties in §5 can close.**

Qualifications that belong with that sentence:

- This is a recommendation about the **wire**, not about the shipped Arm B membership proof. Arm B
  is merged, 128-bit, and stays where it is; it is the anon-cred *presentation* that is
  uncompetitive at ~1 MB.
- Order-of-magnitude confidence, not a size commitment. §4's 1-bit margin and §5's open items all
  push the same direction: the real number will be larger than 29.1 KB.
- The lattice branch imports a dependency the FRI arm does not have: LaBRADOR-class proving needs
  AVX-512 for practical performance. Deployment reach is a decision this document does not make.
- Everything here is RED. Nothing above has been reviewed by a cryptographer.
