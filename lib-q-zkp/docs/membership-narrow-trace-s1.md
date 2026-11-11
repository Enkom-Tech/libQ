# Narrow-trace membership AIR (the tracked task, Track S step S1) — RED / research

Code: `lib-q-zkp/src/air/narrow_membership_baby_bear.rs`. Same frozen statement as
`unlinkable_membership_baby_bear` (`libq.zkfri.membership.v0`, public values `root(9) ‖ ctx(4) ‖ N(9)`),
same Poseidon2 / sponge / node hash, same FRI config (`default_config_bb`: blowup 16, 96 queries, PoW 20).
Not a soundness claim; the Poseidon2 round-count obligations (O1/O4) are unchanged and still open.

## Layout
One Poseidon2 round per row, 22 rows per permutation, 73 columns (wide AIR: 1661). Permutations in
order LEAF, NULL0, NULL1, then NODE0..2 per level, then PAD. Round index and stage are one-hot rings in
the main trace, NOT preprocessed columns: `setup_preprocessed` asserts non-ZK, and the membership
statement needs the hiding config. Max constraint degree 9. Depth is a parameter of the AIR
(`rem` counter pinned to `depth-1` on row 0, root check gated on `rem == 0`).

## Measured (release, single thread, this VM; `measure_narrow`, ignored test)
| depth | width | height | prove ms | verify ms | proof bytes | of which opening_proof |
|---|---|---|---|---|---|---|
| 4  | 73 | 512  | 861  | 11.7 | 381 982 | 377 555 |
| 20 | 73 | 2048 | 2549 | 14.7 | 481 895 | 477 483 |
| 32 | 73 | 4096 | 1761 | 19.8 | 536 728 | 532 307 |

Wide AIR for comparison (`membership-arm-b-measurement.md`, other host, INHERITED): 947 600 B (d=4),
1 038 028 B (d=32). Narrow is ~2.5x / ~1.9x smaller, not the 5x+ the width ratio (22x) suggests.
Prove times are wall-clock on a shared VM and noisy (d=32 ran faster than d=20); treat as order of magnitude.

## Finding
Width is no longer the cost. `opening_proof` is ~99% of the bytes; it is per-query Merkle paths
(32-byte SHAKE256 digests, ~log2(height*blowup) levels, for the trace, quotient and each FRI layer).
Floor with 96 queries is ~380 KB regardless of width. The downstream doc's "low hundreds of KB" and the S3
bound of 200 KB are not reachable at these FRI parameters; levers are fewer queries with more PoW /
larger blowup (changes the 128-bit accounting, needs the soundness packet), de-duplicated or
multi-opened Merkle paths, or truncated digests (collision margin).

## Verified vs inferred
Verified by running: reference permutation equality, honest trace satisfies constraints at depth 1-4 and
reproduces the wide AIR's root and nullifier, wrong nullifier/root/ctx/depth rejected, every column
corrupted at three rows is rejected, prove+verify roundtrip, tampered nullifier and wrong depth rejected
by the verifier, ZK-free numbers above. NOT done: ZK (hiding) config run, wasm/no_std builds, wire/envelope,
phone measurement (S3), independent review. S2 (attributes + range predicate) is NOT built.
