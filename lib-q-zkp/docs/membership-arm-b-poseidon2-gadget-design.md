# Arm B — Poseidon2 in-circuit AIR gadget: implementation-ready design

**Status:** design locked from references (this iteration); implementation + tests land next.
**Goal (build-spec step 3):** an AIR gadget that constrains one width-16 Poseidon2-BabyBear
permutation, with a property test that the in-circuit trace output equals
`lib_q_poseidon::poseidon2_baby_bear::permute` for random inputs, plus corruption-rejection tests.

## References used (in gitignored `reference/plonky3/`)
- `poseidon2-air/src/{columns,air,generation}.rs` — canonical Poseidon2 AIR (column layout +
  constraint structure). We mirror its layout but **omit `SBOX_REGISTERS`** (store the sbox output
  directly) because the spec accepts a degree-7 constraint — the same way Arm A's
  `poseidon_gadget.rs` writes the x⁵ sbox as one degree-5 constraint.
- `poseidon2/src/{external,internal}.rs` — the layer math we already transcribed + matrix-checked
  into `lib-q-poseidon/src/poseidon2_baby_bear.rs` (the value-level reference for trace generation).
- lib-Q conventions: `lib-q-stark-air/src/air.rs` (`AirBuilder`/`BaseAir`/`WindowAccess`),
  `lib-q-zkp/src/air/poseidon_gadget.rs` (flat-column `constrain` style), `lib-q-mve/src/air.rs`
  (the `check_constraints(&air, &trace, &pubs)` test pattern + `#[should_panic]` corruption test).

## Column layout — one permutation per row (`WIDTH=16, HALF_FULL=4, PARTIAL=13`)
Linear layers are **folded into expressions** (no columns); only the per-round S-box outputs and the
post-full-round states are stored — so every full round resets to trace `Var`s (bounds expression
size), and the single S-box per partial round keeps the constraint isolated.

| Region | Cols | Offset formula |
|--------|------|----------------|
| `inputs[16]` | 16 | `0 .. 16` |
| `beginning_full[4]`: each `sbox[16] ‖ post[16]` (32) | 128 | round `r`: sbox `16 + 32r`, post `16 + 32r + 16` |
| `partial[13]`: each `post_sbox` (1) | 13 | round `r`: `144 + r` |
| `ending_full[4]`: each `sbox[16] ‖ post[16]` (32) | 128 | round `r`: sbox `157 + 32r`, post `157 + 32r + 16` |
| **total width** | **285** | output digest = ending_full[3].post = cols `269 .. 285` |

## Constraints (`Air::eval`, all over BabyBear; `AB::F = BabyBear`)
Let `state` carry as `Vec<AB::Expr>`; start `state = inputs[i].into()`.

1. **Initial external linear layer** (degree 1, folded): `state = M_E(state)` where `M_E` is the
   block-circulant of `M4=[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]` (apply `apply_mat4` per 4-block,
   then add the four column-sums `sums[i%4]`). No columns.
2. **Each beginning full round `r`** (constants `RC_EXTERNAL_INITIAL[r]`):
   - S-box (degree **7**): for `i in 0..16`, `assert_eq( sbox[r][i], (state[i] + rc[r][i])^7 )`
     with `x^7 = (x²)² · x² · x`.
   - external layer (degree 1): `post_expr = M_E(sbox[r] as Vars)`; for `i`, `assert_eq(post[r][i],
     post_expr[i])`. Set `state = post[r][i].into()` (Vars).
3. **Each partial round `r`** (single constant `RC_INTERNAL[r]`):
   - S-box on lane 0 (degree 7): `assert_eq( post_sbox[r], (state[0] + RC_INTERNAL[r])^7 )`.
   - internal layer (degree 1, folded): `pre = [post_sbox[r], state[1..16]]`;
     `sum = Σ pre`; `state[i] = V[i]·pre[i] + sum` (carry as expressions; **not** stored).
     `V = [-2,1,2,1/2,3,4,-1/2,-3,-4,1/2⁸,1/4,1/8,1/2²⁷,-1/2⁸,-1/16,-1/2²⁷]`.
4. **Each ending full round `r`**: identical to step 2 with `RC_EXTERNAL_FINAL[r]`.
5. **Output**: `state` now equals `ending_full[3].post` columns; callers bind these to the digest.

**Max constraint degree = 7** (the S-box rows; everything else degree 1). Report the resulting FRI
`log_blowup` bump vs Arm A (degree 5) in the measurement table. The 15 unsboxed lanes across the 13
partial rounds become large *degree-1* expressions; this only affects symbolic proving cost (step 6),
not `check_constraints` (concrete eval) and not soundness.

## Trace generation (`generate_poseidon2_row(input) -> [BabyBear; 285]`)
Replay `poseidon2_baby_bear::permute` step-by-step, writing each `sbox`/`post`/`post_sbox` cell as it
is produced (reuse the crate's `apply_mat4`/`external_linear_layer`/`internal` helpers — expose them
`pub(crate)` or duplicate minimally). Pad to a power-of-two height (`MIN_ROWS`, repeat-last like
`lib-q-mve`) for the FRI/ZK floor.

## Tests (mirror `lib-q-mve/src/air.rs`)
- `gadget_matches_value_level`: for N random inputs, build the trace, `check_constraints(&air,
  &trace, &[])` passes, and `trace.ending_full[3].post == permute(input)`.
- `#[should_panic]` corruption: flip (a) a `sbox` cell, (b) a `post` cell, (c) a `post_sbox` cell, (d)
  an `input` cell while leaving the claimed output — each must make `check_constraints` panic. This is
  the under-constrained-column hunt for step 3 (every stored column has a constraint that pins it).

## Reuse
The `constrain_permutation(builder, initial_state_exprs, start_col) -> Vec<Expr>` entry point (final
state expressions, no output binding) is what steps 4–5 (wide sponge / Merkle / nullifier / membership
AIR) call repeatedly — analogous to Arm A's `PoseidonGadget::constrain_permutation`.

## Honesty
`check_constraints` proving the trace satisfies the AIR shows the gadget *computes Poseidon2
correctly and is fully constrained* — it does NOT prove the round counts are cryptographically sound
(that's the obligation packet, tier RED). The degree-7 S-box and the `M_E`/internal-diagonal matrices
are the deployed instance; their security is cited, not established here.
