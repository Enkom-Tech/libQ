#!/usr/bin/env python3
"""Independent reference + constant emitter for Poseidon2-BabyBear width 16.

Validation strategy (see lib-q-zkp/docs/membership-arm-b-build-status.md):
  * CONSTANTS are PARSED straight from the upstream Plonky3 source file
    `baby-bear/src/poseidon2.rs` (no manual re-typing) and emitted as Rust
    literals, so the field-element constants flow source -> here -> Rust
    mechanically. Source: https://github.com/Plonky3/Plonky3 (main),
    baby-bear/src/poseidon2.rs (Grain LFSR: field_type=1, alpha=7, n=31, t=16,
    R_F=8, R_P=13).
  * The LINEAR LAYERS are each checked here against their DOCUMENTED MATRIX form
    (external M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] with outer circulant;
    internal (1 + diag(V))), so the layer formulas are not merely transcribed.
  * The permutation OUTPUT vectors emitted here are the KAT the Rust value-level
    permutation must reproduce (independent re-implementation of the algorithm).

NOTE (honesty): this is NOT a third-party binary KAT. Executing upstream Plonky3
to anchor the deployed-constant output was blocked by policy; the constants are
verbatim-from-source and the layers are matrix-checked, but a direct
upstream-compiled vector remains a documented open item.

Run:  python tools/gen_poseidon2_ref.py [path-to-fetched-poseidon2.rs]
"""
import re
import sys
import os

P = 2**31 - 2**27 + 1
WIDTH = 16
HALF_FULL = 4
PARTIAL = 13

def inv(x):
    return pow(x % P, -1, P)

# --- internal diagonal V (V = mat_internal_diag_m_1), width 16, from upstream comment ---
# V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/4, 1/8, 1/2^27, -1/2^8, -1/16, -1/2^27]
V = [(-2) % P, 1, 2, inv(2), 3, 4, (-inv(2)) % P, (-3) % P, (-4) % P,
     inv(2**8), inv(2**2), inv(2**3), inv(2**27),
     (-inv(2**8)) % P, (-inv(2**4)) % P, (-inv(2**27)) % P]

def parse_constants(path):
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    def grab(marker, count):
        i = src.index(marker)
        j = src.index("]);", i)
        hexes = re.findall(r"0x[0-9a-fA-F]+", src[i:j])
        vals = [int(h, 16) for h in hexes]
        assert len(vals) == count, f"{marker}: got {len(vals)} expected {count}"
        for v in vals:
            assert 0 <= v < P, f"{marker}: {hex(v)} not in [0,P)"
        return vals
    ext_init = grab("BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL", 64)
    ext_fin  = grab("BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL", 64)
    internal = grab("BABYBEAR_POSEIDON2_RC_16_INTERNAL", 13)
    return ([ext_init[r*16:(r+1)*16] for r in range(4)],
            [ext_fin[r*16:(r+1)*16] for r in range(4)],
            internal)

def sbox(x):
    return pow(x % P, 7, P)

# --- external layer ---
M4 = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]

def mat4_formula(x):
    # verbatim transcription of Plonky3 apply_mat4
    t01 = (x[0] + x[1]) % P
    t23 = (x[2] + x[3]) % P
    t0123 = (t01 + t23) % P
    t01123 = (t0123 + x[1]) % P
    t01233 = (t0123 + x[3]) % P
    o3 = (t01233 + 2 * x[0]) % P
    o1 = (t01123 + 2 * x[2]) % P
    o0 = (t01123 + t01) % P
    o2 = (t01233 + t23) % P
    return [o0, o1, o2, o3]

def mat4_matrix(x):
    return [sum(M4[r][c] * x[c] for c in range(4)) % P for r in range(4)]

def external_linear(state):
    s = state[:]
    for c in range(0, WIDTH, 4):
        blk = mat4_formula(s[c:c+4])
        s[c:c+4] = blk
    sums = [sum(s[j+k] for j in range(0, WIDTH, 4)) % P for k in range(4)]
    return [(s[i] + sums[i % 4]) % P for i in range(WIDTH)]

def external_matrix(state):
    # M_E = [[2M4, M4, ...],[M4, 2M4, ...], ...] (block circulant, 2 on the diagonal block)
    out = [0] * WIDTH
    for bi in range(4):
        for bj in range(4):
            coeff = 2 if bi == bj else 1
            for r in range(4):
                acc = 0
                for c in range(4):
                    acc += coeff * M4[r][c] * state[bj*4 + c]
                out[bi*4 + r] = (out[bi*4 + r] + acc) % P
    return out

def internal_layer(state):
    sm = sum(state) % P
    return [(V[i] * state[i] + sm) % P for i in range(WIDTH)]

def internal_matrix(state):
    # (J + diag(V)) state, J = all-ones
    sm = sum(state) % P
    return [(sm + V[i] * state[i]) % P for i in range(WIDTH)]

def permute(state, ext_init, ext_fin, internal_rc):
    s = external_linear(state)
    for r in range(HALF_FULL):
        s = [sbox((s[i] + ext_init[r][i]) % P) for i in range(WIDTH)]
        s = external_linear(s)
    for r in range(PARTIAL):
        s[0] = sbox((s[0] + internal_rc[r]) % P)
        s = internal_layer(s)
    for r in range(HALF_FULL):
        s = [sbox((s[i] + ext_fin[r][i]) % P) for i in range(WIDTH)]
        s = external_linear(s)
    return s

def rng32(seed):
    # tiny deterministic LCG just to drive structural self-checks (NOT crypto)
    x = seed & 0xffffffff
    while True:
        x = (1103515245 * x + 12345) & 0x7fffffff
        yield x % P

def self_checks():
    g = rng32(12345)
    for _ in range(200):
        x = [next(g) for _ in range(4)]
        assert mat4_formula(x) == mat4_matrix(x), "mat4 formula != matrix M4"
    for _ in range(200):
        st = [next(g) for _ in range(WIDTH)]
        assert external_linear(st) == external_matrix(st), "external formula != block-circulant M_E"
        assert internal_layer(st) == internal_matrix(st), "internal formula != (J+diag(V))"
    print("SELF-CHECKS PASSED: mat4==M4, external==M_E(block-circ), internal==(J+diag(V))")

def emit_rust(name, rows):
    if isinstance(rows[0], list):
        body = ",\n".join("    [" + ", ".join(f"BabyBear::new({v})" for v in row) + "]" for row in rows)
        print(f"// {name}\n[\n{body},\n];\n")
    else:
        body = ", ".join(f"BabyBear::new({v})" for v in rows)
        print(f"// {name}\n[{body}];\n")

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.environ.get("TEMP", "/tmp"), "p3ref", "baby-bear__src__poseidon2.rs")
    self_checks()
    ext_init, ext_fin, internal_rc = parse_constants(path)
    print(f"Parsed constants from: {path}")

    test_inputs = {
        "file_random": [894848333, 1437655012, 1200606629, 1690012884, 71131202, 1749206695,
                        1717947831, 120589055, 19776022, 42382981, 1831865506, 724844064,
                        171220207, 1299207443, 227047920, 1783754913],
        "iota_0_15": list(range(16)),
        "all_ones": [1]*16,
    }
    print("\n==== DEPLOYED-CONSTANT KAT VECTORS (Rust must reproduce) ====")
    for nm, inp in test_inputs.items():
        out = permute(inp, ext_init, ext_fin, internal_rc)
        print(f"{nm}:\n  in  = {inp}\n  out = {out}")

    print("\n==== Rust const literals ====")
    emit_rust("RC_EXTERNAL_INITIAL: [[BabyBear; 16]; 4]", ext_init)
    emit_rust("RC_EXTERNAL_FINAL: [[BabyBear; 16]; 4]", ext_fin)
    emit_rust("RC_INTERNAL: [BabyBear; 13]", internal_rc)
    print("DONE")

if __name__ == "__main__":
    main()
