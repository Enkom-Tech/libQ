"""Turn pp_kat.c output into tests/vectors/lazer_anon_cred_pp_v0.txt."""
import sys

seed, path = sys.argv[1], sys.argv[2]
print("""# LaZer anon_cred public parameters -- EXTERNAL ORACLE, third-party origin.
#
# origin: third-party (LaZer, https://github.com/lazer-crypto/lazer, commit
#         10eafeca4cd53ff4fc54193dce904dbd0026fefd -- NOT this repository's code).
# NOT self-generated: every number below was printed by LaZer's own src/lazer.c
# (polymat_urandom, rng_urandom, RNG_AES256CTR) via tests/lazer-ref/pp_kat.c, built for
# TARGET_AMD64 and TARGET_GENERIC with byte-identical output. Regenerate with
# tests/lazer-ref/gen_anon_cred_pp_kat.sh.
#
# Construction (python/anon_cred/anon_cred.py): seed = SHAKE128(0x00).digest(32) (BLINDSIGPP);
# AR = urandom(8x16, mod 12289, dom 1); AM = urandom(8x8, dom 2); ATAU = urandom(8x8, dom 3).
#
# Lines:
#   seed <hex>
#   rng <hex>               first 160 bytes of rng_init(seed, dom = 1 << 32)
#   poly <MAT> <i> <j> c0 .. c63   coefficients of element (i, j), values in [0, 12289)""")
print("seed", seed)
for line in open(path):
    f = line.split()
    if f[0] == "rng":
        print("rng", bytes(int(x) for x in f[1:]).hex())
        continue
    name, rows, cols = f[0], int(f[1]), int(f[2])
    vals = f[4:]
    assert len(vals) == rows * cols * 64, name
    for i in range(rows):
        for j in range(cols):
            k = (i * cols + j) * 64
            print("poly", name, i, j, " ".join(vals[k:k + 64]))
