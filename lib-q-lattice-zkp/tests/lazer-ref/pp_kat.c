/* Reference harness: dump LaZer's anon_cred public-parameter
 * expansion (python/anon_cred/anon_cred.py lines 24-26) using LaZer's own
 * polymat_urandom and RNG, unmodified, linked from src/lazer.c. */
#include "lazer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void unhex(uint8_t *o, const char *h, size_t n)
{ for (size_t i = 0; i < n; i++) sscanf(h + 2*i, "%2hhx", &o[i]); }

static void dump_mat(const char *name, polyring_t ring, unsigned r, unsigned c,
                     const uint8_t seed[32], uint32_t dom)
{
  polymat_t m; polymat_alloc(m, ring, r, c);
  INT_T(q, 1); int_set_i64(q, 12289);
  polymat_urandom(m, q, 14, seed, dom);  /* log2mod = (12289-1).bit_length() */
  printf("%s %u %u %u", name, r, c, dom);
  for (unsigned i = 0; i < r; i++) for (unsigned j = 0; j < c; j++) {
    int64_t v[64]; poly_get_coeffvec_i64(v, polymat_get_elem(m, i, j));
    for (int k = 0; k < 64; k++) printf(" %lld", (long long)v[k]);
  }
  printf("\n"); polymat_free(m);
}

int main(int argc, char **argv)
{
  uint8_t seed[32]; if (argc < 2) return 2; unhex(seed, argv[1], 32);
  lazer_init();
  /* raw RNG stream: seed, dom = (1 << 32) | 0, i.e. matrix dom 1 element (0,0) */
  rng_state_t st; uint8_t out[160];
  rng_init(st, seed, ((uint64_t)1 << 32)); rng_urandom(st, out, sizeof out); rng_clear(st);
  printf("rng"); for (size_t i = 0; i < sizeof out; i++) printf(" %u", out[i]); printf("\n");
  INT_T(q, 1); int_set_i64(q, 12289);
  POLYRING_T(ring, q, 64);
  dump_mat("AR", ring, 8, 16, seed, 1);
  dump_mat("AM", ring, 8, 8, seed, 2);
  dump_mat("ATAU", ring, 8, 8, seed, 3);
  return 0;
}
