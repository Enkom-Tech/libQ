/* Constant-time: data-independent control flow, no division, no secret-indexed loads. */
void ct_clean(unsigned char *key, unsigned char *msg, unsigned char *out) {
  for (int i = 0; i < 16; i++) out[i] = (unsigned char)(key[i] ^ msg[i]);
}
