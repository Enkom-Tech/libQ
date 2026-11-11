/* Secret-dependent loop count: running time grows with the key byte. */
void ct_leaky_branch(unsigned char *key, unsigned char *msg, unsigned char *out) {
  volatile unsigned int acc = 0;
  for (int i = 0; i < 16; i++) out[i] = msg[i];
  if (key[0] & 1) {
    for (int r = 0; r < 20000; r++) acc += (unsigned int)r;
  }
  out[0] ^= (unsigned char)acc;
}
