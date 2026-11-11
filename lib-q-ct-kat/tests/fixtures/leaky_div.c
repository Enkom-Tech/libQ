/* Secret-dependent division: the divisor comes from the key, so div/idiv latency varies. */
volatile unsigned int sink_den;
void ct_leaky_div(unsigned char *key, unsigned char *msg, unsigned char *out) {
  unsigned int den = sink_den = ((unsigned int)key[0] | 1u);
  for (int i = 0; i < 16; i++) out[i] = (unsigned char)((unsigned int)msg[i] * 977u / den);
}
