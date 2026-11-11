/* Crashes on well-formed input: the target itself is invalid. */
void ct_crash(unsigned char *key, unsigned char *msg, unsigned char *out) {
  (void)key; (void)msg; (void)out;
  *(volatile int *)0 = 1;
}
