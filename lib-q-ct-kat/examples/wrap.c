/* Thin C entry points over the Rust shim (shim/src/lib.rs). NOTE for asm_scan: this file is all
 * the C compiler sees; the Rust code behind it is compiled by rustc/LLVM and is NOT covered by
 * the assembly scan. */
extern void ctkat_mlkem768_decaps(const unsigned char *seed, const unsigned char *ct, unsigned char *out);
extern void ctkat_mldsa44_sign(const unsigned char *seed, const unsigned char *msg, unsigned char *out);
void libq_mlkem768_decaps(unsigned char *seed, unsigned char *ct, unsigned char *out) { ctkat_mlkem768_decaps(seed, ct, out); }
void libq_mldsa44_sign(unsigned char *seed, unsigned char *msg, unsigned char *out) { ctkat_mldsa44_sign(seed, msg, out); }
