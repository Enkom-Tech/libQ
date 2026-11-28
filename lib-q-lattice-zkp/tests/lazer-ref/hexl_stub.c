/* HEXL NTT entry points are never reached by the uniform-sampling path the
 * harness exercises; abort loudly if that assumption is ever wrong. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
static void die(const char *f){fprintf(stderr,"hexl stub reached: %s\n",f);abort();}
void *hexl_ntt_alloc(uint64_t d,uint64_t p){(void)d;(void)p;return (void*)1;}
void hexl_ntt_fwd(void*a,int64_t*b,uint64_t c,const int64_t*d,uint64_t e){(void)a;(void)b;(void)c;(void)d;(void)e;die("fwd");}
void hexl_ntt_inv(void*a,int64_t*b,uint64_t c,const int64_t*d,uint64_t e){(void)a;(void)b;(void)c;(void)d;(void)e;die("inv");}
void hexl_ntt_free(void*a){(void)a;}
void hexl_ntt_add(int64_t*r,const int64_t*a,const int64_t*b,uint64_t d,uint64_t p){(void)r;(void)a;(void)b;(void)d;(void)p;die("add");}
void hexl_ntt_sub(int64_t*r,const int64_t*a,const int64_t*b,uint64_t d,uint64_t p){(void)r;(void)a;(void)b;(void)d;(void)p;die("sub");}
void hexl_ntt_mul(int64_t*r,const int64_t*a,const int64_t*b,uint64_t f,uint64_t d,uint64_t p){(void)r;(void)a;(void)b;(void)f;(void)d;(void)p;die("mul");}
void hexl_ntt_scale(int64_t*r,const uint64_t s,const int64_t*b,int64_t d,uint64_t p){(void)r;(void)s;(void)b;(void)d;(void)p;die("scale");}
void hexl_ntt_red(int64_t*r,uint64_t f,const int64_t*a,uint64_t i,uint64_t d,uint64_t p){(void)r;(void)f;(void)a;(void)i;(void)d;(void)p;die("red");}
