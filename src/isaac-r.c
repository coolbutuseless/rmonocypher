
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>


#include <R.h>
#include <Rinternals.h>
#include <Rdefines.h>
#include <R_ext/Connections.h>

#if ! defined(R_CONNECTIONS_VERSION) || R_CONNECTIONS_VERSION != 1
#error "Unsupported connections API version"
#endif


#include "isaac-rand.h"
#include "isaac-r.h"


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Return the chunk of 256 uint32_t random integers as 1024 uint8_t
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP isaac_(SEXP n_) {
  ub4 i;
  randctx ctx;
  ctx.randa=ctx.randb=ctx.randc=(ub4)0;
  
  int n = asInteger(n_);
  if (n < 1 || n > 256*4) {
    error("isaac_(): Expect 1 <= n <= 1024. Not %i", n);
  }
  
  GetRNGstate();
  // Initialise buffers
  for (i=0; i<256; ++i) {
    ctx.randrsl[i] = (uint32_t)(unif_rand() * INT32_MAX);
  }
  PutRNGstate();
  
  // initialise isaac.
  // Arg = TRUE means to use ctx.randrsl to init state
  randinit(&ctx, TRUE);
  
  isaac(&ctx);
  isaac(&ctx);
  
  SEXP res_ = PROTECT(allocVector(RAWSXP, n));
  
  memcpy(RAW(res_), ctx.randrsl, n);
  
  // for (i=0; i<2; ++i) {
  //   isaac(&ctx);
  //   for (j=0; j<256; ++j) {
  //     Rprintf("%.8lx ",ctx.randrsl[j]);
  //     if ((j&7)==7) Rprintf("\n");
  //   }
  //   Rprintf("\n");
  // }

  UNPROTECT(1);  
  return res_;
}


void fill_isaac(uint8_t *buf, int n) {
  if (n < 1 || n > 1024) {
    error("fill_isaac() improbably n = %i", n);
  }
  
  // Create the context
  randctx ctx;
  ctx.randa = ctx.randb = ctx.randc = 0;
  
  // Initialise RNG state buffers
  GetRNGstate();
  for (int i = 0; i < 256; ++i) {
    ctx.randrsl[i] = (uint32_t)(unif_rand() * INT32_MAX);
  }
  PutRNGstate();
  randinit(&ctx, TRUE);
  
  // Use the second run of isaac numbers
  isaac(&ctx);
  isaac(&ctx);
  
  memcpy(buf, ctx.randrsl, n);
}








