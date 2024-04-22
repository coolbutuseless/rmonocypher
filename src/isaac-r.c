
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
#include "utils.h"


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Return the chunk of 256 uint32_t random integers as 1024 uint8_t
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP isaac_(SEXP n_, SEXP type_) {
  ub4 i;
  randctx ctx;
  ctx.randa=ctx.randb=ctx.randc=(ub4)0;
  
  int n = asInteger(n_);
  if (n < 1 || n > 256*4) {
    error("isaac_(): Expect 1 <= n <= 1024. Not %i", n);
  }
  
  GetRNGstate();
  // Initialise buffers with random numbers from R 'runif()'
  for (i=0; i<256; ++i) {
    ctx.randrsl[i] = (uint32_t)(unif_rand() * INT32_MAX);
  }
  PutRNGstate();
  
  // initialise isaac.
  // Arg = TRUE means to use ctx.randrsl to init state
  randinit(&ctx, TRUE);
  
  // Run it twice. Just because
  isaac(&ctx);
  isaac(&ctx);
  
  return wrap_bytes_for_return((uint8_t *)ctx.randrsl, n, type_);
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








