
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include <R.h>
#include <Rinternals.h>
#include <Rdefines.h>

#include "monocypher.h"
#include "utils.h"
#include "argon2.h"
#include "rcrypto.h"


#define KEYSIZE   32
#define NONCESIZE 24
#define LENGTHSIZE sizeof(size_t)
#define MACSIZE   16



SEXP blake2b_raw_(SEXP x_, SEXP N_, SEXP type_) {
  
  if (asInteger(N_) < 1 || asInteger(N_) > 64) {
    error("blake2b_raw(): N must be >= 1, not %i", asInteger(N_));
  }
  size_t N = (size_t)asInteger(N_);
  
  uint8_t *buf = NULL;
  size_t buf_size;
  
  if (TYPEOF(x_) == RAWSXP) {
    buf = (uint8_t *)RAW(x_);
    buf_size = (size_t)xlength(x_);
  } else if (TYPEOF(x_) == STRSXP) {
    const char *str = CHAR(STRING_ELT(x_, 0));
    buf_size = strlen(str);
    buf = (uint8_t *)str;
  }
  
  if (buf == NULL) {
    error("blake2b_raw(): input buffer is NULL");
  }
  
  // void
  // crypto_blake2b(uint8_t hash[64], size_t hash_size, const uint8_t *message, size_t message_size);
  uint8_t hash[64];
  crypto_blake2b(hash, N, buf, buf_size);
  
  
  return wrap_bytes_for_return(hash, N, type_);
}
