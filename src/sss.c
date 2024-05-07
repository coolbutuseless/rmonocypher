
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


#include "hazmat.h"
#include "utils.h"

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// One share of a cryptographic key which is shared using Shamir's
// the `sss_create_keyshares` function.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// typedef uint8_t sss_Keyshare[sss_KEYSHARE_LEN];


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// 
// Share the secret given in `key` into `n` shares with a treshold value given
// in `k`. The resulting shares are written to `out`.
// 
// The share generation that is done in this function is only secure if the key
// that is given is indeed a cryptographic key. This means that it should be
// randomly and uniformly generated string of 32 bytes.
// 
// Also, for performance reasons, this function assumes that both `n` and `k`
// are *public* values.
// 
// If you are looking for a function that *just* creates shares of arbitrary
// data, you should use the `sss_create_shares` function in `sss.h`.
// 
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP create_keyshares_(SEXP key_, SEXP n_, SEXP k_, SEXP type_) {
  
  if (asInteger(n_) <= 1 || asInteger(n_) > 255) {
    error("Bad n");
  }
  if (asInteger(k_) < 1 || asInteger(k_) > 255) {
    error("Bad k");
  }
  
  uint8_t n = (uint8_t)asInteger(n_);
  uint8_t k = (uint8_t)asInteger(k_);
  
  uint8_t key[32];
  unpack_key(key_, key);
  
  sss_Keyshare *out = calloc(n, sizeof(sss_Keyshare));
  
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // void sss_create_keyshares(sss_Keyshare *out,
  //                           const uint8_t key[32],
  //                           uint8_t n,
  //                           uint8_t k);
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  sss_create_keyshares(out, key, n, k);
  
  SEXP res_ = PROTECT(allocVector(VECSXP, (R_xlen_t)n));
  
  for (int i = 0; i < n; i++) { 
    SET_VECTOR_ELT(res_, i, wrap_bytes_for_return(out[i], sss_KEYSHARE_LEN, type_));
  }
  
  free(out);
  UNPROTECT(1);
  return res_;
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Combine the `k` shares provided in `shares` and write the resulting key to
// `key`. The amount of shares used to restore a secret may be larger than the
// threshold needed to restore them.
// 
// This function does *not* do *any* checking for integrity. If any of the
// shares not original, this will result in an invalid resored value.
// All values written to `key` should be treated as secret. Even if some of the
// shares that were provided as input were incorrect, the resulting key *still*
// allows an attacker to gain information about the real key.
// 
// This function treats `shares` and `key` as secret values. `k` is treated as
// a public value (for performance reasons).
// 
// If you are looking for a function that combines shares of arbitrary
// data, you should use the `sss_combine_shares` function in `sss.h`.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP combine_keyshares_(SEXP shares_, SEXP type_) {

  if (!isNewList(shares_)) {
    error("Shares must be a list");
  }
  
  int k = (int)length(shares_);
  if (k < 1 || k > 255) {
    error("Bad k");
  }
  
  sss_Keyshare *shares = calloc((unsigned long)k, sizeof(sss_Keyshare));
  
  
  for (int i = 0; i < k; i++) {
    unpack_bytes(VECTOR_ELT(shares_, i), shares[i], sss_KEYSHARE_LEN);
    // memcpy(shares[i], RAW(VECTOR_ELT(shares_, i)), sss_KEYSHARE_LEN);
  }

  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // void sss_combine_keyshares(uint8_t key[32],
  //                            const sss_Keyshare *shares,
  //                            uint8_t k);
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t key[32];
  sss_combine_keyshares(key, (const sss_Keyshare *)shares, (uint8_t)k);
  // SEXP key_ = PROTECT(allocVector(RAWSXP, 32));
  // memcpy(RAW(key_), key, 32);
  
  SEXP key_ = PROTECT(wrap_bytes_for_return(key, 32, type_));
  
  free(shares);
  UNPROTECT(1);
  return key_;
}









