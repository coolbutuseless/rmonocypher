
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include <R.h>
#include <Rinternals.h>
#include <Rdefines.h>
#include <R_ext/Connections.h>

#if ! defined(R_CONNECTIONS_VERSION) || R_CONNECTIONS_VERSION != 1
#error "Unsupported connections API version"
#endif


#include "monocypher.h"
#include "utils.h"
#include "argon2.h"


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// x25519 key exchange
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP create_public_key_(SEXP your_secret_key_, SEXP type_) {
  
  uint8_t private_key[32];
  uint8_t  public_key[32];
  unpack_key(your_secret_key_, private_key);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // void crypto_x25519_public_key(
  //     uint8_t your_public_key[32], 
  //     const uint8_t your_secret_key[32]
  // );
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_x25519_public_key(public_key, private_key);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Return value
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  SEXP public_key_ = R_NilValue;
  const char *type = CHAR(STRING_ELT(type_, 0));
  
  if (strcmp(type, "raw") == 0) {
    public_key_ = PROTECT(allocVector(RAWSXP, 32));
    memcpy(RAW(public_key_), public_key, 32);
  } else {
    char *hex = bytes_to_hex(public_key, 32);
    public_key_ = PROTECT(allocVector(STRSXP, 1));
    SET_STRING_ELT(public_key_, 0, mkChar(hex));
  }
  
  UNPROTECT(1);
  return public_key_;
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP create_shared_key_(SEXP their_public_key_, SEXP your_secret_key_, SEXP type_) {
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Setup 
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t your_secret_key [32];
  uint8_t your_public_key [32];
  uint8_t their_public_key[32];
  uint8_t shared_secret   [32]; /* Shared secret (NOT a key) */
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Unpack the given keys
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  unpack_key(their_public_key_, their_public_key);
  unpack_key( your_secret_key_,  your_secret_key);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // void crypto_x25519_public_key(
  //     uint8_t your_public_key[32], 
  //     const uint8_t your_secret_key[32]
  // );
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_x25519_public_key(your_public_key, your_secret_key);
  // dump_uint8(your_public_key, 32);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // void crypto_x25519(
  //    uint8_t raw_shared_secret[32], 
  //    const uint8_t your_secret_key[32], 
  //    const uint8_t their_public_key[32]
  // );
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_x25519(shared_secret, your_secret_key, their_public_key);
  crypto_wipe(your_secret_key, 32); // not needed again
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // "Many (private, public) key pairs produce the same shared secret. Therefore, 
  // not including the public keys in the key derivation can lead to subtle 
  // vulnerabilities. This can be avoided by hashing the shared secret 
  // concatenated with both public keys" - monocypher docs
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t shared_key[32]; 
  crypto_blake2b_ctx ctx;
  crypto_blake2b_init  (&ctx, 32);
  crypto_blake2b_update(&ctx,    shared_secret, 32);
  
  // Need deterministic ordering of hashing these two keys so that 
  // both parties hash in the same way.
  if (memcmp(your_public_key, their_public_key, 32) < 0) {
    crypto_blake2b_update(&ctx,  your_public_key, 32);
    crypto_blake2b_update(&ctx, their_public_key, 32);
  } else {
    crypto_blake2b_update(&ctx, their_public_key, 32);
    crypto_blake2b_update(&ctx,  your_public_key, 32);
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Extract the final key
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_blake2b_final (&ctx, shared_key);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Return value
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  SEXP shared_key_ = R_NilValue;
  const char *type = CHAR(STRING_ELT(type_, 0));
  
  if (strcmp(type, "raw") == 0) {
    shared_key_ = PROTECT(allocVector(RAWSXP, 32));
    memcpy(RAW(shared_key_), shared_key, 32);
  } else {
    char *hex = bytes_to_hex(shared_key, 32);
    shared_key_ = PROTECT(allocVector(STRSXP, 1));
    SET_STRING_ELT(shared_key_, 0, mkChar(hex));
  }
  
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Tidy and return
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_wipe(shared_key   , 32);
  crypto_wipe(shared_secret, 32);
  UNPROTECT(1); 
  return shared_key_;
}
