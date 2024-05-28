
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <R.h>
#include <Rinternals.h>
#include <Rdefines.h>

#include "monocypher.h"
#include "utils.h"
#include "argon2.h"

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//  Argon function call
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// hash
// The output hash. If all parameters to crypto_argon2() are identical between 
// two calls, then the output hash is also identical. In other words, all input 
// parameters passed to the function influence the output value.
// 
// hash_size
// Length of hash, in bytes. This argument should be set to 32 or 64 for 
// compatibility with the crypto_verify32() or crypto_verify64() constant time 
// comparison functions.
// 
// work_area
// Temporary buffer for the algorithm, allocated by the caller. It must be 
// config.nb_blocks × 1024 bytes big and suitably aligned for 64-bit integers.
// If you are not sure how to allocate that buffer, just use malloc(3).
// The work area is automatically wiped by crypto_argon2().
// 
// config
// A struct of type crypto_argon2_config that determines the base parameters 
// of this particular instance of Argon2. These are domain parameters and remain 
// constant between multiple invocations of crypto_argon2().
// inputs
// A struct of type crypto_argon2_inputs that contains the actual input 
// parameters.
// 
// extras
// A struct of type crypto_argon2_extras that contains optional extra input 
// parameters, which are not commonly used. 

// void
// crypto_argon2(
//   uint8_t *hash, 
//   uint32_t hash_size, 
//   void *work_area, 
//   crypto_argon2_config config, 
//   crypto_argon2_inputs inputs, 
//   crypto_argon2_extras extras
// );



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//  Configuration struct
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// algorithm
// This value determines which variant of Argon2 should be used. CRYPTO_ARGON2_D 
// indicates Argon2d, CRYPTO_ARGON2_I indicates Argon2i, CRYPTO_ARGON2_ID indicates 
// Argon2id.
// 
// nb_blocks
// The number of blocks for the work area. Must be at least 8 × nb_lanes. A value
// of 100000 (one hundred megabytes) is a good starting point. If the computation
// takes too long, reduce this number. If it is too fast, increase it. If it is 
// still too fast with all available memory, increase nb_passes.
// 
// nb_passes
// The number of passes. Must be at least 1. A value of 3 is strongly recommended 
// when using Argon2i; any value lower than 3 enables significantly more efficient
// attacks.
// 
// nb_lanes
// The level of parallelism. Must be at least 1. Since Monocypher does not support 
// threads, this does not actually increase the number of threads. It is only
// provided for completeness to match the Argon2 specification. Otherwise, leaving
// it to 1 is strongly recommended.
// 
// Users who want to take actual advantage of parallelism should instead call
// several instances of Argon2 in parallel. The extras parameter may be used to 
// differentiate the inputs and produce independent digests that can be hashed together.

// typedef struct {
//   uint32_t algorithm;
//   uint32_t nb_blocks;
//   uint32_t nb_passes;
//   uint32_t nb_lanes;
// } crypto_argon2_config;


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Inputs struct
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// pass
// The password to hash. It should be wiped with crypto_wipe() after being hashed.
// 
// pass_size
// Length of pass, in bytes.
// 
// salt
// A password salt. This should be filled with random bytes, generated separately 
// for each password to be hashed. See intro() for advice about generating random 
// bytes (use the operating system's random number generator).
// 
// salt_size
// Length of salt, in bytes. Must be at least 8. 16 is recommended. 

// typedef struct {
//   const uint8_t *pass;
//   const uint8_t *salt;
//   uint32_t pass_size;
//   uint32_t salt_size;
// } crypto_argon2_inputs;


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Extras struct
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// key
// A key to use in the hash. May be NULL if key_size is zero. The key is generally
// not needed, but it does have some uses. In the context of password derivation, 
// it would be stored separately from the password database and would remain secret 
// even if an attacker were to steal the database. Note that changing the key 
// requires rehashing the user's password, which can only be done when the user 
// logs in.
// 
// key_size
// Length of key, in bytes. Must be zero if there is no key.
// 
// ad
// Additional data. May be NULL if ad_size is zero. This is additional data that 
// goes into the hash, similar to the authenticated encryption construction in 
//   crypto_aead_lock(). Can be used to differentiate inputs when invoking 
// several Argon2 instances in parallel: each instance gets a different thread 
// number as additional data, generating as many independent digests as we need.
// We can then hash those digests with crypto_blake2b().
// 
// ad_size
// Length of ad, in bytes. Must be zero if there is no additional data. 

// typedef struct {
//   const uint8_t *key;
//   const uint8_t *ad;
//   uint32_t key_size;
//   uint32_t ad_size;
// } crypto_argon2_extras;

#define SALTSIZE 16



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Internal argon2 function to wrap monocypher call
//
// @param password pointer to plain text
// @param pass_size strlen(password)
// @param salt 16-byte salt
// @param hash destination buffer for the calculated hash
// @param hash_length length of hash in bytes. Use 32 for key.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void argon_internal(uint8_t *password, size_t pass_size, uint8_t *salt, uint8_t *hash, uint32_t hash_length) {
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Argon2 Config
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_argon2_config config = {
    .algorithm = CRYPTO_ARGON2_ID,            /* Argon2i        */
    .nb_blocks = 100000,                     /* 100 megabytes   */
    .nb_passes = 3,                          /* 3 iterations    */
    .nb_lanes  = 1                           /* Single-threaded */
  };
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Argon2 Inputs
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_argon2_inputs inputs = {
    .pass      = (uint8_t *)password,  /* User password */
    .salt      = salt,                 /* Salt for the password */
    .pass_size = (uint32_t)pass_size, /* Password length */
    .salt_size = SALTSIZE
  };
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Argon2 Extras
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_argon2_extras extras = {0};   /* Extra parameters unused */
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Allocate work area.
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  void *work_area = malloc((size_t)config.nb_blocks * 1024);
  
  if (work_area == NULL) {
    error("argon2_(): Could not allocate memory for 'work_area'");
  } 
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Derive Key
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_argon2(hash, hash_length, work_area, config, inputs, extras);
  free(work_area);
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// R-callable function for deriving a key from a password
//
// @param password_ password
// @param salt_ 16 byte salt. Or hex string. Or shorter string to be expanded
// @param hash_length_ output key length
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP argon2_(SEXP password_, SEXP salt_, SEXP hash_length_, SEXP type_) {
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Password
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  const char *password = CHAR(STRING_ELT(password_, 0));
  size_t pass_size = (size_t)strlen(password);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Salt
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t salt[16] = { 0 };
  unpack_salt(salt_, salt);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Hash
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  size_t N = (size_t)asInteger(hash_length_);
  uint8_t *hash = (uint8_t *)calloc(N, 1);
  if (hash == NULL) {
    error("argon2_(): Couldn't allocate hash buffer");
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Derive key
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  argon_internal((uint8_t *)password, pass_size, salt, hash, (uint32_t)N);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Tidy and return
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  SEXP hash_ = PROTECT(wrap_bytes_for_return(hash, N, type_));
  free(hash);
  UNPROTECT(1);
  return hash_;
}

