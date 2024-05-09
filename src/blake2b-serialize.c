
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

typedef struct {
  bool in_header;
  int n;
  int enc_size;
  void *ctx;
} ser_state_t;


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Hash a byte
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void hash_byte(R_outpstream_t stream, int c) {
  error("blake2b::hash_byte(): Single byte hashing should never be called during binary serialisation");
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Hash multiple bytes
//
// Similar to rlang::hash(), we ignore the first 18+n bytes which are just
// the version-specific header for the data.
// The 'n' represents the length of the string used to specify the
// native encodeing.  This is often a 5 byte string "UTF-8"
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void hash_bytes(R_outpstream_t stream, void *src, int n) {
  ser_state_t *ser_state = (ser_state_t *)stream->data;
  
  if (ser_state->in_header) {
    ser_state->n += n;
    if (ser_state->n == 18) {
      memcpy(&ser_state->enc_size, src, sizeof(int));
    }
    if (ser_state->n == 18 + ser_state->enc_size) {
      ser_state->in_header = false;
    }
    return;
  }
  
  
  // void crypto_blake2b_update(crypto_blake2b_ctx *ctx, const uint8_t *message, size_t message_size);
  crypto_blake2b_ctx *ctx = (crypto_blake2b_ctx *)ser_state->ctx;
  crypto_blake2b_update(ctx, (uint8_t *)src, (size_t)n);
}




//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Serialize an R object
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP blake2b_(SEXP robj_, SEXP N_, SEXP type_) {

  if (asInteger(N_) < 1) {
    error("blake2b(): N must be >= 1, not %i", asInteger(N_));
  }
  size_t N = (size_t)asInteger(N_);
  
  ser_state_t ser_state = {
    .in_header = true,
    .n = 0,
    .ctx = NULL
  };

  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Set up the state
  // void crypto_blake2b_init(crypto_blake2b_ctx *ctx, size_t hash_size);
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_blake2b_ctx ctx;
  crypto_blake2b_init(&ctx, N);
  ser_state.ctx = &ctx;

  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Create the output stream structure
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  struct R_outpstream_st output_stream;

  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Initialise the output stream structure
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  R_InitOutPStream(
    &output_stream,             // The stream object which wraps everything
    (R_pstream_data_t) &ser_state, // The "location" to write to
    R_pstream_binary_format,    // Store as binary
    3,                          // Version = 3 for R >3.5.0 See `?base::serialize`
    hash_byte,                  // Function to write single byte to buffer
    hash_bytes,                 // Function for writing multiple bytes to buffer
    NULL,                       // Func for special handling of reference data.
    R_NilValue                  // Data related to reference data handling
  );

  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Serialize the object into the output_stream
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  R_Serialize(robj_, &output_stream);


  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Produce the final hash value
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~void
  // crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *hash);
  uint8_t *buf = (uint8_t *)R_alloc(N, 1);
  crypto_blake2b_final(&ctx, buf);
  
  return wrap_bytes_for_return(buf, N, type_);
}







