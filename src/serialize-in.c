

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
#include "rcrypto.h"


#define KEYSIZE   32
#define NONCESIZE 24
#define LENGTHSIZE sizeof(size_t)
#define MACSIZE   16

#define INITBUFSIZE 131702

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Context for deserialization
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
typedef struct {
  crypto_aead_ctx ctx;
  uint8_t nonce[NONCESIZE];
  uint8_t mac[MACSIZE];
  uint8_t key[KEYSIZE];
  FILE *fp;

  uint8_t *buf;
  size_t buf_pos;
  size_t buf_size;
  size_t payload_size;
  
  uint8_t *ad;
  size_t ad_len;
} unserialize_buffer_t;



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Decrypt a frame from the file given the current cstate
//
// Prerequisites:
//   * file is open for reading
//   * cstate has been initialised
//
// @return Was a frame read?  
//      Hitting the end-of-file reading the frameheader returns '0'
//      If MAC or payload cannot be read, then a decryption error is thrown
//      '1' is returned at end of function to indicate a full frame was read.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
int decrypt_frame2(unserialize_buffer_t *cstate) {
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Check for end-of-file
  //   This may not trigger until a read is attmpted further below
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (feof(cstate->fp)) {
    return 0;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Read Frame Header:  payload size + mac
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  unsigned long bytes_read; 
  bytes_read = fread(&cstate->payload_size, 1, LENGTHSIZE, cstate->fp);

  if (bytes_read == 0) {
    return 0; // EOF
  }
  if (bytes_read != LENGTHSIZE) { 
    Rprintf("decrypt_frame2(): Possible End of file? EOF:%i\n", feof(cstate->fp));
    error("decrypt_frame2(): Rrror reading payload size (EOF: %i) %lu/%zu", feof(cstate->fp), bytes_read, LENGTHSIZE); 
  }
  
  bytes_read = fread(cstate->mac, 1, MACSIZE, cstate->fp);

  if (bytes_read != MACSIZE) { 
    error("decrypt_frame2(): Error reading MAC"); 
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Read payload for this frame
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (cstate->payload_size > cstate->buf_size) {
    cstate->buf_size = 2 * cstate->payload_size;
    cstate->buf = (uint8_t *)realloc(cstate->buf, cstate->buf_size);
  }
  
  bytes_read = fread(cstate->buf, 1, cstate->payload_size, cstate->fp);
  if (bytes_read != cstate->payload_size) { 
    error("decrypt_frame2(): Error reading payload %lu/%zu", bytes_read, cstate->payload_size); 
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Decrypt stream, in-place
  // 
  // crypto_aead_read(
  //     crypto_aead_ctx *ctx, 
  //     uint8_t *plain_text, 
  //     const uint8_t mac[16], 
  //     const uint8_t *ad, size_t ad_size, 
  //     const uint8_t *cipher_text, 
  //     size_t text_size
  // );
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  int res = crypto_aead_read(
    &cstate->ctx, 
    cstate->buf, 
    cstate->mac,
    cstate->ad, cstate->ad_len,
    cstate->buf, 
    cstate->payload_size
  );
  
  if (cstate->ad != NULL) {
    // additional data is only applied to first frame
    cstate->ad = NULL;
    cstate->ad_len = 0;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Was the message decrypted and authenticated?
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (res < 0) {
    error("decrypt_frame2(): Decryption failed");
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Reset buffer to start position
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  cstate->buf_pos = 0;
  
  return 1;
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Write a byte into the buffer at the current location.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
int read_byte_from_stream(R_inpstream_t stream) {
  error("read_byte_from_stream(): Reading single byte is unsupported\n");
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Write multiple bytes into the buffer at the current location.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void read_bytes_from_stream(R_inpstream_t stream, void *dst, int length) {
  unserialize_buffer_t *cstate = (unserialize_buffer_t *)stream->data;
  
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // If we're reach the end of the current decrypted data, then 
  // decrypt another frame
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (cstate->buf_pos >= cstate->payload_size) {
    int res = decrypt_frame2(cstate); 
    if (res == 0) {
      error("unserialize_(): end-of-file reached");
    }
  }
  
  memcpy(dst, cstate->buf + cstate->buf_pos, length);
  cstate->buf_pos += length;
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Unpack a raw vector to an R object
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP unserialize_(SEXP filename_, SEXP key_, SEXP additional_data_) {


  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // serialization struct 
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  unserialize_buffer_t cstate;
  memset(cstate.mac, 0, MACSIZE);
  cstate.buf = (uint8_t *)malloc(INITBUFSIZE);
  if (cstate.buf == NULL) {
    error("decrypt_stream(): Couldn't allocate buffer");
  }
  cstate.buf_pos = 0;
  cstate.buf_size = INITBUFSIZE;
  cstate.ad = NULL;
  cstate.ad_len = 0;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Open file
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  const char *filename = CHAR(STRING_ELT(filename_, 0));
  cstate.fp = fopen(filename, "rb");
  if (cstate.fp == NULL) {
    error("decrypt_stream(): Couldn't open file to write: '%s'", filename);
  }
  
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Read NONCE
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  unsigned long nread = fread(cstate.nonce, 1, NONCESIZE, cstate.fp);
  if (nread != NONCESIZE) {
    error("decrypt_stream(): coulnd't read from file '%s'", filename);
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Key
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  unpack_key(key_, cstate.key);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Setup the crypto state
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_aead_init_x(&cstate.ctx, cstate.key, cstate.nonce);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Additional data
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (isNull(additional_data_)) {
    // Do nothing
  } else if (TYPEOF(additional_data_) == RAWSXP) {
    if (length(additional_data_) > 0) {
      cstate.ad = RAW(additional_data_);
      cstate.ad_len = (size_t)xlength(additional_data_); 
    } else {
      error("unserialize_(): 'additional_data' cannot be empty raw vector");
    }
  } else if (TYPEOF(additional_data_) == STRSXP) {
    const char *ad_string = CHAR(STRING_ELT(additional_data_, 0));
    if (strlen(ad_string) > 0) {
      cstate.ad = (uint8_t *)ad_string;
      cstate.ad_len = strlen(ad_string);
    } else {
      error("unserialize_(): 'additional_data' cannot be empty string");
    }
  } else {
    error("unserialize_(): 'additional_data' must be raw vector or string.");
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Initial frame of data
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  decrypt_frame2(&cstate);
  
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Setup the R serialization struct
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  struct R_inpstream_st input_stream;
  R_InitInPStream(
    &input_stream,              // Stream object wrapping data buffer
    (R_pstream_data_t) &cstate, // Actual data buffer
    R_pstream_any_format,       // Unpack all serialized types
    read_byte_from_stream,      // Function to read single byte from buffer
    read_bytes_from_stream,     // Function for reading multiple bytes from buffer
    NULL,                       // Func for special handling of reference data.
    NULL                        // Data related to reference data handling
  );

  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Unserialize the input_stream into an R object
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  SEXP res_ = PROTECT(R_Unserialize(&input_stream));
  free(cstate.buf);
  UNPROTECT(1);
  return res_;
}



