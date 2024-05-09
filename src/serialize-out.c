
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

#define INITBUFSIZE 131072

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Serialization context
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
typedef struct {
  crypto_aead_ctx ctx;
  
  uint8_t nonce[NONCESIZE];
  uint8_t mac[MACSIZE];
  uint8_t key[KEYSIZE];
  
  FILE *fp;
  
  uint8_t *buf;
  size_t buf_pos;
  size_t buf_size;
  
  uint8_t *ad;
  size_t ad_len;
} serialize_buffer_t;



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Write a byte into the buffer at the current location.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void write_byte_to_stream(R_outpstream_t stream, int c) {
  error("write_byte_to_stream(): Not implemented");
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Write multiple bytes to file
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void write_bytes_to_stream(R_outpstream_t stream, void *src, int length) {
  serialize_buffer_t *cstate = (serialize_buffer_t *)stream->data;
  
  size_t nbytes = (size_t)length;
  
  if (cstate->buf_pos + nbytes > cstate->buf_size) {
    // Encrypt and write out the entirety of the current buffer
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Encrypt stream 
    //
    // void crypto_aead_write(
    //    crypto_aead_ctx *ctx, 
    //    uint8_t *cipher_text, 
    //    uint8_t mac[16], 
    //    const uint8_t *ad, size_t ad_size, 
    //    const uint8_t *plain_text, 
    //    size_t text_size
    // );
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    crypto_aead_write(
      &cstate->ctx,
      cstate->buf,
      cstate->mac,
      cstate->ad, cstate->ad_len,
      cstate->buf,
      cstate->buf_pos
    );
    
    if (cstate->ad != NULL) {
      // additional data is only applied to first frame
      cstate->ad = NULL;
      cstate->ad_len = 0;
    }
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Write frame
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    size_t bytes_written = 0;
    bytes_written += fwrite(&cstate->buf_pos   , 1  ,    LENGTHSIZE, cstate->fp);
    bytes_written += fwrite(cstate->mac        , 1,         MACSIZE, cstate->fp);
    bytes_written += (size_t)fwrite(cstate->buf, 1, cstate->buf_pos, cstate->fp);
    if (bytes_written != LENGTHSIZE + MACSIZE + cstate->buf_pos) {
      error("encrypt_stream_(): Write error - only wrote %zu/%zu bytes\n", bytes_written, LENGTHSIZE + MACSIZE + cstate->buf_pos);
    }
    cstate->buf_pos = 0;
  }
  
  
  if (nbytes > cstate->buf_size) {
    cstate->buf_size = nbytes * 2;
    cstate->buf = (uint8_t *)realloc(cstate->buf, cstate->buf_size);
    if (cstate->buf == NULL) {
      error("Couldn't realloc to size %zu", cstate->buf_size);
    }
    
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Encrypt data from src -> cstate->buf
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    crypto_aead_write(
      &cstate->ctx,
      cstate->buf,
      cstate->mac,
      cstate->ad, cstate->ad_len,
      src,
      nbytes
    );
    
    if (cstate->ad != NULL) {
      // additional data is only applied to first frame
      cstate->ad = NULL;
      cstate->ad_len = 0;
    }
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Write frame
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    size_t bytes_written = 0;
    bytes_written += fwrite(&nbytes            , 1, LENGTHSIZE, cstate->fp);
    bytes_written += fwrite(cstate->mac        , 1,    MACSIZE, cstate->fp);
    bytes_written += (size_t)fwrite(cstate->buf, 1,     nbytes, cstate->fp);
    if (bytes_written != LENGTHSIZE + MACSIZE + cstate->buf_pos) {
      error("encrypt_stream_(): Write error - only wrote %zu/%zu bytes\n", bytes_written, LENGTHSIZE + MACSIZE + nbytes);
    }
    cstate->buf_pos = 0;
  } else {
    memcpy(cstate->buf + cstate->buf_pos, src, nbytes);
    cstate->buf_pos += nbytes;
  }

  
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Serialize an R object to a buffer of fixed size and then compress
// the buffer using zstd
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP serialize_(SEXP robj, SEXP filename_, SEXP key_, SEXP additional_data_) {
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // serialization struct 
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  serialize_buffer_t cstate;
  memset(cstate.mac, 0, MACSIZE);
  cstate.buf = (uint8_t *)malloc(INITBUFSIZE);
  if (cstate.buf == NULL) {
    error("encrypt_stream(): Couldn't initialize buffer");
  }
  cstate.buf_pos = 0;
  cstate.buf_size = INITBUFSIZE;
  cstate.ad = NULL;
  cstate.ad_len = 0;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Open file
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  const char *filename = CHAR(STRING_ELT(filename_, 0));
  cstate.fp = fopen(filename, "wb");
  if (cstate.fp == NULL) {
    error("encrypt_stream(): Couldn't open file to write: '%s'", filename);
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Key
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  unpack_key(key_, cstate.key);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Select a random nonce
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  rcrypto(cstate.nonce, NONCESIZE);

  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Write nonce to file
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  size_t out = fwrite(cstate.nonce, 1, NONCESIZE, cstate.fp);
  if (out != NONCESIZE) {
    free(cstate.buf);
    error("encrypt_stream(): Couldn't write to file '%s'", filename);
  }
  
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
      error("serialize_(): 'additional_data' cannot be empty raw vector");
    }
  } else if (TYPEOF(additional_data_) == STRSXP) {
    const char *ad_string = CHAR(STRING_ELT(additional_data_, 0));
    if (strlen(ad_string) > 0) {
      cstate.ad = (uint8_t *)ad_string;
      cstate.ad_len = strlen(ad_string);
    } else {
      error("serialize_(): 'additional_data' cannot be empty string");
    }
  } else {
    error("serialize_(): 'additional_data' must be raw vector or string.");
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Setup the crypto state
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_aead_init_x(&cstate.ctx, cstate.key, cstate.nonce);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Setup the R serialization struct
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  struct R_outpstream_st output_stream;
  R_InitOutPStream(
    &output_stream,             // The stream object which wraps everything
    (R_pstream_data_t) &cstate, // The actual serialized data. R_pstream_data_t = void *
    R_pstream_binary_format,    // Store as binary
    3,                          // Version = 3 for R >3.5.0 See `?base::serialize`
    write_byte_to_stream,       // Function to write single byte to buffer
    write_bytes_to_stream,      // Function for writing multiple bytes to buffer
    NULL,                       // Func for special handling of reference data.
    R_NilValue                  // Data related to reference data handling
  );
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Serialize the object into the output_stream
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  R_Serialize(robj, &output_stream);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Flush buffer
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (cstate.buf_pos > 0) {
    crypto_aead_write(
      &cstate.ctx,
      cstate.buf,
      cstate.mac,
      cstate.ad, cstate.ad_len,
      cstate.buf,
      cstate.buf_pos
    );
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Write frame
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    size_t bytes_written = 0;
    bytes_written += fwrite(&cstate.buf_pos   , 1  ,   LENGTHSIZE, cstate.fp);
    bytes_written += fwrite(cstate.mac        , 1,        MACSIZE, cstate.fp);
    bytes_written += (size_t)fwrite(cstate.buf, 1, cstate.buf_pos, cstate.fp);
    if (bytes_written != LENGTHSIZE + MACSIZE + cstate.buf_pos) {
      error("encrypt_stream_(): Write error - only wrote %zu/%zu bytes\n", bytes_written, LENGTHSIZE + MACSIZE + cstate.buf_pos);
    }
    cstate.buf_pos = 0;
  }
  
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Tidy and return
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  fclose(cstate.fp);
  free(cstate.buf);
  crypto_wipe(cstate.key, sizeof(cstate.key));
  crypto_wipe(&cstate.ctx, sizeof(cstate.ctx));
  
  return R_NilValue;
}













































