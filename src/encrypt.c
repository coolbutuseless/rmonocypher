
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
#include "isaac-r.h"


#define KEYSIZE   32
#define NONCESIZE 24
#define LENGTHSIZE sizeof(size_t)
#define MACSIZE   16



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Encrypt data
//
// @param x_ raw vector or string
// @param key_ 32 bytes.  Raw vector. Or hex string. Or password to feed to 
//        argon2()
// @param additional_data_ data used for message authentication, but not
//        encrypted or included with encrypted output
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP encrypt_(SEXP x_, SEXP key_, SEXP additional_data_) {
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Key
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t key[32];
  unpack_key(key_, key);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Plain Text
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t *plain_text = NULL;
  size_t payload_size = 0;
  
  if (TYPEOF(x_) == RAWSXP) {
    plain_text   = RAW(x_);
    payload_size = (size_t)xlength(x_);
  } else if (TYPEOF(x_) == STRSXP) {
    plain_text = (uint8_t *)CHAR(STRING_ELT(x_, 0));
    payload_size = (size_t)strlen(CHAR(STRING_ELT(x_, 0)));
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Nonce
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t nonce[NONCESIZE];
  fill_isaac(nonce, NONCESIZE);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Encryption Context
  // void crypto_aead_init_x(crypto_aead_ctx *ctx, const uint8_t key[32], const uint8_t nonce[24]);
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_aead_ctx ctx;
  crypto_aead_init_x(&ctx, key, nonce);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Initialise MAC
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t mac[MACSIZE] = { 0 };
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Cipher Text
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  size_t N = payload_size + NONCESIZE + MACSIZE + LENGTHSIZE;
  SEXP cipher_text_ = PROTECT(allocVector(RAWSXP, N));
  uint8_t *cipher_text = RAW(cipher_text_);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Additional data
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t *ad = NULL;
  size_t ad_len = 0;
  if (isNull(additional_data_)) {
    // Do nothing
  } else if (TYPEOF(additional_data_) == RAWSXP) {
    if (length(additional_data_) > 0) {
      ad = RAW(additional_data_);
      ad_len = (size_t)xlength(additional_data_); 
    } else {
      error("encrypt_(): 'additional_data' cannot be empty raw vector");
    }
  } else if (TYPEOF(additional_data_) == STRSXP) {
    const char *ad_string = CHAR(STRING_ELT(additional_data_, 0));
    if (strlen(ad_string) > 0) {
      ad = (uint8_t *)ad_string;
      ad_len = strlen(ad_string);
    } else {
      error("encrypt_(): 'additional_data' cannot be empty string");
    }
  } else {
    error("encrypt_(): 'additional_data' must be raw vector or string.");
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Encryption
  //   Leave room at start of buffer for nonce, payload size and mac
  // void
  // crypto_aead_write(
  //    crypto_aead_ctx *ctx, 
  //    uint8_t *cipher_text, 
  //    uint8_t mac[16], 
  //    const uint8_t *ad, size_t ad_size, 
  //    const uint8_t *plain_text, size_t text_size
  // );
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_aead_write(
    &ctx, 
    cipher_text + NONCESIZE + LENGTHSIZE + MACSIZE, 
    mac,
    ad, ad_len,
    plain_text, payload_size
  );
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Record nonce and mac at start of data
  // [nonce] [len, mac, data] [len, mac, data] 
  // where 'len' is the size of the encrypted data (not including 'len' or 'mac')
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  memcpy(cipher_text            ,                      nonce,  NONCESIZE);
  memcpy(cipher_text + NONCESIZE,              &payload_size, LENGTHSIZE);
  memcpy(cipher_text + NONCESIZE + LENGTHSIZE,           mac,    MACSIZE);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Tidy and return encrypted text
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_wipe(&ctx, sizeof(ctx));
  UNPROTECT(1);
  return cipher_text_;
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Decrypt data
//
// @param src_ raw vector containing encrypted data
// @param key_ 32 bytes.  Raw vector. Or hex string. Or password to feed to 
//        argon2()
// @param type_ 'raw' or 'string'?
// @param additional_data_ data used for message authentication, but not
//        encrypted or included with encrypted output
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP decrypt_(SEXP src_, SEXP key_, SEXP type_, SEXP additional_data_) {
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // return type is 'string' or 'raw'?
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  const char *type = CHAR(STRING_ELT(type_, 0));
  int as_string = strcmp(type, "string") == 0;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Position within cipher text
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  size_t pos = 0;
  size_t ntotal = (size_t)xlength(src_);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Cipher text
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t *cipher_text = RAW(src_);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // plaintext buffer for decrypted output
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t *plaintext = (uint8_t *)calloc(ntotal, 1);
  if (plaintext == NULL) {
    error("decrypt_(): Couldn't malloc output buffer");
  }
  size_t plaintext_pos = 0;
  size_t plaintext_size = ntotal;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Key
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t key[32];
  unpack_key(key_, key);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Nonce
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t nonce[NONCESIZE];
  memcpy(nonce, cipher_text + pos, NONCESIZE);
  pos += NONCESIZE;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // context
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_aead_ctx ctx;
  crypto_aead_init_x(&ctx, key, nonce);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // For this package, additional data only applies to first message in 
  // a stream of messages
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t *ad = NULL;
  size_t ad_len = 0;
  if (isNull(additional_data_)) {
    // Do nothing
  } else if (TYPEOF(additional_data_) == RAWSXP) {
    if (length(additional_data_) > 0) {
      ad = RAW(additional_data_);
      ad_len = (size_t)xlength(additional_data_); 
    } else {
      error("decrypt_(): 'additional_data' cannot be empty raw vector");
    }
  } else if (TYPEOF(additional_data_) == STRSXP) {
    const char *ad_string = CHAR(STRING_ELT(additional_data_, 0));
    if (strlen(ad_string) > 0) {
      ad = (uint8_t *)ad_string;
      ad_len = strlen(ad_string);
    } else {
      error("decrypt_(): 'additional_data' cannot be empty string");
    }
  } else {
    error("decrypt_(): 'additional_data' must be raw vector or string.");
  }
  
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Process frames until we're out of data
  // Encrypted data = [nonce] [frame] [frame] ... [frame]
  // [frame] = [payload length] [mac] [payload]
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  while (pos < ntotal) {
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // frameheader - get payload size for this frame
    //   payload size is just the encyprted data.  It does not include MAC
    //     or the bytes indicating the length.
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    size_t payload_size;
    memcpy(&payload_size, cipher_text + pos, LENGTHSIZE);
    pos += LENGTHSIZE;
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // frameheader - get MAC for this frame
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    uint8_t mac[MACSIZE];
    memcpy(mac, cipher_text + pos, MACSIZE);
    pos += MACSIZE;
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Sanity check: are there enough bytes to decrypt from?
    // This could happen if the 'payload_size' field is corrupted
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if (pos + payload_size > ntotal) {
      error("decrypt_(): Corrupt data? Recorded payload size exceeds data length: %zu + %zu > %zu", pos, payload_size, ntotal);
    }
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Sanity check: is there enough space in the plain_text buffer?
    // This shouldn't happen!  Decryption now sets up a buffer the 
    // full length of the input data, and therefore should never overflow.
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if (plaintext_pos + payload_size > plaintext_size) {
      error("decrypt_(): Attempt to write plaintext past end of buffer: %zu + %zu > %zu", plaintext_pos, payload_size, plaintext_size);
    }
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Decrypt stream
    // crypto_aead_read(
    //    crypto_aead_ctx *ctx, 
    //    uint8_t *plain_text, 
    //    const uint8_t mac[16], 
    //    const uint8_t *ad, size_t ad_size, 
    //    const uint8_t *cipher_text, 
    //    size_t text_size
    // );
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    int res = crypto_aead_read(
      &ctx, 
      plaintext + plaintext_pos, 
      mac,
      ad, ad_len,
      cipher_text + pos, payload_size
    );
    pos += payload_size;
    plaintext_pos += payload_size;
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Sanity check it went OK
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if (res < 0) {
      crypto_wipe(&ctx, sizeof(ctx));
      free(plaintext);
      error("decrypt_(): Decryption failed\n");
      return R_NilValue;
    } 
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Zero out any additional data after first frame
    //  i.e. additional frames in the data are not considered to have any
    //  additional data.
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    ad = NULL;
    ad_len = 0;
  }

  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Plaintext - copy raw bytes into an R vector
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  SEXP res_ = R_NilValue;
  
  if (as_string) {
    res_ = PROTECT(allocVector(STRSXP, 1));
    SET_STRING_ELT(res_, 0, mkChar((const char *)plaintext));
  } else {
    res_ = PROTECT(allocVector(RAWSXP, (R_xlen_t)plaintext_pos));
    memcpy(RAW(res_), plaintext, plaintext_pos);
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Tidy and return decrypted text
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_wipe(&ctx, sizeof(ctx));
  free(plaintext);
  UNPROTECT(1);
  return res_;
}


