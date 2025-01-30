
#define R_NO_REMAP

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <R.h>
#include <Rinternals.h>
#include <Rdefines.h>

#include "monocypher.h"
#include "utils.h"
#include "argon2.h"
#include "rbyte.h"


#define KEYSIZE   32
#define NONCESIZE 24
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
  
  if (TYPEOF(x_) != RAWSXP) {
    Rf_error("'x' input must be a raw vector");
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Key
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t key[32];
  unpack_key(key_, key);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Plain Text
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t *plain_text = RAW(x_);
  size_t payload_size = (size_t)Rf_xlength(x_);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Nonce
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t nonce[NONCESIZE];
  rbyte(nonce, NONCESIZE);
  
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
  size_t N = payload_size + NONCESIZE + MACSIZE;
  SEXP cipher_text_ = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)N));
  uint8_t *cipher_text = RAW(cipher_text_);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Additional data
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t *ad = NULL;
  size_t ad_len = 0;
  if (Rf_isNull(additional_data_)) {
    // Do nothing
  } else if (TYPEOF(additional_data_) == RAWSXP) {
    if (Rf_length(additional_data_) > 0) {
      ad = RAW(additional_data_);
      ad_len = (size_t)Rf_xlength(additional_data_); 
    } else {
      Rf_error("encrypt_(): 'additional_data' cannot be empty raw vector");
    }
  } else if (TYPEOF(additional_data_) == STRSXP) {
    const char *ad_string = CHAR(STRING_ELT(additional_data_, 0));
    if (strlen(ad_string) > 0) {
      ad = (uint8_t *)ad_string;
      ad_len = strlen(ad_string);
    } else {
      Rf_error("encrypt_(): 'additional_data' cannot be empty string");
    }
  } else {
    Rf_error("encrypt_(): 'additional_data' must be raw vector or string.");
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
    cipher_text + NONCESIZE + MACSIZE, 
    mac,
    ad, ad_len,
    plain_text, payload_size
  );
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Record nonce and mac at start of data
  // [nonce] [len, mac, data] [len, mac, data] 
  // where 'len' is the size of the encrypted data (not including 'len' or 'mac')
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  memcpy(cipher_text            , nonce,  NONCESIZE);
  memcpy(cipher_text + NONCESIZE,   mac,    MACSIZE);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Tidy and return encrypted text
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_wipe(key, sizeof(key));
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
// @param type_ 'raw' or "chr"?
// @param additional_data_ data used for message authentication, but not
//        encrypted or included with encrypted output
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP decrypt_(SEXP src_, SEXP key_, SEXP additional_data_) {
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Position within cipher text
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  size_t ntotal = (size_t)Rf_xlength(src_);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Cipher text
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t *cipher_text = RAW(src_);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // frameheader - get payload size for this frame
  //   payload size is just the encyprted data.  It does not include MAC
  //     or the bytes indicating the length.
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  size_t payload_size = ntotal - NONCESIZE - MACSIZE;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // plaintext buffer for decrypted output
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  SEXP res_ = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)payload_size));
  uint8_t *plaintext = (uint8_t *)RAW(res_);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Key
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t key[32];
  unpack_key(key_, key);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Nonce
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t nonce[NONCESIZE];
  memcpy(nonce, cipher_text, NONCESIZE);
  cipher_text += NONCESIZE;
  
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
  if (Rf_isNull(additional_data_)) {
    // Do nothing
  } else if (TYPEOF(additional_data_) == RAWSXP) {
    if (Rf_length(additional_data_) > 0) {
      ad = RAW(additional_data_);
      ad_len = (size_t)Rf_xlength(additional_data_); 
    } else {
      Rf_error("decrypt_(): 'additional_data' cannot be empty raw vector");
    }
  } else if (TYPEOF(additional_data_) == STRSXP) {
    const char *ad_string = CHAR(STRING_ELT(additional_data_, 0));
    if (strlen(ad_string) > 0) {
      ad = (uint8_t *)ad_string;
      ad_len = strlen(ad_string);
    } else {
      Rf_error("decrypt_(): 'additional_data' cannot be empty string");
    }
  } else {
    Rf_error("decrypt_(): 'additional_data' must be raw vector or string.");
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // frameheader - get MAC
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  uint8_t mac[MACSIZE];
  memcpy(mac, cipher_text, MACSIZE);
  cipher_text += MACSIZE;

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
    plaintext, 
    mac,
    ad, ad_len,
    cipher_text, payload_size
  );
  
  crypto_wipe(key, sizeof(key));
  crypto_wipe(&ctx, sizeof(ctx));
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Sanity check it went OK
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (res < 0) {
    Rf_error("decrypt_(): Decryption failed\n");
  } 
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Tidy and return decrypted text
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  UNPROTECT(1);
  return res_;
}


