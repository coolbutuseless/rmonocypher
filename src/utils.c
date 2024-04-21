
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


#include "utils.h"
#include "argon2.h"

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Write raw bytes to screen
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void dump(SEXP key_, int n) {
  uint8_t *key = RAW(key_);
  for (int i = 0; i < n; i++) {
    Rprintf("%02x ", key[i]);
  }
  Rprintf("\n");
}

void dump_uint8(uint8_t *key, int n) {
  for (int i = 0; i < n; i++) {
    Rprintf("%02x ", key[i]);
  }
  Rprintf("\n");
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Fill a buffer with random bytes
// These should be cryptographically random bytes!  FIXME TODO
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void fill_rand(uint8_t *buf, int n) {
  GetRNGstate();
  for (int i = 0; i < n; i++) {
    buf[i] = (uint8_t)(round(unif_rand() * 255));
  }
  PutRNGstate();
} 

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Convert a hex digit to a nibble. Return -1 if not a hexdigits
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
static int8_t hexdigit(int digit) {
  if('0' <= digit && digit <= '9') return (int8_t)(     digit - '0');
  if('A' <= digit && digit <= 'F') return (int8_t)(10 + digit - 'A');
  if('a' <= digit && digit <= 'f') return (int8_t)(10 + digit - 'a');
  return -1;
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Convert a string to bytes.
// return 0  when conversion fails
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
int hexstring_to_bytes(const char *str, uint8_t *buf, int nbytes) {
  
  int n = (int)strlen(str);
  if (n != (2 * nbytes)) {
    return 0;
  }
  
  for (size_t i = 0, j = 0; i < nbytes; i++, j += 2) {
    int8_t nib1 = hexdigit(str[j    ]);
    int8_t nib2 = hexdigit(str[j + 1]);
    if (nib1 < 0 || nib2 < 0) {
      return 0;
    }
    buf[i] = (uint8_t)(nib1 << 4) + (uint8_t)nib2;
  }
  
  return 1;
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Unpack a user-supplied salt
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void unpack_salt(SEXP salt_, uint8_t salt[16]) {
  
  static uint8_t default_salt[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  
  if (TYPEOF(salt_) == RAWSXP) {
    if (length(salt_) >= 16) {
      memcpy(salt, RAW(salt_), 16);
    } else {
      error("argon2_(): 'salt' provided as a raw vector with length < %i", 16);
    }
  } else if (TYPEOF(salt_) == STRSXP) {
    const char *text = CHAR(STRING_ELT(salt_, 0));
    if (hexstring_to_bytes(text, salt, 16)) {
      // Success! Parsed hexstring to 16 bytes
    } else if (strlen(text) > 0) {
      // Derive 16-byte salt from this text
      argon_internal((uint8_t *)text, (size_t)strlen(text), default_salt, salt, 16);
    } else {
      error("argon2_(): if 'salt' is a string it must not be empty");
    }
  }
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Unpack a user-supplied key
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void unpack_key(SEXP key_, uint8_t key[32]) {

  if (isNull(key_)) {
    error("unpack_key(): Key must not be NULL");
  } else if (TYPEOF(key_) == RAWSXP) {
    if (length(key_) != 32) {
      error("unpack_key(): Expected 32 bytes in raw vector, not %i.\n", length(key_));
    }
    memcpy(key, RAW(key_), 32);
  } else if (TYPEOF(key_) == STRSXP) {
    const char *str = CHAR(STRING_ELT(key_, 0));
    unsigned long len = strlen(str);
    if (hexstring_to_bytes(str, key, 32)) {
      // Success! parsed the hex string to raw bytes
    } else if (len > 0) {
      // Use argon2 key derivation, with the key as its own salt.
      // Paranoia levels:
      //    Use random salt
      //    Use password as salt
      //    Use constant value as salt.
      uint8_t salt[16];
      unpack_salt(key_, salt);
      argon_internal((uint8_t *)str, len, salt, key, 32);
    } else {
      error("unpack_key(): zero-length string not allowed here");
    }
  } else {
    error("unpack_key(): Type of 'key' not understood");
  }
}



