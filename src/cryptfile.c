
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


#include "monocypher.h"
#include "utils.h"
#include "rcrypto.h"



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// File format:
//
// Encrypted file = [nonce] [frame] [frame] ... [frame]
// [frame] = [payload size] [MAC] [payload]
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#define KEYSIZE   32
#define NONCESIZE 24
#define MACSIZE   16
#define LENGTHSIZE sizeof(size_t)

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// cryptfile state. 
//   - This is user/private data stored with the 'Rconn' struct that gets 
//     passed to each callback function
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
typedef struct {
  crypto_aead_ctx ctx;
  
  int is_file;
  FILE *fp; 
  Rconnection inner;
  
  int verbosity;
  
  uint8_t key[KEYSIZE];
  uint8_t mac[MACSIZE];
  uint8_t nonce[NONCESIZE];
  
  uint8_t *buf;
  size_t bufsize;
  size_t bufpos;
  
  char *linebuf;
  size_t linebufsize;
  
  size_t payload_size;
  
  // Additional data
  uint8_t *ad;
  size_t ad_len;
} cryptfile_state;


#define INITBUFSIZE 65536  

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
int decrypt_frame(cryptfile_state *cstate) {
  
  if (cstate->verbosity > 2) Rprintf("decrypt_frame-(feof = %i)\n", feof(cstate->fp));
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Check for end-of-file
  //   This may not trigger until a read is attmpted further below
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if ((cstate->is_file && feof(cstate->fp)) || (!cstate->is_file && cstate->inner->EOF_signalled)) {
    return 0;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Read Frame Header:  payload size + mac
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  unsigned long bytes_read; 
  if (cstate->is_file) {
    bytes_read = fread(&cstate->payload_size, 1, LENGTHSIZE, cstate->fp);
  } else {
    bytes_read = R_ReadConnection(cstate->inner, &cstate->payload_size, LENGTHSIZE);
  }
  if (bytes_read == 0) {
    return 0; // EOF
  }
  if (bytes_read != LENGTHSIZE) { 
    Rprintf("decrypt_frame(): Possible End of file? EOF:%i\n", feof(cstate->fp));
    error("decrypt_frame_(): Rrror reading payload size (EOF: %i) %lu/%zu", feof(cstate->fp), bytes_read, LENGTHSIZE); 
  }
  
  if (cstate->is_file) {
    bytes_read = fread(cstate->mac, 1, MACSIZE, cstate->fp);
  } else {
    bytes_read = R_ReadConnection(cstate->inner, cstate->mac, MACSIZE);
  }
  if (bytes_read != MACSIZE) { 
    error("decrypt_frame_(): Error reading MAC"); 
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Read payload for this frame
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (cstate->payload_size > cstate->bufsize) {
    cstate->bufsize = 2 * cstate->payload_size;
    cstate->buf = (uint8_t *)realloc(cstate->buf, cstate->bufsize);
  }
  
  if (cstate->is_file) {
    bytes_read = fread(cstate->buf, 1, cstate->payload_size, cstate->fp);
  } else {
    bytes_read = R_ReadConnection(cstate->inner, cstate->buf, cstate->payload_size);
  }
  if (bytes_read != cstate->payload_size) { 
    error("cryptfile_open(): Error reading payload %lu/%zu", bytes_read, cstate->payload_size); 
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
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Additional data only applies to first frame in a file.
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (cstate->ad != NULL) {
    cstate->ad     = NULL;
    cstate->ad_len = 0;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Was the message decrypted and authenticated?
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (res < 0) {
    error("decrypt_frame_(): Decryption failed");
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Reset buffer to start position
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  cstate->bufpos = 0;
  
  return 1;
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// open()
//  - this may be called explicitly by a user call to open(con, mode)
//  - this is also called implicitly by readBin()/writeBin()/readLines()/writeLines();
//
// Possible Modes
//    - "r" or "rt"    Open for reading in text mode.
//    - "w" or "wt"    Open for writing in text mode.
//    - "a" or "at"    Open for appending in text mode.
//    - "rb"           Open for reading in binary mode.
//    - "wb"           Open for writing in binary mode.
//    - "ab"           Open for appending in binary mode.
//    - "r+", "r+b"    Open for reading and writing.
//    - "w+", "w+b"    Open for reading and writing, truncating file initially.
//    - "a+", "a+b"    Open for reading and appending.
//
// Notes:
//   - Supported modes: r, rt, w, wt, rb, wb
//   - unsupported modes: append, simultaneous read/write
//
// @return Rboolean - true if connection successfully opened, false otherwise
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rboolean cryptfile_open(struct Rconn *rconn) {
  
  cryptfile_state *cstate = (cryptfile_state *)rconn->private;
  if (cstate->verbosity > 0) Rprintf("cryptfile_open('%s', mode = '%s')\n", 
      rconn->description, rconn->mode);
  
  if (rconn->isopen) {
    error("cryptfile(): Connection is already open. Cannot open twice");
  }
  
  if (strchr(rconn->mode, 'a') != NULL) {
    error("cryptfile() does not support append.");
  } else if (strchr(rconn->mode, '+') != NULL) {
    error("cryptfile() does not support simultaneous r/w.");
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Text mode?   Not used to drive anything in this device, as
  // we are always reading/writing binary data from file.
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  rconn->text   = strchr(rconn->mode, 'b') ? FALSE : TRUE;
  rconn->isopen = TRUE;
  
  if (strchr(rconn->mode, 'w') == NULL) {
    rconn->canread  =  TRUE;
    rconn->canwrite = FALSE;
  } else {
    rconn->canread  = FALSE;
    rconn->canwrite =  TRUE;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Setup buffer
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  cstate->buf       = (uint8_t *)calloc(INITBUFSIZE, 1);
  cstate->bufsize   = INITBUFSIZE;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Setup line buffer for text printing in 'cryptfile_vsprintf()'
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  cstate->linebuf = (char *)calloc(INITBUFSIZE, 1);
  cstate->linebufsize = INITBUFSIZE;
  cstate->bufpos = 0;
  
  
  if (rconn->canread) {
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Initialize 'cstate' for decryption
    //   open file in 'read' mode
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if (cstate->is_file) {
      cstate->fp = fopen(rconn->description, "rb");
      if (cstate->fp == NULL) error("cryptfile_open_(): Couldn't open file '%s'", rconn->description);
    } else {
      strcpy(cstate->inner->mode, "rb");
      int res = cstate->inner->open(cstate->inner);
      if (!res) {
        error("cryptfile_open(): Couldn't open inner connection for reading");
      }
    }
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Read Nonce from first bytes of file
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    unsigned long bytes_read;
    if (cstate->is_file) {
      bytes_read = fread(cstate->nonce, 1, NONCESIZE, cstate->fp);
    } else {
      bytes_read = R_ReadConnection(cstate->inner, cstate->nonce, NONCESIZE);
    }
    if (bytes_read != NONCESIZE) { error("cryptfile_open_(): error reading nonce"); }
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Initialize context
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    crypto_aead_init_x(&cstate->ctx, cstate->key, cstate->nonce);

    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Decrypt first frame
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    int got_frame = decrypt_frame(cstate);
    if (!got_frame) {
      error("cryptfile_open_(): Couldn't read initial frame");
    }
  } else {
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Initialize 'cstate' for encryption
    //   open file in 'write' mode
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if (cstate->is_file) {
      cstate->fp = fopen(rconn->description, "wb");
      if (cstate->fp == NULL) {
        error("cryptfile_open_(): Couldn't open input file '%s' with mode '%s'", rconn->description, rconn->mode);
      }
    } else {
      strcpy(cstate->inner->mode, "wb");
      int res = cstate->inner->open(cstate->inner);
      if (!res) {
        error("cryptfile_open(): Couldn't open inner connection for writing");
      }
    }
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Initialise 'mac' to 0
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    memset(cstate->mac, 0, MACSIZE);
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Select a random nonce and write to file
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    rcrypto(cstate->nonce, NONCESIZE);
    if (cstate->is_file) {
      fwrite(cstate->nonce, 1, NONCESIZE, cstate->fp);
    } else {
      R_WriteConnection(cstate->inner, cstate->nonce, NONCESIZE);
    }  
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Initialize context
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    crypto_aead_init_x(&cstate->ctx, cstate->key, cstate->nonce);
  }
  
  // We're open for business!
  return TRUE; 
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Encrypt buffer and write to file
// 
// If 'ciphertext' and 'plaintext' point to the same data, this will 
// encrypt in-place
//
// @param ciphertext pointer to destination buffer for encrypted data.
//        Must have capacity for 'payload_size' bytes
// @param plaintext pointer to source buffer for plaintext data.
//        Must have capacity for 'payload_size' bytes
// @param payload_size Number of bytes to encrypt
// @param cstate cryptfile state
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void encrypt_frame(uint8_t *ciphertext, uint8_t *plaintext, size_t payload_size, cryptfile_state *cstate) {
  
  if (cstate->verbosity > 2) Rprintf("encrypt_frame_(): %zu\n", payload_size);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Sanity check
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (payload_size == 0) {
    return;
  }
  
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
    ciphertext, 
    cstate->mac,
    cstate->ad, cstate->ad_len,
    plaintext, 
    payload_size
  );
  
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Additional data only applies to first frame in a file.
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (cstate->ad != NULL) {
    cstate->ad     = NULL;
    cstate->ad_len = 0;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Write frameheader
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  size_t bytes_written = 0;
  if (cstate->is_file) {
    bytes_written += fwrite(&payload_size, 1, LENGTHSIZE, cstate->fp);
    bytes_written += fwrite(cstate->mac  , 1,    MACSIZE, cstate->fp);
    bytes_written += (size_t)fwrite(ciphertext, 1, payload_size, cstate->fp);
  } else {
    bytes_written += R_WriteConnection(cstate->inner, &payload_size, LENGTHSIZE);
    bytes_written += R_WriteConnection(cstate->inner, cstate->mac  , MACSIZE);
    bytes_written += R_WriteConnection(cstate->inner, ciphertext, payload_size);
  }
  if (bytes_written != LENGTHSIZE + MACSIZE + payload_size) {
    error("encrypt_frame_(): Write error - only wrote %zu/%zu bytes\n", bytes_written, LENGTHSIZE + MACSIZE + payload_size);
  }
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Close()
//  - should only change state. No resources should be created/destroyed
//  - all actual destruction should happen in 'destroy()' which is called
//    by the garbage collector.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void cryptfile_close(struct Rconn *rconn) {
  
  cryptfile_state *cstate = (cryptfile_state *)rconn->private;
  if (cstate->verbosity > 0)Rprintf("cryptfile_close('%s')\n", rconn->description);
  
  rconn->isopen = FALSE;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Encrypt the remaining data and flush to file
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (rconn->canwrite) {
    encrypt_frame(cstate->buf, cstate->buf, cstate->bufpos, cstate);
    cstate->bufpos = 0;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Close the file
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (cstate->is_file && cstate->fp) {
    fclose(cstate->fp);
    cstate->fp = NULL;  
  } else if (!cstate->is_file) {
    cstate->inner->close(cstate->inner);
  }
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Destroy()
//   - R will destroy the Rbonn struct (?)
//   - R will destroy the Rconnection object (?)
//   - Only really have to take care of 'rconn->private' (?)
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void cryptfile_destroy(struct Rconn *rconn) {
  
  cryptfile_state *cstate = (cryptfile_state *)rconn->private;
  if (cstate->verbosity > 0) Rprintf("cryptfile_destroy()\n");
  
  crypto_wipe(cstate->key, sizeof(cstate->key));
  free(cstate->buf);
  free(cstate->linebuf);
  crypto_wipe(&cstate->ctx, sizeof(cstate->ctx));
  
  free(cstate); 
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// get a character from the connection
// This doesn't seem to be called for use cases I've tried.
// @return int - a character, or R_EOF
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
int cryptfile_fgetc_internal(struct Rconn *rconn) {
  
  cryptfile_state *cstate = (cryptfile_state *)rconn->private;
  if (cstate->verbosity > 0) Rprintf("cryptfile_fgetc_internal()\n");
  
  return rconn->fgetc(rconn);
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// seek()
//   - cryptfile() will not support seeking
// @param double - offset to seek relative to origin, apparently 
//        double is used here to avoid using 
//        integer types, i.e. long int, which is 
//        the prototype of the corresponding parameter 
//        in fseek, as defined in stdio.h
// @param int - the origin of seeking, 1 (and any except 2 and
//        3) if relative to the beginning of the 
//        connection, 2 if relative to the current 
//        connection read/write position, 3 if relative to 
//        the end of the connection
// @param int - currently only used by file_seek to select 
//        the read or write position when the offset is NA
// @return  double - the read/write position of the connection before 
//          seeking, negative on error double is again used to 
//          avoid integer types
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
double cryptfile_seek(struct Rconn *rconn, double x, int y, int z) {
  error("cryptfile_seek() - not supported");
  return 0;
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// truncate the connection at the current read/write position.
//   - cryptfile() will not support truncation
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void cryptfile_truncate(struct Rconn *rconn) {
  error("cryptfile_truncate() - not supported");
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// called when the connection should flush internal read/write buffers
//   - cryptfile will not suport flush()
//
// @return int zero on success. Non-zero otherwise
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
int cryptfile_fflush(struct Rconn *rconn) {
  error("cryptfile_fflush() - not supported\n");
  return 1;
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// cryptfile_read() is used by 'readBin()' and whenver binary data is
// being read.  E.g. 'readRDS()'
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
size_t cryptfile_read(void *dst, size_t size, size_t nitems, struct Rconn *rconn) {
  
  cryptfile_state *cstate = (cryptfile_state *)rconn->private;
  if (cstate->verbosity > 0) Rprintf("cryptfile_read(size = %zu, nitems = %zu)\n", size, nitems);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // We might not always return the same number of bytes as requested.
  // This happens at the end of file.
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  size_t len = size * nitems;
  size_t nread = 0;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // If 0 bytes left in buffer, read another frame
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  size_t bytes_left_in_buffer = cstate->payload_size - cstate->bufpos;
  
  if (bytes_left_in_buffer == 0) {
    int got_frame = decrypt_frame(cstate);
    if (!got_frame) {
      rconn->EOF_signalled = TRUE;
      return 0;
    }
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // While more bytes are still required
  //   copy data into 'dst' and read more frames
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  while (len > 0) {
    bytes_left_in_buffer = cstate->payload_size - cstate->bufpos;
    
    if (bytes_left_in_buffer >= len) {
      // Enough bytes to satisfy the 'len' required
      // Copy bytes into 'dst' and finish
      memcpy((uint8_t *)dst + nread, cstate->buf + cstate->bufpos, len);
      cstate->bufpos += len;
      nread          += len;
      len             = 0; 
    } else {
      // Not enough bytes in buffer to satisfy 'len'
      //  1. write the entire buf we have now
      //  2. read another frame
      memcpy((uint8_t *)dst + nread, cstate->buf + cstate->bufpos, bytes_left_in_buffer);
      cstate->bufpos += bytes_left_in_buffer;
      nread          += bytes_left_in_buffer;
      len            -= bytes_left_in_buffer;
      int got_frame = decrypt_frame(cstate);
      if (!got_frame) {
        rconn->EOF_signalled = TRUE;
        break;
      }
    }
  }
  
  return nread;
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// readLines()
//   - fgetc() called until '\n'. this counts as 1 line.
//   - when EOF reached, return -1
//
// This is used by 'readLines()'
//
// get a (re-encoded) character from the connection
// @return int - a (re-encoded) character, or R_EOF
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
int cryptfile_fgetc(struct Rconn *rconn) {
  
  cryptfile_state *cstate = (cryptfile_state *)rconn->private;
  if (cstate->verbosity > 1) Rprintf("cryptfile_fgetc()\n");

  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // IF there is no data in buffer, grab another frame
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  size_t bytes_left_in_buffer = cstate->payload_size - cstate->bufpos;
  
  if (bytes_left_in_buffer == 0) {
    int got_frame = decrypt_frame(cstate);
    if (!got_frame) {
      return -1; // EOF
    }
  }
  
  return cstate->buf[cstate->bufpos++];
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// cryptfile_write() is called for binary writing.  e.g. saveRDS(), writeBin()
//
// This write has to cope with lots of little writes. E.g. when serializing
// an object there are a lot of 4-byte writes.  We don't want to 
// output a frame for every single write because of the overhead with 
// writing the payload size and mac for the frameheader!
//
// So we have to deal with a buffered writer.
//
// Note: we don't own 'src', so definitely do NOT do in-place encryption.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
size_t cryptfile_write(const void *src, size_t size, size_t nitems, struct Rconn *rconn) {
  
  cryptfile_state *cstate = (cryptfile_state *)rconn->private;
  if (cstate->verbosity > 0) Rprintf("cryptfile_write(size = %zu, nitems = %zu)\n", size, nitems);
 
  size_t len = size * nitems;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // If new write to buffer would exceed bufsize, then encrypt buffer, write 
  // frome to file, and reset buffer
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (cstate->bufpos + len >= cstate->bufsize) {
    encrypt_frame(cstate->buf, cstate->buf, cstate->bufpos, cstate);
    cstate->bufpos = 0;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // If new write is larger than bufsize, 
  //     then encrypt directly, write frame to file
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (len > cstate->bufsize) {
    cstate->bufsize = len * 2; // over-malloc
    cstate->buf = (uint8_t *)realloc(cstate->buf, cstate->bufsize);
    encrypt_frame(cstate->buf, (uint8_t *)src, len, cstate);
  } else {
    memcpy(cstate->buf + cstate->bufpos, src, len);
    cstate->bufpos += len;
  }
  
  
  return len;
}



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Used in writeLines()
// @return int - number of characters printed, negative on failure
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
int cryptfile_vfprintf(struct Rconn *rconn, const char* fmt, va_list ap) {
  
  cryptfile_state *cstate = (cryptfile_state *)rconn->private;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // vsnprintf() return value:
  //   The number of characters written if successful or negative value if an 
  //   error occurred. If the resulting string gets truncated due to buf_size 
  //   limit, function returns the total number of characters (not including the 
  //   terminating null-byte) which would have been written, if the limit 
  //   was not imposed. 
  //
  // So when vsnprintf() overflows the given size, it returns the number of 
  // characters it couldn't write.  Tell it the buffer size is '0' and it
  // will just return how long a buffer would be needed to contain the string!
  //
  // Note: need to copy the 'va_list', since you can't (officially) use it twice!
  // ubuntu platform complains
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  va_list apc;
  va_copy(apc, ap);
  size_t slen = (size_t)vsnprintf(cstate->linebuf, 0, fmt, apc);
  va_end(apc);
  slen++;
  
  if (slen >= cstate->linebufsize) {
    cstate->linebufsize = 2 * slen; // over-allocate
    cstate->linebuf = (char *)realloc(cstate->linebuf, cstate->linebufsize);
  }

  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Actually create the string
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  slen = (size_t)vsnprintf(cstate->linebuf, slen, fmt, ap);
  if (slen < 0) {
    error("cryptfile_vfprintf(): error in 'vsnprintf()");
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // For output when verbosity >= 1
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  if (cstate->verbosity > 0) {
    unsigned char display_buf[40+1];
    strncpy((char *)display_buf, cstate->linebuf, 40);
    display_buf[40] = '\0';
    Rprintf("cryptfile_vfprintf('%s ...')\n", display_buf);
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Delegate to the binary 'write' method to actually add this data to the
  // buffer
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  rconn->write(cstate->linebuf, 1, slen, rconn); 
  
  return (int)slen;
}

  
  
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Initialize a cryptfile() R connection object to return to the user
//
// @param description_ filename
// @param key_ 32-byte raw vector. 64-character hex string. or character string
//        to use as input to 'argon2()'
// @param mode file mode r, rt, rb, w, wt, wb
// @param verbosity print messages during encryption? default: 0
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP cryptfile_(SEXP description_, SEXP key_, SEXP mode_, 
                SEXP additional_data_, SEXP verbosity_) {
  
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Create and Initialize User State
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  cryptfile_state *cstate = (cryptfile_state *)calloc(1, sizeof(cryptfile_state));
  if (cstate == NULL) {
    error("cryptfile_(): Couldn't allocate private data");
  }
  cstate->verbosity = asInteger(verbosity_);
  
  
  char *description;
  if (TYPEOF(description_) == STRSXP) {
    cstate->is_file = 1;
    description = (char *)CHAR(STRING_ELT(description_, 0));
  } else {
    cstate->is_file = 0;
    cstate->inner = R_GetConnection(description_);
    description = "cryptfile(connection)";
    if (cstate->inner->isopen) {
      error("cryptfile_(): Inner connection must not already be opened");
    }
  }
  
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Unpack the key into canonical 32-bytes uint8_t data
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  unpack_key(key_, cstate->key);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Additional data - 
  // if there is additional data, be sure to copy this across to the 'cstate'
  // as we cannot guarantee it will still exist when the time comes
  // to actually open the device.  The user might have deleted/chagned it
  // before then!
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  cstate->ad = NULL;
  cstate->ad_len = 0;
  if (isNull(additional_data_)) {
    // Do nothing
  } else if (TYPEOF(additional_data_) == RAWSXP) {
    if (length(additional_data_) > 0) {
      cstate->ad_len = (size_t)xlength(additional_data_); 
      cstate->ad = (uint8_t *)calloc(cstate->ad_len, 1);
      memcpy(cstate->ad, RAW(additional_data_), cstate->ad_len);
    } else {
      error("cryptfile_(): 'additional_data' cannot be empty raw vector");
    }
  } else if (TYPEOF(additional_data_) == STRSXP) {
    const char *ad_string = CHAR(STRING_ELT(additional_data_, 0));
    if (strlen(ad_string) > 0) {
      cstate->ad_len = strlen(ad_string);
      cstate->ad = (uint8_t *)calloc(cstate->ad_len, 1);
      memcpy(cstate->ad, (uint8_t *)ad_string, cstate->ad_len);
    } else {
      error("cryptfile_(): 'additional_data' cannot be empty string");
    }
  } else {
    error("cryptfile_(): 'additional_data' must be NULL, a raw vector or string.");
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // R will alloc for 'con' within R_new_custom_connection() and then
  // I think it takes responsibility for freeing it later.
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  Rconnection con = NULL;
  SEXP rc = PROTECT(R_new_custom_connection(description, "rb", "cryptfile", &con));
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // text       - true if connection operates on text
  // isopen     - true if connection is open
  // incomplete - used in @code{do_readLines}, @code{do_isincomplete}, 
  //              and text_vfprintf, From `?connections`: true if last 
  //              read was blocked, or for an output text connection whether 
  //              there is unflushed output
  // canread    - true if connection is readable
  // canwrite   - true if connection is writable
  // canseek    - true if connection is seekable
  // blocking   - true if connection reads are blocking
  // isGzcon    - true if connection operates on gzip compressed data 
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  con->isopen     = FALSE; // not open initially.
  con->incomplete =  TRUE; // NFI. Data write hasn't been completed?
  con->text       = FALSE; // binary connection by default
  con->canread    =  TRUE; // read-only for now
  con->canwrite   =  TRUE; // read-only for now
  con->canseek    = FALSE; // not possible in this implementation
  con->blocking   =  TRUE; // blacking IO
  con->isGzcon    = FALSE; // Not a gzcon
  
  // Not sure what this really means, but cryptfile() is not going to do 
  // any character conversion, so let's pretend any text returned in readLines()
  // is utf8.
  con->UTF8out =  TRUE; 
  con->private = cstate;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Callbacks
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  con->open           = cryptfile_open;
  con->close          = cryptfile_close;
  con->destroy        = cryptfile_destroy;
  con->vfprintf       = cryptfile_vfprintf;
  con->fgetc          = cryptfile_fgetc;
  con->fgetc_internal = cryptfile_fgetc_internal;
  con->seek           = cryptfile_seek;
  con->truncate       = cryptfile_truncate;
  con->fflush         = cryptfile_fflush;
  con->read           = cryptfile_read;
  con->write          = cryptfile_write;
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Auto open if 'mode' is set to something other than the empty string.
  // An issue is that without the context stuff (not exported from R?), 
  // I don't think I can get the context to auto-close!
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  const char *mode = CHAR(STRING_ELT(mode_, 0));
  strncpy(con->mode, mode, 4);
  con->mode[4] = '\0';
  if (strlen(mode) > 0) {
    con->open(con);
  }
  
  UNPROTECT(1);
  return rc;
}
