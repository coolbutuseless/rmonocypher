
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "monocypher.h"

#define KEYSIZE   32
#define NONCESIZE 24
#define LENGTHSIZE sizeof(size_t)
#define MACSIZE   16


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// This is C code for a stand-alone decryptor which works outside of R
//
// This can be used to decrypt any bytes created in the {rmonocypher} package
// (except when 'additional_data' is used.).  The full 32-byte key must 
// be known and presented as a hexadecimal string (64-characters)
// 
// * Copy 'monocypher.c/h' from the monocypher library into this directory
// * Compile:  gcc -Wall standalone-decrypt.c monocypher.c -o decrypt
// * Decrypt: ./decrypt [filename] [hexadecimal_key] [outfile]
//
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~







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
// Compile:  gcc -Wall decrypt.c monocypher.c -o decrypt
// Decrypt: ./decrypt [filename] [hexadecimal_key] [outfile]
//             Will write decoded bytes to outfile
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
int main(int argc, char **argv) {
  
  int retval = -1; // return value. -1 by default.
  
  size_t total = 0;         // keep track of number of decoded bytes
  size_t nframes = 0;       // keep track of number of frames of data decoded
  uint8_t key[32];          // Decryption key
  uint8_t nonce[NONCESIZE]; // nonce. Read from file.
  crypto_aead_ctx ctx;      // Decryption context (monocypher)
  
  FILE *fp = NULL;     // input file
  FILE *out = NULL;    // output file
  uint8_t *buf = NULL; // buffer used to read data and decrypt in-place
  
  if (argc != 4) {
    printf("./decrypt [filename] [hexadecimal_key] [output_filename]\n");
    return -1;
  }
  
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Unpack hexadecimal string to 32-byte key
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  const char *hexkey = argv[2];
  int res = hexstring_to_bytes(hexkey, key, 32);
  if (res == 0) {
    printf("Failed to convert hex key to bytes\n");
    return -1;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Output filename
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  const char *output_filename = (const char *)argv[3];
  out = fopen(output_filename, "wb");
  if (out == NULL) {
    printf("Couldn't open file for output: '%s'\n", output_filename);
    goto error;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Open file
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  const char *filename = (const char *)argv[1];
  fp = fopen(filename, "rb");
  if (fp == NULL) {
    printf("Couldn't open file for input: '%s'\n", filename);
    goto error;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // TODO: Read magic bytes and version header
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Read NONCE
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  unsigned long bytes_read = fread(nonce, 1, NONCESIZE, fp);
  if (bytes_read != NONCESIZE) {
    printf("Error reading nonce\n");
    goto error;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // context
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  crypto_aead_init_x(&ctx, key, nonce);
  
  while (!feof(fp)) {
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Read payload size
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    size_t payload_size = 0;
    bytes_read = fread(&payload_size, 1, LENGTHSIZE, fp);
    if (bytes_read == 0 && feof(fp)) {
      goto success;
    }
    if (bytes_read != LENGTHSIZE) {
      printf("Error reading payload size\n");
      goto error;
    }
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Read MAC
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    uint8_t mac[MACSIZE];
    bytes_read = fread(mac, 1, MACSIZE, fp);
    if (bytes_read != MACSIZE) {
      printf("Error reading mac size\n");
      goto error;
    }
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Read payload
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    buf = (uint8_t *)malloc(payload_size);
    if (buf == NULL) {
      printf("Couldn't allocate buffer of size %zu\n", payload_size);
      goto error;
    }
    bytes_read = fread(buf, 1, payload_size, fp);
    if (bytes_read != payload_size) {
      printf("Couldn't read entire payload\n");
      goto error;
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
    int decrypt_status = crypto_aead_read(
      &ctx, 
      buf, 
      mac,
      NULL, 0,
      buf,
      payload_size
    );
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Sanity check it went OK
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if (decrypt_status < 0) {
      printf("Decryption failed at frame %zu\n", nframes);
      goto error;
    } 
    
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Write decoded bytes to file
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    unsigned long bytes_written = fwrite(buf, 1, payload_size, out);
    if (bytes_written != payload_size) {
      printf("Couldn't write decrypted data to file  %lu/%zu\n", bytes_written, payload_size);
      goto error;
    }
    nframes++;
    total += payload_size;
    free(buf);
    buf = NULL;
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Exit pathway for success
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  success:
  retval = 0;
  printf("Decoded %zu bytes from %zu frames\n", total, nframes);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Exit pathway if not success
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  error:
  crypto_wipe(key, sizeof(key));
  crypto_wipe(&ctx, sizeof(ctx));
  if (buf) crypto_wipe(buf, sizeof(buf));
  if (buf) free(buf);
  if (out) fclose(out);
  if (fp) fclose(fp);
  return retval;  
}

