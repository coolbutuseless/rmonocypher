
<!-- README.md is generated from README.Rmd. Please edit that file -->

# `{rmonocypher}`: simple encryption tools for R

<!-- badges: start -->

[![R-CMD-check](https://github.com/coolbutuseless/rmonocypher/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/coolbutuseless/rmonocypher/actions/workflows/R-CMD-check.yaml)
<!-- badges: end -->

`{rmonocypher}` provides easy-to-use tools for encrypting data in R,
based on the [`monocypher`](https://monocypher.org/) library.

The key features are:

- Seamless encryption with many R functions using a `connection`
- Easy encryption of data and strings
  - Using [‘Authenticated Encryption with Additional
    Data’](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD))
    (AEAD)
- Generate encryption keys from easier-to-remember pass-phrases
  - Using [‘Argon2’](https://en.wikipedia.org/wiki/Argon2) for
    password-based key derivation

# TODO before release

- Rename `rmonocypher` to `rmonocypher`
- Convert some docs to vignettes

## What’s in the box

- `cryptfile()` is a connection for reading/writing encrypted data.
  - This connection automatically encrypts/decrypts data to file and can
    be used in any function which supports connections e.g. `saveRDS()`,
    `write.csv()`, `png::writePNG()` etc
- `mc_encrypt()` and `mc_decrypt()` are for encrypting and decrypting
  raw vectors and strings
- `argon2()` derives random bytes (e.g. a `key`) from a pass-phrase
- `isaac()` is a cryptographic RNG for generating random bytes

## Installation

You can install the development version of rmonocypher from
[GitHub](https://github.com/coolbutuseless/rmonocypher) with:

``` r
# install.packages("devtools")
devtools::install_github("coolbutuseless/rmonocypher")
```

# Using the `cryptfile()` connection

Any function which supports reading/writing with a connection, now
supports automatic encryption/decrytion using the `cryptfile()`
connection in this package.

Many R functions support connections e.g. `read.csv()`, `saveRDS()`,
`serialize()`, `png::writePNG()`, and these can all seamlessly use the
`cryptfile()` connection.

The output can only be recovered using the same `key` which was used for
encryption.

``` r
robj <- head(mtcars)
path <- tempfile()
key  <- argon2("my secret")
saveRDS(robj, cryptfile(path, key))

readRDS(cryptfile(path, key))
```

    #>                    mpg cyl disp  hp drat    wt  qsec vs am gear carb
    #> Mazda RX4         21.0   6  160 110 3.90 2.620 16.46  0  1    4    4
    #> Mazda RX4 Wag     21.0   6  160 110 3.90 2.875 17.02  0  1    4    4
    #> Datsun 710        22.8   4  108  93 3.85 2.320 18.61  1  1    4    1
    #> Hornet 4 Drive    21.4   6  258 110 3.08 3.215 19.44  1  0    3    1
    #> Hornet Sportabout 18.7   8  360 175 3.15 3.440 17.02  0  0    3    2
    #> Valiant           18.1   6  225 105 2.76 3.460 20.22  1  0    3    1

Attempting to use an incorrect key will not work:

``` r
readRDS(cryptfile(path, "wrong key"))
```

    #> Error in readRDS(cryptfile(path, "wrong key")): decrypt_frame_(): Decryption failed

Attempting to read the file without decrypting it will not work:

``` r
readRDS(path)
```

    #> Error in readRDS(path): unknown input format

### More examples using `cryptfile()` connection

``` r
# Saving R objects
saveRDS(robj, cryptfile(path, key))
readRDS(cryptfile(path, key))

# CSV files
write.csv(iris, cryptfile(path, key))
read.csv(cryptfile(path, key))

# PNG files
png::writePNG(image, cryptfile(path, key))
png::readPNG(cryptfile(path, key))

# sink()
sink(cryptfile(path, key))
...
sink()

# Text
writeLines(my_diary, cryptfile(path, key))
readLines(cryptfile(path, key))

# cat()
cat(data, cryptfile(path, key))
```

# Simple encrypt/decrypt of raw data and strings

`mc_encrypt()` and `mc_decrypt()` are functions for directly encrypting
strings and raw vectors

``` r
library(rmonocypher)

# Plain text. Can be string or raw bytes
dat <- "Hello #RStats"

# Encrypt 
enc <- mc_encrypt(dat, key = "my secret")

# the encrypted data
enc
```

    #>  [1] 3e 46 2e dd 33 25 74 8b a4 a0 e3 a9 95 a7 78 f9 20 f8 fb 89 3b 29 60 68 0d
    #> [26] 00 00 00 00 00 00 00 cb d1 79 45 b7 54 0e 4f 2a 55 68 09 6b ef b7 58 c3 9d
    #> [51] 9d 22 dd 4e ba 00 ee 7a f7 a0 a3

``` r
# Decrypt using the same key
mc_decrypt(enc, key = "my secret", type = 'string')
```

    #> [1] "Hello #RStats"

# Encryption keys

The `key` for encryption may be one of:

- A 32-byte raw vector
- A 64-character hexadecimal string
- Any other length string is also acceptable. In this case, `argon2()`
  will be used to derive a 32-byte key from this text. Note: this method
  will use a default, fixed salt which will reduce the strength of this
  encryption when facing a skilled adversary.

The key may be set explicitly when the function is called, but can also
be set globally for the current session using
`options(MONOCYPHER_KEY = "...")`

Some valid keys for encryption are:

``` r
# Random raw bytes
key <- as.raw(sample(0:255, 32, TRUE))

# Random raw bytes from isaac()
key <- isaac(32)

# 64-character hexadecimal string
key <- "82febb63ac2ab2a10193ee40ac711250965ed35dc1ce6a7e213145a6fa753230"

# Output from argon2() using an explicit salt
key <- argon2("my secret", salt = "cefca6aafae5bdbc15977fd56ea7f1eb")

# Output from argon2() using an random bytes
key <- argon2("my secret", salt = isaac(16))
```

# Argon2: Password-based Key Derivation

Argon2 is a resource intensive password-based key derivation scheme.

Use `argon2()` to generate random bytes for keys from a pass-phrase.

``` r
# For the sake of convenience for novice users, a salt will be 
# derived internally from the pass-phrase.
argon2("my secret")
```

    #>  [1] bd 75 49 be f4 10 0b 88 8c 47 e4 21 b0 3c 52 fe e5 8b 28 5f cc 40 df a4 c0
    #> [26] 50 26 89 c4 ed 16 d0

``` r
# Calling 'argon2()' without a salt is equivalent to using the pass-phrase
# as the salt.  This is not the best security practice
argon2("my secret", salt = "my secret")
```

    #>  [1] bd 75 49 be f4 10 0b 88 8c 47 e4 21 b0 3c 52 fe e5 8b 28 5f cc 40 df a4 c0
    #> [26] 50 26 89 c4 ed 16 d0

``` r
# Best practice is to use your own random bytes for the salt
argon2("my secret", salt = as.raw(sample(0:255, 16, TRUE)))
```

    #>  [1] 36 8d 46 13 99 6f 6d 90 83 52 4b fa cf 97 21 17 fc 40 95 34 61 a2 48 b9 c5
    #> [26] 40 6a ee b7 b3 c9 3e

``` r
#Can also use 'isaac()' to source random bytes
argon2("my secret", salt = isaac(16))
```

    #>  [1] 44 2a 80 ec 73 5d 10 43 fc 22 32 2e 28 e8 7f 0c e9 08 89 0e 1b 39 f0 3b 2b
    #> [26] d6 66 98 31 a4 30 25

# Additional data

**Note:** This is an advanced topic, and not essential for regular use
of the encryption tools in this package.

This package uses [‘Authenticated Encryption with Additional Data
(AEAD)’](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD))
to encrypt messages.

Additional data (or ‘associated data’) may be included in the encryption
process. This additional data is part of the message authentication, but
not part of the encrypted message.

A common way additional data is used is for encrypted data which has an
unencrypted header containing meta-information. This header must be
readable before the message is decrypted, but also must not allow
tampering.

An example of the use of *additional data* is addressing an encrypted
message to a particular recipient.

The address on the envelope must be readable to allow delivery, but the
message inside needs to remain confidential.

In this case, the *address* is the *additional data* - it is sent with
the data, but not encrypted. Because the address forms part of the
message authentication, any modification of the address will prevent the
authentication of the encrypted payload.

**In the following example**, a message for Judy is encrypted, and the
address on the envelope is used as the *additional data*.

``` r
# Using additional data to encrypt a message
key      <- argon2("my secret key2")
message  <- 'Meet me in St Louis'
address  <- 'To: Judy'
enc      <- mc_encrypt(message, key, additional_data = address)

# Package the additional data and deliver to recipient
letter <- list(address = address, message = enc)
letter
```

    #> $address
    #> [1] "To: Judy"
    #> 
    #> $message
    #>  [1] 74 a1 d9 df 1b 7b bc 13 f6 e6 17 86 fc 9e 6b e9 12 73 c1 61 45 08 a1 b7 13
    #> [26] 00 00 00 00 00 00 00 27 d6 c0 15 6d 69 fd 62 e0 8f 65 77 d5 0a 47 05 49 c8
    #> [51] be 79 52 b9 6d ae b8 d4 24 52 e5 87 e0 ee 19 7a 83

``` r
# Recipient decodes message. 
# If envelope or contents are tampered with, message decryption will fail.
mc_decrypt(letter$message, key = key, type = 'string', additional_data = letter$address)
```

    #> [1] "Meet me in St Louis"

If a malicious third-party tampers with the address, then the message
cannot be authenticated. E.g. if the letter is altered as if it were
being sent to “Sandra”, then decryption will fail:

``` r
letter$address <- "To: Sandra"
mc_decrypt(letter$message, key = key, type = 'string', additional_data = letter$address)
```

    #> Error in mc_decrypt(letter$message, key = key, type = "string", additional_data = letter$address): mc_decrypt_(): Decryption failed

# Technical Notes

- The file structure is:
  - `[nonce] [frame] [frame] ... [frame]`
    - `[nonce]` = 24 bytes
    - A `[frame]` = `[payload size] [mac] [payload]`
      - `[payload size]` = 8 bytes
      - `[mac]` = 16 bytes
      - `[payload]` is `payload size` bytes
- The nonce is created internally using random bytes from the ISAAC
  random number generator
- There are no magic bytes pre-pended to the data to identify it as
  encrypted.
- In general when encrypting data using Authenticated Encryption:
  - these should be kept secret:
    - the original data (obviously!)
    - the encryption key.
  - these elements do not need to be kept secret:
    - MAC - message authentication code
    - Number of bytes
    - Nonce
    - Salt (if `argon2()` is being used to derive `key` from a
      pass-phrase)

#### Built-in libraries

This package uses the [monocypher](https://monocypher.org) encryption
library v4.0.2 to provide ‘authenticated encryption with additional
data’ (AEAD) and Argon2 password-based key derivation.

The cryptographic RNG is ISAAC. Code is in the public domain, and
available from the [Bob Jenkins’ (author)
homepage](https://burtleburtle.net/bob/rand/isaacafa.html).
