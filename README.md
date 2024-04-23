
<!-- README.md is generated from README.Rmd. Please edit that file -->

# `{rmonocypher}`: simple encryption tools for R

<!-- badges: start -->

[![R-CMD-check](https://github.com/coolbutuseless/rmonocypher/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/coolbutuseless/rmonocypher/actions/workflows/R-CMD-check.yaml)
<!-- badges: end -->

`{rmonocypher}` provides easy-to-use tools for encrypting data in R,
based on the [`monocypher`](https://monocypher.org/) library.

#### Features

- Seamless encryption with many R functions using a `connection`
- Easy encryption of data and strings
  - Using [‘Authenticated Encryption with Additional
    Data’](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD))
    (AEAD)
- Generate encryption keys from easier-to-remember pass-phrases
  - Using [‘Argon2’](https://en.wikipedia.org/wiki/Argon2) for
    password-based key derivation

#### Motivating example

Use `{rmonocypher}` to write R data to an encrypted file on a shared
drive, dropbox or cloud.

The data is not readable by others, but easily recoverable if the `key`
is known.

``` r
saveRDS(results, cryptfile("ShareDrive/results.rds", key = "#RsTaTs123!"))

readRDS(cryptfile("ShareDrive/results.rds", key = "#RsTaTs123!"))
```

## What’s in the box

- `cryptfile()` is a connection for reading/writing encrypted data.
  - This connection automatically encrypts/decrypts data to file and can
    be used in any function which supports connections e.g. `saveRDS()`,
    `write.csv()`, `png::writePNG()` etc
- `encrypt()` and `decrypt()` are for encrypting and decrypting raw
  vectors and strings
- `argon2()` derives encryption keys from pass-phrases
- `create_public_key()` and `create_shared_key()` can be used to perform
  key exchange over an insecure channel (i.e. Public Key Cryptography)
- `isaac()` is a cryptographic RNG for generating random bytes

## \`monocypher’

The package relies on the cryptographic algorithms supplied by
[`monocypher`](https://monocypher.org/)

- x25519 key exchange (Public Key Cryptography)
- RFC 8439 [‘Authenticated Encryption with Additional Data
  (AEAD)’](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD))
  i.e. ChaCha20-Poly1305 combining ChaCha20 stream cipher with Poly1305
  message authentication code.

## Installation

To install `rmonocypher` from
[GitHub](https://github.com/coolbutuseless/rmonocypher) with:

``` r
# install.packages("devtools")
devtools::install_github("coolbutuseless/rmonocypher")
```

# Using the `cryptfile()` connection

Any function which supports reading/writing with a connection, now
supports automatic encryption/decryption using the `cryptfile()`
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

`encrypt()` and `decrypt()` are functions for directly encrypting
strings and raw vectors

``` r
library(rmonocypher)

# Plain text. Can be string or raw bytes
dat <- "Hello #RStats"

# Encrypt 
enc <- encrypt(dat, key = "my secret")

# the encrypted data
enc
```

    #>  [1] 3e 46 2e dd 33 25 74 8b a4 a0 e3 a9 95 a7 78 f9 20 f8 fb 89 3b 29 60 68 0d
    #> [26] 00 00 00 00 00 00 00 cb d1 79 45 b7 54 0e 4f 2a 55 68 09 6b ef b7 58 c3 9d
    #> [51] 9d 22 dd 4e ba 00 ee 7a f7 a0 a3

``` r
# Decrypt using the same key
decrypt(enc, key = "my secret", type = 'string')
```

    #> [1] "Hello #RStats"

# Encryption keys

The encryption `key` is the core secret information that allows for
encrypting data.

The `key` for encryption may be one of:

- A 32-byte raw vector
- A 64-character hexadecimal string
- A pass-phrase

The `key` may be created by:

- Using random bytes from a cryptographically secure source
- Using Argon2 to derive random bytes from a pass-phrase
- Creating a shared key through key exchange with another person

When calling functions in `{rmonocypher}`, the key may be set explicitly
when the function is called, but can also be set globally for the
current session using `options(MONOCYPHER_KEY = "...")`

## Using random bytes as a key

``` r
# Random raw bytes
key <- as.raw(sample(0:255, 32, TRUE))

# Random raw bytes from isaac()
key <- isaac(32)

# 64-character hexadecimal string
key <- "82febb63ac2ab2a10193ee40ac711250965ed35dc1ce6a7e213145a6fa753230"
```

## Argon2: Password-based Key Derivation

Argon2 is a resource intensive password-based key derivation scheme.

Use `argon2()` to generate random bytes for keys from a pass-phrase. It
is recommended to further defend against attackers using rainbow tables
by providing extra bytes of `salt`.

If no explicit `salt` is provided, a salt will be derived internally
from the pass-phrase. This is deterministic such that the same
pass-phase will always generate the same key. This is convenient, but
not as secure as using another pass-phrase or random bytes for the
`salt`.

``` r
# When no salt is provided, a salt will be 
# derived internally from the pass-phrase.  This is convenient, but 
# not as secure as using random bytes.
argon2("my secret")
```

    #> [1] "bd7549bef4100b888c47e421b03c52fee58b285fcc40dfa4c0502689c4ed16d0"

``` r
# Use text as the salt
argon2("my secret", salt = "salt and vinegar")
```

    #> [1] "16df2856ba2ecc020ff506831a691b1d92616948197fb74fa651bfc89cad65e4"

``` r
# Use a 32-character hexadecimal string as the salt
argon2("my secret", salt = "cefca6aafae5bdbc15977fd56ea7f1eb")
```

    #> [1] "2216b700af05984f21d7465487f21de0096f7aaa164d2b56c54803e3891ec071"

``` r
# Use 16-bytes of random data for the salt
argon2("my secret", salt = as.raw(sample(0:255, 16, TRUE)))
```

    #> [1] "368d4613996f6d9083524bfacf972117fc40953461a248b9c5406aeeb7b3c93e"

``` r
# Use 'isaac()' to source 16 random bytes for the salt
argon2("my secret", salt = isaac(16))
```

    #> [1] "442a80ec735d1043fc22322e28e87f0ce908890e1b39f03b2bd6669831a43025"

## Securely exchange keys over insecure channels with public key encryption.

**Note:** This is an advanced topic, and not essential for regular use
of encryption when only you are accessing data, or you have a secure way
to share the key with others.

`{rmonocypher}` implement public-key cryptography using x25519. X25519
is an elliptic curve Diffie-Hellman key exchange using Curve25519. It
allows two parties to jointly agree on a shared secret using an insecure
channel.

Steps:

1.  Both users create a secret key (these are never shared!)
2.  Both users derive the public key from their secret key
3.  Users swap their public keys. These do not need to be kept secure.
4.  Both users use their secret key in conjunction with the other user’s
    public key to derive **the exact same key** !
5.  Now both users know the same shared key and can encrypt and decrypt
    messages from each other.

``` r
# You: Create a secret key and a public key.
# You: Share the public key with other party
your_secret <- argon2("hello")
your_public <- create_public_key(your_secret)

# They: Create a secret key and a public key
# They: Share their public key with you
their_secret <- argon2("goodbye")
their_public <- create_public_key(their_secret)

# You: Use their public key and your secret key
#      to derive the common shared key
create_shared_key(their_public, your_secret)
```

    #> [1] "e944b1aad518537ab1a8e2194565b9fc9f75f7abdff3978872afb4d70575c9fa"

``` r
# They: Use your public key and their secret key
#       to derive the same shared key!
create_shared_key(your_public, their_secret)
```

    #> [1] "e944b1aad518537ab1a8e2194565b9fc9f75f7abdff3978872afb4d70575c9fa"

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
enc      <- encrypt(message, key, additional_data = address)

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
# Recipient decodes message, and the 'address' forms part of the decryption.
decrypt(letter$message, key = key, type = 'string', additional_data = letter$address)
```

    #> [1] "Meet me in St Louis"

If a malicious third-party tampers with the address, then the message
cannot be authenticated. E.g. if the letter is altered as if it were
being sent to “Sandra”, then decryption will fail:

``` r
letter$address <- "To: Sandra"
decrypt(letter$message, key = key, type = 'string', additional_data = letter$address)
```

    #> Error in decrypt(letter$message, key = key, type = "string", additional_data = letter$address): decrypt_(): Decryption failed

# Technical Notes

- The nonce used within ‘monocypher’ is 24-bytes (192 bits). This is
  large enough that counter/ratcheting mechanisms do not need to be
  used, and random bytes are unlikely to generate the same nonce twice
  in any reasonable timeframe.
- The nonce is created internally using random bytes from the ISAAC
  random number generator.  
- There are no magic bytes pre-pended to the data to identify it as
  encrypted, but the `payload size` field in the file structure is
  easily identifiable (see below).
- In general when encrypting data using Authenticated Encryption:
  - these should be kept secret:
    - the original data (obviously!)
    - the encryption key.
  - these elements do not need to be kept secret:
    - MAC - message authentication code
    - Number of bytes of data
    - Nonce
    - Salt (if `argon2()` is being used to derive `key` from a
      pass-phrase)

### File structure

The file structure for encrypted data created by this package is
documented here.

The file must hold multiple chunks of streaming encrypted data, each
chunk has a header giving the number of encrypted bytes (payload size)
and a MAC (Message Authentication Code). The `nonce` is stored once at
the beginning of the file.

- `[nonce] [frame] [frame] ... [frame]`
  - `[nonce]` = 24 bytes
  - `[frame]` = `[payload size] [mac] [payload]`
    - `[payload size]` = 8 bytes
    - `[mac]` = 16 bytes
    - `[payload]` is a sequence of `payload size` bytes

### Built-in libraries

This package uses the [monocypher](https://monocypher.org) encryption
library v4.0.2 to provide ‘authenticated encryption with additional
data’ (AEAD) and Argon2 password-based key derivation.

The cryptographic RNG is ISAAC. Code is in the public domain, and
available from the [Bob Jenkins’ (author)
homepage](https://burtleburtle.net/bob/rand/isaacafa.html).
