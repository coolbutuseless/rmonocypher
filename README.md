
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
- A secure source of random bytes generated from the operating system’s
  entropy sources
- Key sharing using *Shamir’s Secret Sharing*
- General-purpose cryptographic hashing using
  [‘blake2b’](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2)
  hash function

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
- `rcrypto()` is a cryptographic RNG for generating random bytes using
  the operating systems cryptographically secure pseudorandom number
  generator.
- `create_keyshares()` and `combine_keyshares()` for distributing key
  shares to a group using *Shamir’s Secret Sharing* algorithm
- `blake2b()` for hashing any R object
- `blake2b_raw()` for hashing raw bytes and strings directly

## Included Source Code

The package relies on the cryptographic algorithms supplied by
[`monocypher`](https://monocypher.org/)

- x25519 key exchange (Public Key Cryptography)
- RFC 8439 [‘Authenticated Encryption with Additional Data
  (AEAD)’](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD))
  i.e. ChaCha20-Poly1305 combining ChaCha20 stream cipher with Poly1305
  message authentication code.

Shamir’s Secret Sharing uses Daan Sprenkel’s
[sss](https://github.com/dsprenkels/sss) code.

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

    #> Error in readRDS(path): cannot read unreleased workspace version -1999629075 written by experimental R 6521.27.162

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

    #>  [1] ab 55 7f cd fd 11 cc d2 0f a7 0d 26 7c 52 f0 54 3d d4 c6 f9 fc cb 50 8b 0d
    #> [26] 00 00 00 00 00 00 00 f6 0b cc d1 41 de 84 7f 21 cd cc a3 c0 f8 9d 4e a0 77
    #> [51] 76 d7 b4 94 49 cf 3a ce bc ca 4c

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

# Random raw bytes from rcrypto()
key <- rcrypto(32)

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
# Use 'rcrypto()' to source 16 random bytes for the salt
argon2("my secret", salt = rcrypto(16))
```

    #> [1] "cc58bf4ca0e15d1649c94a0b0b6150e3ca602c4a936fcc2e1cb07c1c1a9d19e4"

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

## Shamir’s Secret Sharing

*Shamir’s Secret Sharing* algorithm allows a key to be split into
multiple parts (*keyshares*) and shared. When splitting the key, the
number (`k`) is specified to indicate how many keyshares are required to
reconstruct the key. Any individual *keyshare* cannot reveal the key.
See
[wikipedia](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing).

#### Application example (from wikipedia)

    A company needs to secure their vault. If a single person knows the 
    code to the vault, the code might be lost or unavailable when the 
    vault needs to be opened. If there are several people who know the 
    code, they may not trust each other to always act honestly.

    SSS can be used in this situation to generate shares of the vault's code
    which are distributed to authorized individuals in the company. The 
    minimum threshold and number of shares given to each individual can be 
    selected such that the vault is accessible only by (groups of) authorized 
    individuals. If fewer shares than the threshold are presented, the vault
    cannot be opened.

    By accident, coercion or as an act of opposition, some individuals might 
    present incorrect information for their shares. If the total of correct 
    shares fails to meet the minimum threshold, the vault remains locked.

``` r
orig_key <- "337ca9406391140208844c76b536c111f44531adef8d5cebcc68f83ab43cc745"
shares <- create_keyshares(orig_key, n = 6, k = 3)
shares
```

    #> [[1]]
    #> [1] "0132194cd30da2d410968fca6c6f1885898ecc699d0c9b16a8460ea31bd298f327"
    #> 
    #> [[2]]
    #> [1] "0235fd03f8ed94716d38253d4d3757e7dd8fdddc9c74e07149cc6e371f659cf7ab"
    #> 
    #> [[3]]
    #> [1] "033498e66b83a7b17fa62ebb57ed79a345f55484ac97f63b0a46086c3e0338c3c9"
    #> 
    #> [[4]]
    #> [1] "042f521109370c0beb34372d3c1e000323081c9f90c148d424f06182f77986dc2a"
    #> 
    #> [[5]]
    #> [1] "052e37f49a593fcbf9aa3cab26c42e47bb7295c7a0225e9e677a07d9d61f22e848"
    #> 
    #> [[6]]
    #> [1] "0629d3bbb1b9096e8404965c079c6125ef738472a15a25f986f0674dd2a826ecc4"

``` r
# Reassemble original key from any 3 keyshares
combine_keyshares(shares[c(1, 2, 3)])
```

    #> [1] "337ca9406391140208844c76b536c111f44531adef8d5cebcc68f83ab43cc745"

``` r
combine_keyshares(shares[c(6, 1, 4)])
```

    #> [1] "337ca9406391140208844c76b536c111f44531adef8d5cebcc68f83ab43cc745"

## Cryptographic Hash `blake2b()` and `blake2b_raw()`

    BLAKE2 is a cryptographic hash function based on BLAKE, created by 
    Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian 
    Winnerlein. The design goal was to replace the widely used, but broken, 
    MD5 and SHA-1 algorithms in applications requiring high performance in software

For more on why you might want a cryptographic hash vs a regular hash,
see [wikipedia article on cryptographic hash
functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function).

``` r
# Hash of any R object using R's serialization mechanism
blake2b(mtcars)
```

    #> [1] "c848f0df5ceeaa64f86d9e73a5e3d26dd6f9169f83e0ee499bba612df0aa2985"

``` r
# Hash of raw vectors and strings directly
blake2b_raw(as.raw(1:20))
```

    #> [1] "877a567036d56c98c42ea9a05d739b5537423d24411579286fd93816d5e296c7"

``` r
blake2b_raw("hello")
```

    #> [1] "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf"

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
    #>  [1] 4d 39 66 4b 08 b3 b5 c1 90 3e 60 a3 25 b3 92 01 17 08 76 86 f4 40 37 93 13
    #> [26] 00 00 00 00 00 00 00 f8 6f 46 e0 d0 25 5a 9c 3f dd f4 28 2e 6e 01 19 6e 3f
    #> [51] c3 38 1f 58 ad 48 a0 a6 23 e9 50 6c f0 c3 d5 0b 5a

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
- The nonce is created internally using random bytes from the
  cryptographic random number generator from the system this is running
  on.
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

Shamir’s Secret Sharing uses Daan Sprenkel’s
[sss](https://github.com/dsprenkels/sss) code.
