
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
- Read/write encrypted objects to file

## What’s in the box

- `encrypt_raw()` and `decrypt_raw()` are for encrypting and decrypting
  raw vectors and strings
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
- `encrypt()` and `decrypt()` for saving encrypted objects to file

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

## Save data to an encrypted file using a pass-phrase to access

- Data cannot be decrypted without the key
- Safe to save to shared folders

``` r
encrypt(mydata, filename = "SharedDrive/mydata.rds", key = "mykey")
decrypt(        filename = "SharedDrive/mydata.rds", key = "mykey")
```

## Create an encryption key from a pass-phrase

``` r
key <- argon2("horse battery stapler")
key
```

    #> [1] "2d465fc9f8e116425a3003c8e8edfeb490a14116099f0b3e78b830bb32e38da4"

## Save data to an encrypted file using an encryption key

``` r
# Create a key
key <- argon2("horse battery stapler")

encrypt(mydata, filename = "SharedDrive/mydata.rds", key = key)
decrypt(        filename = "SharedDrive/mydata.rds", key = key)
```

## Save data to an encrypted file using encryption key set in via `options()`

``` r
# Create a key and set via options() 
key <- argon2("horse battery stapler")
options(MONOCYPHER_KEY = key)


encrypt(mydata, filename = "SharedDrive/mydata.rds")
decrypt(        filename = "SharedDrive/mydata.rds")
```

## Create some truly random bytes

Using your OS built-in cryptographic pseudorandom number generator.

``` r
rcrypto(n = 16)
```

    #> [1] "fbe309fd006e83aca10b81941e803ad0"

``` r
rcrypto(n = 16, type = 'raw')
```

    #>  [1] cc 2e 53 11 c4 2b fa 09 1a 72 88 4f 63 4a 0e 0f

## Create a cryptographic hash of your data

``` r
blake2b(mtcars)
```

    #> [1] "c848f0df5ceeaa64f86d9e73a5e3d26dd6f9169f83e0ee499bba612df0aa2985"

## Securely exchange keys over insecure channels with public key encryption.

#### You: create a secret and public key

``` r
# You: Create a secret key and a public key.
your_secret <- argon2("hello")
your_public <- create_public_key(your_secret)
```

#### They: create a secret and public key

``` r
# They: Create a secret key and a public key
their_secret <- argon2("goodbye")
their_public <- create_public_key(their_secret)
```

#### Swap public keys

These can be swapped in the open (e.g. via email)

#### You: Create a shared key

``` r
# You: Use their public key and your secret key
#      to derive the common shared key
create_shared_key(their_public, your_secret)
```

    #> [1] "e944b1aad518537ab1a8e2194565b9fc9f75f7abdff3978872afb4d70575c9fa"

#### They: Create the same shared key

``` r
# They: Use your public key and their secret key
#       to derive the same shared key!
create_shared_key(your_public, their_secret)
```

    #> [1] "e944b1aad518537ab1a8e2194565b9fc9f75f7abdff3978872afb4d70575c9fa"

## Split an encryption key into `n` parts with only `k` keyshares needed to decode

``` r
key <- argon2("horse battery stapler")
key
```

    #> [1] "2d465fc9f8e116425a3003c8e8edfeb490a14116099f0b3e78b830bb32e38da4"

``` r
# Split the key into 6 keyshares. Any 3 keyshares can re-construct.
shares <- create_keyshares(key, n = 6, k = 3)
# Distribute these shares to your group
shares
```

    #> [[1]]
    #> [1] "013796fa1d0db1b5402e805223c913934cd1c4883e0b49e497f7d6bde07ffa5a6e"
    #> 
    #> [[2]]
    #> [1] "0204ecb090f9d5866d5a76f620584a03c85afb1e38562b0a1ff5a4222e6b636565"
    #> 
    #> [[3]]
    #> [1] "031e3c15440c85256f2ec6a7cb79b46e301b9ed71054fde5b67acaaf75267ab2af"
    #> 
    #> [[4]]
    #> [1] "040b4d54fe17ef34b0d748b59776a3832624638aa9c0e034c76fad5806a106291e"
    #> 
    #> [[5]]
    #> [1] "05119df12ae2bf97b2a3f8e47c575deede65064381c236db6ee0c3d55dec1ffed4"
    #> 
    #> [[6]]
    #> [1] "0622e7bba716dba49fd70e407fc6047e5aee39d5879f5435e6e2b14a93f886c1df"

``` r
# Any 3 members of the group can re-combine their keyshares to re-create the key
combine_keyshares(shares[c(6, 1, 4)])
```

    #> [1] "2d465fc9f8e116425a3003c8e8edfeb490a14116099f0b3e78b830bb32e38da4"

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
