
<!-- README.md is generated from README.Rmd. Please edit that file -->

# `{rmonocypher}`: Easy-to-use encryption tools for R

<!-- badges: start -->

[![R-CMD-check](https://github.com/coolbutuseless/rmonocypher/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/coolbutuseless/rmonocypher/actions/workflows/R-CMD-check.yaml)
<!-- badges: end -->

`{rmonocypher}` provides easy-to-use tools for encrypting data in R.

These tools are backed by the [`monocypher`](https://monocypher.org/)
cryptographic library.

The key encryption technique in this package is
[XChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
which is the [extended
nonce](https://en.wikipedia.org/wiki/ChaCha20-Poly1305#XChaCha20-Poly1305_%E2%80%93_extended_nonce_variant)
variant of the ChaCha20-Poly1305 technique used in
[IPsec](https://en.wikipedia.org/wiki/IPsec),
[SSH](https://en.wikipedia.org/wiki/Secure_Shell) and
[Wireguard](https://en.wikipedia.org/wiki/WireGuard).

#### Features

- Simple reading/writing of encrypted data to file
- Generate encryption keys from easier-to-remember pass-phrases
- A secure source of random bytes generated from the operating system’s
  entropy sources
- General-purpose cryptographic hashing
- Key sharing using *Shamir’s Secret Sharing*
- Public Key Cryptography to negotiate a shared key over insecure
  channels

## What’s in the box

- `encrypt()` and `decrypt()` for reading/writing encrypted R objects to
  file
- `argon2()` derives encryption keys from pass-phrases
- `rcrypto()` generates random bytes using the operating system’ss
  cryptographically secure pseudo-random number generator.
- `blake2b()` for calculating a cryptographic hash of any R object
  - `blake2b_raw()` is a low-level variant for calculating
    cryptographics hashes for raw bytes and strings directly
- `create_public_key()` and `create_shared_key()` for performing key
  exchange over an insecure channel (i.e. Public Key Cryptography)
- `create_keyshares()` and `combine_keyshares()` for splitting an
  encryptiong key into `n` keyshares, but requiring only `k` keyshares
  to reconstruct (uses *Shamir’s Secret Sharing* algorithm)
- `encrypt_raw()` and `decrypt_raw()` are for low-level encryption of
  raw vectors and strings

## Installation

To install `rmonocypher` from
[GitHub](https://github.com/coolbutuseless/rmonocypher) with:

``` r
# install.packages("devtools")
devtools::install_github("coolbutuseless/rmonocypher")
```

## Save data to an encrypted file

- Data cannot be decrypted without the pass-phrase
- Safe to save to shared folders

``` r
encrypt(mydata, filename = "SharedDrive/mydata.rds", key = "mykey")
decrypt(        filename = "SharedDrive/mydata.rds", key = "mykey")
```

<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->
<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->
<details>
<summary style="font-size:large;">
Technical Notes (click to expand)
</summary>

- a pass-phrase key is transformed to 32-byte encryption key using
  `argon2()`
- the key may also be provided as a 32-byte raw vector, or a
  64-character hexadecimal string
- data is encrypted prior to writing to file
- `encrypt()` understands any data understood by `saveRDS()`
- Encryption follows RFC 8439 [‘Authenticated Encryption with Additional
  Data
  (AEAD)’](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD))
  i.e. ChaCha20-Poly1305 combining ChaCha20 stream cipher with Poly1305
  message authentication code.
- The 24-byte nonce is derived internally using 24 random bytes from
  `rcrypto()`

</details>
<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->
<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->
<details>
<summary style="font-size:large;">
Using a pre-generated encryption key (click to expand)
</summary>

``` r
# Create an encryption key from your secret pass-phrase
key <- argon2("horse battery stapler")

encrypt(mydata, filename = "SharedDrive/mydata.rds", key = key)
decrypt(        filename = "SharedDrive/mydata.rds", key = key)
```

</details>
<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->
<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->
<details>
<summary style="font-size:large;">
Using an encryption key set via `options()` (click to expand)
</summary>

``` r
# Create a key and set via options() 
key <- argon2("horse battery stapler")
options(MONOCYPHER_KEY = key)


encrypt(mydata, filename = "SharedDrive/mydata.rds")
decrypt(        filename = "SharedDrive/mydata.rds")
```

</details>
<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->
<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->

## Create an encryption key from a pass-phrase

``` r
key <- argon2("horse battery stapler")
key
```

    #> [1] "2d465fc9f8e116425a3003c8e8edfeb490a14116099f0b3e78b830bb32e38da4"

<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->
<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->
<details>
<summary style="font-size:large;">
Technical Notes (click to expand)
</summary>

Argon2 is a resource intensive password-based key derivation scheme.

Use `argon2()` to generate random bytes for keys from a pass-phrase. It
is recommended to further defend against attackers (who may be using
rainbow tables) by providing extra bytes of `salt`.

If no explicit `salt` is provided, a salt will be derived internally
from the pass-phrase. This is deterministic such that the same
pass-phase will always generate the same key. This is convenient, but
not as secure as using another pass-phrase for the `salt`. For maximum
strength, use a sequence of random bytes generated by `rcyprto()`

</details>
<details>
<summary style="font-size:large;">
Notes on Encryption Keys (click to expand)
</summary>

The encryption `key` is the core secret information that allows for
encrypting data.

The `key` for encryption may be one of:

- A 32-byte raw vector
- A 64-character hexadecimal string
- A pass-phrase

The `key` may be created by:

- Using random bytes from a cryptographically secure source
  e.g. `rcrypto()`
- Using Argon2 to derive random bytes from a pass-phrase i.e. `argon2()`
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

</details>
<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->
<!-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ -->
<details>
<summary style="font-size:large;">
Further Examples using ‘argon2()’ (click to expand)
</summary>

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

    #> [1] "36dc5ec0315e3cddaddf4d45f6a725ea8542c5b0354e77ddd13cd60aff866958"

</details>

## Generate cryptographically secure random bytes

These are possibly the best random bytes your OS provides.

``` r
rcrypto(n = 16)
```

    #> [1] "4115a022399712a17c7f62c683d36e59"

<details>
<summary style="font-size:large">
Technical Details
</summary>

This function generates bytes using your OS built-in cryptographic
pseudorandom number generator.

This random number generator is seeded by entropy gathered by your OS
such as:

- hardware noise
- timing jitter
- network timing
- mouse movements
- hard-drive event

This entropy is used to seed a cryptographically secure pseudorandom
number generator e.g. something based on ChaCha20.

Such a random number generator has important properties for
cryptographic purposes e.g.

- knowing the output does not allow you to infer the internal state
- knowing a large sequence of random bytes does not allow you to infer
  the next byte, or calculate prior bytes.

``` r
rcrypto(n = 16, type = 'raw')
```

    #>  [1] 63 83 bb f2 c2 0a 5a 7f 76 36 cb 19 12 57 21 21

</details>

## Calculate a cryptographic hash of your data

``` r
blake2b(mtcars)
```

    #> [1] "c848f0df5ceeaa64f86d9e73a5e3d26dd6f9169f83e0ee499bba612df0aa2985"

<details>
<summary style="font-size: large;">
Technical Notes
</summary>

    BLAKE2 is a cryptographic hash function based on BLAKE, created by 
    Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian 
    Winnerlein. The design goal was to replace the widely used, but broken, 
    MD5 and SHA-1 algorithms in applications requiring high performance in software

For more on why you might want a cryptographic hash vs a regular hash,
see [wikipedia article on cryptographic hash
functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function).
</details>

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

<details>
<summary style="font-size: large;">
Technical Notes
</summary>

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

</details>

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
    #> [1] "01cb12805186de41528cec6829f186d9473dce29bc89d0edc5750f9d7df32706b6"
    #> 
    #> [[2]]
    #> [1] "0285820ddfe7c19383446817bde84f0ca57ff71b7b7957860a14f82609569db3b4"
    #> 
    #> [[3]]
    #> [1] "0363d6d24799fec49392b47c5cf1242b56d29873d1f91860f1194f8bcf975938a6"
    #> 
    #> [[4]]
    #> [1] "04817e0a1167c2ab72f4410ea42079c70bdb1beb445e57791f63ec5b5023863d54"
    #> 
    #> [[5]]
    #> [1] "05672ad58919fdfc62229d65453912e0f8767483eede189fe46e5bf696e242b646"
    #> 
    #> [[6]]
    #> [1] "0629ba580778e22eb3ea191ad120db351a344db1292e9ff42b0fac4de247f80344"

``` r
# Any 3 members of the group can re-combine their keyshares to re-create the key
combine_keyshares(shares[c(6, 1, 4)])
```

    #> [1] "2d465fc9f8e116425a3003c8e8edfeb490a14116099f0b3e78b830bb32e38da4"

<details>
<summary style="font-size: large;">
Technical Notes
</summary>

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

</details>

# General Technical Notes

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

### Included Cryptographic Libraries

The package relies on the cryptographic algorithms supplied by
[`monocypher`](https://monocypher.org/)

- x25519 key exchange (Public Key Cryptography)
- RFC 8439 [‘Authenticated Encryption with Additional Data
  (AEAD)’](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD))
  i.e. ChaCha20-Poly1305 combining ChaCha20 stream cipher with Poly1305
  message authentication code.
- Argon2 password-based key derivation

Shamir’s Secret Sharing uses Daan Sprenkel’s
[sss](https://github.com/dsprenkels/sss) code.

### Decoding in other programs/languages

The encryption technique used through this package is the
XChaCha20-Poly1305 - this uses an extended 24-byte nonce.

This may be decoded by any program/language which implements this
technique i.e.

- The `standalone-decrypt.c` code included with this package
- The Rust Language
  `https://docs.rs/chacha20poly1305/latest/chacha20poly1305/`

C sourcecode for decoding outside of R is included in the installed
directory of this package in the file `standalone-decrypt.c`.

To find it, see the source tarball on CRAN or github, or when the
package is installed in R, find its location using

``` r
system.file("standalone-decrypt.c", package = 'rmonocypher', mustWork = TRUE)
```

This file must be compiled with the `monocypher.c/h` source files from
[`monocypher`](https://monocypher.org/)

    gcc -Wall standalone-decrypt.c monocypher.c -o decrypt
    ./decrypt [filename] [hexadecimal_key] [outfile]
