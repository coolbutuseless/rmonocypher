
<!-- README.md is generated from README.Rmd. Please edit that file -->

# Encryption for R Data

<!-- badges: start -->

![](https://img.shields.io/badge/cool-useless-green.svg)
![](https://img.shields.io/badge/dependencies-zero-blue.svg)
[![CRAN](https://www.r-pkg.org/badges/version/rmonocypher)](https://CRAN.R-project.org/package=rmonocypher)
[![R-CMD-check](https://github.com/coolbutuseless/rmonocypher/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/coolbutuseless/rmonocypher/actions/workflows/R-CMD-check.yaml)
<!-- badges: end -->

`{rmonocypher}` provides a simple, high-level interface for easily
encrypting R objects using a strong, modern cryptographic technique.

The key use-case this package addresses:

    I want to easily encrypt and save data to a public location 
    (e.g. shared drive, cloud drive, etc) which only I can decrypt.

## What’s in the box

- `decrypt()`/`encrypt()` read/write encrypted R objects to file
- `argon2()` derives encryption keys from passwords
- `rbyte()` generates secure random bytes using your operating system’s
  [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator).

#### Technical *bona fides*

- Cryptographic primitives are provided by the included
  [`monocypher`](https://monocypher.org/) library (v4.0.2)
- Encryption method is
  [XChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
  which combines ChaCha20 stream cipher (extended nonce variant) with
  Poly1305 message authentication.
- Encryption process follows RFC 8439 [‘Authenticated Encryption with
  Additional Data
  (AEAD)’](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD))
- Key derivation uses [Argon2 password-based key
  derviation](https://en.wikipedia.org/wiki/Argon2).
- All random bytes are sourced from [Cryptographically secure
  pseudo-random number generators
  (CSPRNG)](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator).

## Installation

This package can be installed from CRAN

``` r
install.packages('rmonocypher')
```

You can install the latest development version from
[GitHub](https://github.com/coolbutuseless/rmonocypher) with:

``` r
# install.package('remotes')
remotes::install_github('coolbutuseless/rmonocypher')
```

Pre-built source/binary versions can also be installed from
[R-universe](https://r-universe.dev)

``` r
install.packages('rmonocypher', repos = c('https://coolbutuseless.r-universe.dev', 'https://cloud.r-project.org'))
```

## Read/write data to an encrypted file

Encrypt any R object and save to file.

``` r
encrypt(mtcars, dst = "SharedDrive/mydata.dat", key = "mykey")
```

Then decrypt the object using the same key.

``` r
decrypt(src = "SharedDrive/mydata.dat", key = "mykey")
```

For more details on how passwords are used to derive encryption keys,
and for other ways of supplying and generating keys see the Vignette:
[Encryption
Keys](https://coolbutuseless.github.io/package/rmonocypher/articles/encryption-keys.html).

## Vignettes

- [Encryption
  Keys](https://coolbutuseless.github.io/package/rmonocypher/articles/encryption-keys.html)
  - Generating encryption keys from passwords with `argon2()`
  - Using random bytes as the encryption key
  - Using hexadecimal string as the encryption key
- [Technical
  Notes](https://coolbutuseless.github.io/package/rmonocypher/articles/technical-notes.html)
  - Background on the encryptiong techniques used
- [Using Additional
  Data](https://coolbutuseless.github.io/package/rmonocypher/articles/additional-data.html)
  - Advanced technique which is not needed for regular use of this
    package.
  - Details on using *additional data*
  - Worked example
