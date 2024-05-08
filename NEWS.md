
# rmonocypher 0.1.7.9000 2024-05-08

* Enable `additional_data` argument for `encrypt()`/`decrypt()`

# rmonocypher 0.1.7  2024-05-08

* Remove `cryptfile()`
* Rename `encrypt()` to `encrypt_raw()`
* Rename `encrypt_obj()` to `encrypt()`

# rmonocypher 0.1.6  2024-05-07

* `encrypt()` to serialize encrypted objects to file

# rmonocypher 0.1.5  2024-05-07

* Add `blake2b()` for hashing any R object
* Add `blake2b_raw()` for hashing raw vectors and strings directly.

# rmonocypher 0.1.4  2024-05-03

* Include functions for Shamir's Secret Sharing
    * `create_keyshares(key, n, k)` to split a 32-bytes key into `n` pieces, 
       and recoverable with only `k` of them.
    * `combine_keyshares(shares)` to combine at least `k` shares in order 
      to recover the original key.

# rmonocypher 0.1.3  2024-04-26

* Update `cryptfile()` to read/write with **connections** as well as files.

# rmonocypher 0.1.2  2024-04-25

* Replace the ISAAC CSPRNG with the OS-provided, platform specific CSPRNG

# rmonocypher 0.1.1  2024-04-22

* Added x25519 key exchange functions `create_public_key()` and 
  `create_shared_key()`
* `argon2()` now returns a hex string by default.

# rmonocypher 0.1.0  2024-04-21

Initial release
