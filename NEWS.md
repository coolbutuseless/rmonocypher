
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
