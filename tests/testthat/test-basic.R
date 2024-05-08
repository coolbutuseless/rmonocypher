

test_that("stream encrypt/decrypt works", {
  
  dat <- as.raw(seq(10000) %% 255)
  key <- argon2('my secret', rcrypto(16))
  res <- encrypt_raw(dat, key) |> decrypt_raw(key)
  expect_identical(res, dat)
  
  
  dat <- as.raw(seq(1000000) %% 255)
  key <- argon2('my secret', rcrypto(16))
  res <- encrypt_raw(dat, key) |> decrypt_raw(key)
  expect_identical(res, dat)
  
})


test_that("stream encrypt/decrypt with textworks", {
  
  dat <- "hello"
  key <- argon2('my secret', rcrypto(16))
  res <- encrypt_raw(dat, key) |> decrypt_raw(key, type = 'string')
  expect_identical(res, dat)
  
  
  dat <- paste(sample(letters, 100000, T), collapse = "")
  key <- argon2('my secret', rcrypto(16))
  res <- encrypt_raw(dat, key) |> decrypt_raw(key, type = 'string')
  expect_identical(res, dat)
  
})



test_that("hex to key works", {
  
  dat <- as.raw(sample(1:255))
  key <- "82febb63ac2ab2a10193ee40ac711250965ed35dc1ce6a7e213145a6fa753230"
  tst <- encrypt_raw(dat, key) |> decrypt_raw(key)
  expect_identical(tst, dat)
  
})
