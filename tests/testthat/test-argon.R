
test_that("argon2 works", {

  salt <- rbyte(16)
  res1 <- argon2("my secret", type = 'raw', salt = salt)
  res2 <- argon2("my secret", type = 'raw', salt = salt)
  res3 <- argon2("my secret", type = 'raw', salt = rbyte(16))

  expect_true(is.raw(res1))
  expect_identical(res1, res2)
  expect_true(!identical(res1, res3))
    
})



test_that("argon2 works", {
  
  salt <- rbyte(16)
  res1 <- argon2("my secret", type = "chr", salt = salt)
  res2 <- argon2("my secret", type = "chr", salt = salt)
  res3 <- argon2("my secret", type = "chr", salt = rbyte(16))
  
  expect_true(is.character(res1))
  expect_identical(res1, res2)
  expect_true(!identical(res1, res3))
  
})
