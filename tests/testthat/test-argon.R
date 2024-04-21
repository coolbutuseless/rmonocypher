
test_that("argon2 works", {

  salt <- isaac(16)
  res1 <- argon2("my secret", salt = salt)
  res2 <- argon2("my secret", salt = salt)
  res3 <- argon2("my secret", salt = isaac(16))

  expect_true(is.raw(res1))
  expect_identical(res1, res2)
  expect_true(!identical(res1, res3))
    
})
