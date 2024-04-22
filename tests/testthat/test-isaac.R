
test_that("isaac works", {
  res <- isaac(32, type = 'raw')
  expect_length(res, 32)
  expect_true(is.raw(res))
  
  res <- isaac(32, type = 'string')
  expect_true(is.character(res))
  expect_true(nchar(res) == 64)
})
