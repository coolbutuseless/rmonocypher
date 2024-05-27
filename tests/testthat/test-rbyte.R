
test_that("rbyte works", {
  res <- rbyte(32, type = 'raw')
  expect_length(res, 32)
  expect_true(is.raw(res))
  
  res <- rbyte(32, type = "chr")
  expect_true(is.character(res))
  expect_true(nchar(res) == 64)
})
