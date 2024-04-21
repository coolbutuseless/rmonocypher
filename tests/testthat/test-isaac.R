
test_that("isaac works", {
  res <- isaac(32)
  expect_length(res, 32)
  expect_true(is.raw(res))
})
