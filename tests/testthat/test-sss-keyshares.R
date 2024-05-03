
test_that("sss keyshares works", {
  
  orig_key <- as.raw(1:32) 
  shares <- create_keyshares(orig_key, n = 6, k = 3, type = 'raw')
  
  expect_length(shares, 6)
  expect_identical(
    combine_keyshares(shares[1:3], type = 'raw'),
    orig_key
  )
  expect_identical(
    combine_keyshares(shares[2:4], type = 'raw'),
    orig_key
  )
  expect_identical(
    combine_keyshares(shares[4:6], type = 'raw'),
    orig_key
  )
  expect_identical(
    combine_keyshares(shares[c(1, 6, 2, 3)], type = 'raw'),
    orig_key
  )
  expect_false(
    identical(
      combine_keyshares(shares[c(1, 6)], type = 'raw'),
      orig_key
    )
  )
})




test_that("sss keyshares works", {
  
  orig_key <- sprintf("%02x", 1:32) |> paste(collapse = "")
  shares <- create_keyshares(orig_key, n = 6, k = 3, type = 'string')
  
  expect_length(shares, 6)
  expect_identical(
    combine_keyshares(shares[1:3], type = 'string'),
    orig_key
  )
  expect_identical(
    combine_keyshares(shares[2:4], type = 'string'),
    orig_key
  )
  expect_identical(
    combine_keyshares(shares[4:6], type = 'string'),
    orig_key
  )
  expect_identical(
    combine_keyshares(shares[c(1, 6, 2, 3)], type = 'string'),
    orig_key
  )
  expect_false(
    identical(
      combine_keyshares(shares[c(1, 6)], type = 'string'),
      orig_key
    )
  )
})
