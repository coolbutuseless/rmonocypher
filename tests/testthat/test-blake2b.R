
test_that("serialized blake2b hash works", {
  
  res <- blake2b(mtcars, type = 'string')
  expect_true(is.character(res))
  expect_true(nchar(res) == 64)
  expect_identical(res, blake2b(mtcars))
  
  
  res <- blake2b(mtcars, type = 'raw', N = 20)
  expect_true(is.raw(res))
  expect_length(res, 20)
  expect_identical(res, blake2b(mtcars, type = 'raw', N = 20))
  
})


test_that("blake2b_raw works", {
  
  # from wikipedia
  expect_identical(
    blake2b_raw("", N = 64),
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
  )
  
  # from wikipedia
  expect_identical(
    blake2b_raw("The quick brown fox jumps over the lazy dog", N = 64),
    "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918"
  )
  
  # from wikipedia
  expect_identical(
    blake2b_raw("The quick brown fox jumps over the lazy dof", N = 64),
    "ab6b007747d8068c02e25a6008db8a77c218d94f3b40d2291a7dc8a62090a744c082ea27af01521a102e42f480a31e9844053f456b4b41e8aa78bbe5c12957bb"
  )
  
  expect_identical(
    blake2b_raw("hello"), 
    blake2b_raw(charToRaw("hello"))
  )
  
  
})