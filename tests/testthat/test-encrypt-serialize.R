
test_that("encrypted serialization works", {
  
  expect_true(TRUE)
  
  key <- 'great'
  filename <- tempfile()
  robj <- mtcars

  encrypt(robj = robj, filename = filename, key = key)
  dec <- decrypt(filename = filename, key = key)

  expect_identical(dec, robj)


  zz <- readBin(filename, raw(), file.size(filename))
  dec <- unserialize(decrypt_raw(zz, key = key))
  expect_identical(dec, robj)
  
})



test_that("encrypted serialization of large object works", {
  
  expect_true(TRUE)
  
  key <- 'great'
  filename <- tempfile()
  set.seed(1)
  robj <- mtcars[sample(nrow(mtcars), 5000, T), ]


  encrypt(robj = robj, filename = filename, key = key)
  dec <- NULL
  dec <- decrypt(filename = filename, key = key)

  expect_identical(dec, robj)


  zz <- readBin(filename, raw(), file.size(filename))
  dec <- unserialize(decrypt_raw(zz, key = key))
  expect_identical(dec, robj)
})
