
test_that("encrypted serialization works", {
  
  expect_true(TRUE)
  
  key <- 'great'
  filename <- tempfile()
  robj <- mtcars

  encrypt_obj(robj = robj, filename = filename, key = key)
  dec <- decrypt_obj(filename = filename, key = key)

  expect_identical(dec, robj)


  zz <- readBin(filename, raw(), file.size(filename))
  dec <- unserialize(decrypt(zz, key = key))
  expect_identical(dec, robj)
  
})



test_that("encrypted serialization of large object works", {
  
  expect_true(TRUE)
  
  key <- 'great'
  filename <- tempfile()
  set.seed(1)
  robj <- mtcars[sample(nrow(mtcars), 5000, T), ]


  encrypt_obj(robj = robj, filename = filename, key = key)
  dec <- NULL
  dec <- decrypt_obj(filename = filename, key = key)

  expect_identical(dec, robj)


  zz <- readBin(filename, raw(), file.size(filename))
  dec <- unserialize(decrypt(zz, key = key))
  expect_identical(dec, robj)
})