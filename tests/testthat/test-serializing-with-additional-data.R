test_that("encrypted serialization with additional data works", {
  
  expect_true(TRUE)
  
  key <- 'great'
  filename <- tempfile()
  robj <- mtcars
  
  additional_data = "pumpernickel"
  
  encrypt(robj = robj, filename = filename, key = key, additional_data = additional_data)
  dec <- decrypt(filename = filename, key = key, additional_data = additional_data)
  
  expect_identical(dec, robj)
  
  
  zz <- readBin(filename, raw(), file.size(filename))
  dec <- unserialize(decrypt_raw(zz, key = key, additional_data = additional_data))
  expect_identical(dec, robj)
  
  # if additional data is wrong or lacking, expect error
  expect_error(
    decrypt(filename = filename, key = key, additional_data = "wrong"),
    "failed"
  )
  # if additional data is wrong or lacking, expect error
  expect_error(
    decrypt(filename = filename, key = key),
    "failed"
  )
    
})



test_that("encrypted serialization of large objects with additional data works", {
  
  expect_true(TRUE)
  
  additional_data = "ryebread"
  
  key <- 'great'
  filename <- tempfile()
  set.seed(1)
  robj <- mtcars[sample(nrow(mtcars), 5000, T), ]
  
  
  encrypt(robj = robj, filename = filename, key = key, additional_data = additional_data)
  dec <- NULL
  dec <- decrypt(filename = filename, key = key, additional_data = additional_data)
  
  expect_identical(dec, robj)
  
  
  zz <- readBin(filename, raw(), file.size(filename))
  dec <- unserialize(decrypt_raw(zz, key = key, additional_data = additional_data))
  expect_identical(dec, robj)
  
  # if additional data is wrong or lacking, expect error
  expect_error(
    decrypt(filename = filename, key = key, additional_data = "wrong"),
    "failed"
  )
  # if additional data is wrong or lacking, expect error
  expect_error(
    decrypt(filename = filename, key = key),
    "failed"
  )
})