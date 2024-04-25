
test_that("encrypt additional data works", {
  
  # Using additional data to encrypt a message
  key      <- argon2("my secret key", rcrypto(16))
  message  <- 'Meet me in St Louis'
  envelope <- 'To: Judy'
  enc      <- encrypt(message, key, additional_data = envelope)
  
  # Package the additional data and deliver to recipient
  letter <- list(envelope = envelope, contents = enc)
  
  # Recipient decodes message. If envelope or contents change, message decryption
  # will fail.
  tst <- decrypt(letter$contents, key = key, type = 'string', additional_data = letter$envelope)
  expect_identical(message, tst)
  
  
  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  # Connections aren't closed when an error occurs here.
  # Instead, we have to wait for gc() to close unused connections.
  # But when testing this just leads to ugly notifcation/warning messages
  # Only run local
  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  testthat::skip_on_cran()
  # Bad key
  expect_error(
    tst <- decrypt(letter$contents, key = "wrong", type = 'string', additional_data = letter$envelope)
  )
  
  # Missing additional data
  expect_error(
    tst <- decrypt(letter$contents, key = key, type = 'string', additional_data = NULL)
  )
  
  # altered additional data
  letter$envelope <- "To: Neo"
  expect_error(
    tst <- decrypt(letter$contents, key = key, type = 'string', additional_data = NULL)
  )
})


test_that("cryptfile with additional data works", {
  
  # Using additional data to encrypt a message
  key      <- argon2("my secret key", rcrypto(16))
  message  <- 'Meet me in St Louis'
  envelope <- 'To: Judy'
  path     <- tempfile()
  # saveRDS(message, cryptfile(path, key, additional_data = NULL))
  # saveRDS(message, cryptfile(path, key, additional_data = charToRaw(envelope)))
  saveRDS(message, cryptfile(path, key, additional_data = envelope))
  
  # Package the additional data and deliver to recipient
  letter <- list(envelope = envelope, contents = path)
  
  # Recipient decodes message. If envelope or contents change, message decryption
  # will fail.
  tst <- readRDS(cryptfile(letter$contents, key = key, additional_data = letter$envelope))
  expect_identical(message, tst)
  
  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  # Connections aren't closed when an error occurs here.
  # Instead, we have to wait for gc() to close unused connections.
  # But when testing this just leads to ugly notifcation/warning messages
  # Only run local
  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  testthat::skip_on_cran()
  # Bad key
  expect_error({
    tst <- readRDS(cryptfile(letter$contents, key = "wrong key", additional_data = letter$envelope))
  })
  
  # Missing additional data
  expect_error({
    tst <- readRDS(cryptfile(letter$contents, key = key, additional_data = NULL))
  })
  
  # Altered additional data
  letter$envelope <- "To: Neo"
  expect_error({
    tst <- readRDS(cryptfile(letter$contents, key = key, additional_data = NULL))
  })
  
})
