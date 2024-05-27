
test_that("encrypt additional data works", {
  
  # Using additional data to encrypt a message
  key      <- argon2("my secret key", rbyte(16))
  message  <- 'Meet me in St Louis' |> charToRaw()
  envelope <- 'To: Judy'
  enc      <- encrypt_raw(message, key, additional_data = envelope)
  
  # Package the additional data and deliver to recipient
  letter <- list(envelope = envelope, contents = enc)
  
  # Recipient decodes message. If envelope or contents change, message decryption
  # will fail.
  tst <- decrypt_raw(letter$contents, key = key, additional_data = letter$envelope)
  expect_identical(message, tst)
  
  # Bad key
  expect_error(
    tst <- decrypt_raw(letter$contents, key = "wrong", additional_data = letter$envelope)
  )
  
  # Missing additional data
  expect_error(
    tst <- decrypt_raw(letter$contents, key = key, additional_data = NULL)
  )
  
  # altered additional data
  letter$envelope <- "To: Neo"
  expect_error(
    tst <- decrypt_raw(letter$contents, key = key, additional_data = NULL)
  )
})


