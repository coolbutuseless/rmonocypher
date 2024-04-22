
test_that("key exchange works", {
  my_secret <- argon2("hello")
  my_public <- create_public_key(my_secret)
  
  their_secret <- argon2("goodbye")
  their_public <- create_public_key(their_secret)
  
  expect_identical(
    create_shared_key(their_public, my_secret),
    create_shared_key(my_public, their_secret)
  )
})
