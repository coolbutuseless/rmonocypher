
test_that("cryptfile is readable by decrypt", {
  tmp <- tempfile()
  dat <- as.raw(1:16)

  
  writeBin(dat, cryptfile(tmp, "my secret"))
  # readBin(tmp, raw(), 100)
  # encrypt(dat, "my secret")
  # readBin(cryptfile(tmp, "my secret"), raw(), 20)

  tst <- readBin(tmp, raw(), 100)
  tst <- decrypt(tst, "my secret")
  expect_identical(tst, dat)
})


test_that("encrypt output is readable by cryptfile", {
  tmp <- tempfile()
  dat <- as.raw(1:16)
  
  enc <- encrypt(dat, "my secret")
  writeBin(enc, tmp)
  # readBin(tmp, raw(), 100)
  # encrypt(dat, "my secret")
  # readBin(cryptfile(tmp, "my secret"), raw(), 20)
  
  tst <- readBin(cryptfile(tmp, "my secret"), raw(), 100)
  expect_identical(tst, dat)
})


test_that("cryptfile works", {
  tmp <- tempfile()
  ref <- as.raw(1:255)
  writeBin(ref, cryptfile(tmp, key = "my secret", verbosity = 0))
  tst <- readBin(cryptfile(tmp, key = "my secret", verbosity = 0),  raw(), 1000)
  expect_identical(tst, ref)
  
  tmp <- tempfile()
  ref <- deparse1(c('hello', 'there'))
  writeLines(ref, cryptfile(tmp, key = "my secret", verbosity = 0))
  tst <- readLines(cryptfile(tmp, key = "my secret", verbosity = 0))
  expect_identical(tst, ref)
})


test_that("cryptfile works at multiple sizes", {
  tmp <- tempfile()
  key <- argon2('my secret', rcrypto(16))
  N <- 65537
  
  for (N in 10^(2:7)) {
    # message(N)
    ref <- as.raw(seq_len(N) %% 256)
    writeBin(ref, cryptfile(tmp, key = key, verbosity = 0))
    tst <- readBin(cryptfile(tmp, key = key, verbosity = 0),  raw(), N)
    expect_identical(tst, ref, label = sprintf("[cryptfile test size = %i]", N))
    
    
    tst <- readBin(tmp, raw(), N*2)
    tst <- decrypt(tst, key)
    expect_identical(tst, ref, label = sprintf("[cryptfile test size (manual decryupt) = %i]", N))
  }
})




test_that("cryptfile doubler works at multiple sizes", {
  tmp <- tempfile()
  key <- argon2('my secret', rcrypto(16))
  N <- 10^2
  
  for (N in 10^(2:6)) {
    # message(N)
    ref <- as.raw(seq_len(N) %% 256)
    stream <- cryptfile(tmp, key = key, verbosity = 0)
    open(stream, 'wb')
    writeBin(ref, stream)
    writeBin(ref, stream)
    close(stream)
    
    # Stream connection reader
    if (TRUE) {
      tst <- readBin(cryptfile(tmp, key = key, verbosity = 0),  raw(), N * 4)
      expect_identical(tst, c(ref, ref), label = sprintf("[cryptfile doubler test size = %i]", N))
    }
    
    # decrypt stream reader
    tst <- readBin(tmp, raw(), N*4)
    tst <- decrypt(tst, key)
    expect_identical(tst, c(ref, ref), label = sprintf("[cryptfile doubler test size (manual decryupt) = %i]", N))
  }
})





test_that("cryptfile text works at multiple sizes", {
  tmp <- tempfile()
  key <- argon2('my secret', rcrypto(16))
  s <- paste(sample(letters, 1000, T), collapse = "")
  N <- 10^1
  
  for (N in 10^c(1,3,5)) {
    ref <- rep(s, N)
    stream <- cryptfile(tmp, key = key, verbosity = 0)
    writeLines(ref, stream)
    
    # Stream connection reader
    tst <- readLines(cryptfile(tmp, key = key, verbosity = 0),  N)
    expect_identical(tst, ref, label = sprintf("[cryptfile lines test size = %i]", N))
    
    # decrypt stream reader
    tst <- readBin(tmp, raw(), file.size(tmp))
    tst <- decrypt(tst, key) |> rawToChar()
    expect_identical(tst, paste(c(ref, ''), collapse = "\n"), label = sprintf("[cryptfile doubler test size (manual decryupt) = %i]", N))
  }
})


test_that("cryptfile serialize works", {
  
  tmp <- tempfile()
  key <- argon2('my secret', rcrypto(16))
  dat <- mtcars
  saveRDS(dat, cryptfile(tmp, key))
  tst <- readRDS(cryptfile(tmp, key))
  expect_identical(tst, dat)  
  
  
  tmp <- tempfile()
  set.seed(1); dat <- mtcars[sample(nrow(dat), 638, T),]
  # pryr::object_size(dat)  
  saveRDS(dat, cryptfile(tmp, key))
  file.size(tmp)
  tst <- readRDS(cryptfile(tmp, key))
  expect_identical(tst, dat)  
  
  
  # Crosses the 65535 bytes threshold
  tmp <- tempfile()
  set.seed(1); dat <- mtcars[sample(nrow(dat), 639, T),] 
  # pryr::object_size(dat)  
  saveRDS(dat, cryptfile(tmp, key))
  file.size(tmp)
  tst <- readRDS(cryptfile(tmp, key))
  expect_identical(tst, dat)  
})



if (FALSE) {
  
  tmp <- tempfile()
  dat  <- as.raw(seq(65534) %% 255)
  dat2 <- as.raw(seq(5) %% 255)
  s <- cryptfile(tmp, key)
  open(s, 'wb')
  writeBin(dat, s)
  writeBin(dat2, s)
  close(s)
  file.size(tmp)
  65534 + 48 + 5 + 8 + 16
  
  
  s <- cryptfile(tmp, key)
  open(s, 'rb')
  tt <- readBin(s, raw(), 65560)
  length(tt)
  tail(tt)
  close(s)
  
  identical(tt, c(dat, dat2))
}










