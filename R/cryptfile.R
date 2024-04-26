
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Create a custom file connection with authenticated encryption
#' 
#' Implements authenticated encryption as documented here \url{https://monocypher.org/manual/aead}.
#' 
#' @details
#' This \code{cryptfile()} connection works like R's built-in \code{file()} connection,
#' but when reading and writing uses the provided key to encrypt and decrypt 
#' the data using \emph{authenticated encryption} provided by the 'monocypher'
#' library.
#' 
#' When encrypted data is written, it cannot be decrypted without using 
#' the secret key.
#' 
#' This connection works with both ASCII and binary data, e.g. using 
#' \code{readLines()} and \code{readBin()}.
#' 
#' @inheritParams encrypt
#' @param description path for encrypted file or a connection to read/write to
#' @param open Character string. A description of how to open the connection if 
#'        it is to be opened upon creation e.g. "rb". Default "" (empty string) means
#'        to not open the connection on creation - user must still call \code{open()}.
#'        Note: If an "open" string is provided, the user must still call \code{close()}
#'        otherwise the contents of the file aren't completely flushed until the
#'        connection is garbage collected.
#' @param verbosity integer value. Default: 0.  
#'        Set to \code{0} for no debugging messages.
#'        Set to higher values (e.g. \code{verbosity = 2}) 
#'        for more debugging messages.
#' 
#' @return An R connection object
#' @export

#' @section Technical Notes:
#' The encryption functions in this package implement RFC 8439 ChaCha20-Poly1305
#' authenticated encryption with additional data. This algorithm combines
#' the ChaCha20 stream cipher with the Poly1305 message authentication code.
#' 
#' To avoid file I/O overhead, multiple sequential writes are buffered, and 
#' encrypted data is split into frames using
#' monocypher's incremental interface described here 
#' \url{https://monocypher.org/manual/aead}
#' 
#' The encrypted data on file has the structure: \code{[nonce] [frame] [frame] ... [frame]}.
#' 
#' Each \code{[frame]} consists of three elements:
#' 
#' \enumerate{
#' \item{\code{payload_size} - a \code{size_t} value giving the length of the 
#' third element in the frame}
#' \item{\code{MAC} - the message authentication code for this frame. 16 bytes}
#' \item{\code{payload} - the encrypted bytes}
#' }
#' 
#' monocypher AEAD supports a 24-byte nonce. This is initialised from random bytes
#' using the ISAAC algorithm.
#' 
#' 
#' @examples
#' # Encrypt binary data to file
#' path <- tempfile()
#' dat <- "Rosebud was his sled"
#' key <- argon2("orson's secret key")
#' writeBin(dat, cryptfile(path, key))
#' readBin(cryptfile(path, key),  raw(), 1000) |> rawToChar()
#' 
#' # Encrypt text
#' txt <- c("on the first day of christmas", "my true love gave to me")
#' writeLines(txt, cryptfile(path, key))
#' readLines(cryptfile(path, key))
#' 
#' # Save an encrypted R object
#' saveRDS(head(mtcars), cryptfile(path, key))
#' readRDS(cryptfile(path, key))
#' 
#' # Write an encrypted CSV
#' write.csv(head(iris), cryptfile(path, key))
#' read.csv(cryptfile(path, key))
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cryptfile <- function(description, key = getOption("MONOCYPHER_KEY", default = NULL),
                      open = "", additional_data = NULL, verbosity = 0) {
  
  if (is.character(description)) {
    description <- normalizePath(description, mustWork = FALSE)
  }
  
  .Call(
    cryptfile_, 
    description     = description, 
    key             = key,
    open            = open,
    additional_data = additional_data,
    verbosity       = verbosity
  )
}
