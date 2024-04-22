
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Generate bytes from a pass-phrase using Argon2 password-based key derivation
#' 
#' Argon2 is a resource intensive password-based key derivation scheme. A typical
#' application is generating an encryption key from a text pass-phrase.
#' 
#' @section Note:
#' Using the same pass-phrase with the same salt will always generate the same
#' key.  It is recommended that a random salt be used.
#' 
#' @section Technical Note:
#' The 'C' version of the ARgon2 algorithm is configured with:
#' 
#' \itemize{
#'   \item{Use the \code{Argon2id} variant of the algorithm}
#'   \item{single-threaded}
#'   \item{3 iterations}
#'   \item{100 megabytes of memory}
#' }
#' 
#' See \url{https://en.wikipedia.org/wiki/Argon2} and 
#' \url{https://monocypher.org/manual/argon2} for more information.
#' 
#' 
#' @param passphrase A character string used to derive the random bytes
#' @param length Number of bytes to output. Default: 32
#' @param salt 16-byte raw vector or 32-character hexadecimal string.
#'        A salt is data used as additional input to key derivation
#'        which helps defend against attacks that use pre-computed (i.e. rainbow) tables.
#'        Note: A salt does not need to be a secret.
#'        See \url{https://en.wikipedia.org/wiki/Salt_(cryptography)} for more details.
#'        The 'salt' may also be a non-hexadecimal string, in which case a real
#'        salt will be created by using Argon2 with a default internal salt.
#' @param type Should the data be returned as raw bytes? Default: 'string'. 
#'        Possible values 'string' or 'raw'
#'
#' @return raw vector of the requested length
#' @export
#' 
#' @examples
#' # For the sake of convenience for novice users, a salt will be 
#' # derived internally from the pass-phrase.
#' argon2("my secret")
#'
#' # Calling 'argon2()' without a seed is equivalent to using the pass-phrase
#' # as the seed.  This is not the best security practice
#' argon2("my secret", salt = "my secret")
#'
#' # Best practice is to use your own random bytes for the salt
#' argon2("my secret", salt = as.raw(sample(0:255, 16, TRUE)))
#'
#' #Can also use 'isaac()' to source random bytes
#' argon2("my secret", salt = isaac(16))
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
argon2 <- function(passphrase, salt = passphrase, length = 32, type = 'string') {
  .Call(argon2_, passphrase, salt, length, type);
}
