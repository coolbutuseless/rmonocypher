

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Cryptographic hash of R object using 'blake2b'
#' 
#' BLAKE2b is a general-purpose cryptographic hash function -  
#' it is not suited for hashing passwords and deriving cryptographic keys from passwords.
#' 
#' To derive cryptograph keys from passwords use \code{argon2()}
#' 
#' @param robj Any R object supported by \code{serialize()} or \code{saveRDS()}
#' @param N size of hash in bytes. valid range [1, 64]. Default: 32.
#'        Anything below 32 is discouraged.  Note that shorter hashes are 
#'        not truncations of longer hashes.
#' @param type Return type: 'raw' or 'string'.  Default: 'string'
#' 
#' @return cryptographic hash of the serialized object
#' @export
#' @examples
#' blake2b(mtcars)
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
blake2b <- function(robj, N = 32, type = 'string') {
  .Call(blake2b_, robj, N, type)
}


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Calculate cryptographic hash or raw vector or string using 'blake2b'
#' 
#' @inheritParams blake2b
#' @param x raw vector or string
#' 
#' @return cryptographic hash of the raw vector or string
#' @export
#' @examples
#' blake2b_raw("apple")
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
blake2b_raw <- function(x, N = 32, type = 'string') {
  .Call(blake2b_raw_, x, N, type)
}