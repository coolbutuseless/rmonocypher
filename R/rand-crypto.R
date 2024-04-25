
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Generate random bytes from the platform-specific cryptographically secure
#' pseudorandom number generator
#' 
#' @param n Number of random bytes to generate.
#'        Note: if the entropy pool is exhausted on your
#'        system it may not be able to provide the requested number of bytes -
#'        in this case an error is thrown.
#' @param type Type of returned values - 'raw' or 'string'. Default: 'string'.
#' 
#' @section Platform notes:
#' The method used for generating random values varies depending on the 
#' operating system (OS):
#'  
#' \itemize{
#'   \item{For macOS and BSDs: \code{arc4random_buf()}}
#'   \item{For linux: \code{syscall(SYS_getrandom())}}
#'   \item{For win32: \code{BCryptGenRandom()}}
#' }
#'
#' All these random number generators are internally seeded by the OS using entropy 
#' gathered from multiple sources and are considered cryptographically secure.
#'
#' @return A raw vector or a hexadecimal string
#' 
#' @export
#' @examples
#' rcrypto(16, type = 'string')
#' rcrypto(16, type = 'raw')
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rcrypto <- function(n, type = 'string') {
  .Call(rcrypto_, n, type)
}
