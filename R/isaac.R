
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Use ISAAC to generate cryptographically secure pseudorandom numbers 
#' 
#' See \url{https://en.wikipedia.org/wiki/ISAAC_(cipher)} and 
#' \url{https://burtleburtle.net/bob/rand/isaacafa.html} for more information
#' on this random number generator.
#' 
#' @param n number of random bytes to return. Acceptable range
#'        [1, 1024]
#' 
#' @return a raw vector of random bytes of the requested length
#'
#' @export
#' @examples
#' isaac(32)
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
isaac <- function(n) {
  .Call(isaac_, n)
}
