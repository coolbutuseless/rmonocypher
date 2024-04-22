
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Use ISAAC to generate cryptographically secure pseudorandom numbers 
#' 
#' See \url{https://en.wikipedia.org/wiki/ISAAC_(cipher)} and 
#' \url{https://burtleburtle.net/bob/rand/isaacafa.html} for more information
#' on this random number generator.
#' 
#' @section Technical Note:
#' The ISAAC RNG is seeded from R's \code{unif_rand()}.  The first generation
#' of random numbers from each ISAAC run is discarded, before return the 
#' required number of bytes from the second iteration.
#' 
#' Because seeding depends on R's built-in RNG, care should be taken when 
#' running in parallel that R's RNG state is not the same in multiple 
#' parallel jobs.
#' 
#' @inheritParams argon2
#' @param n number of random bytes to return. Acceptable range
#'        [1, 1024]
#' 
#' @return a raw vector of random bytes of the requested length
#'
#' @export
#' @examples
#' isaac(32)
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
isaac <- function(n, type = 'string') {
  .Call(isaac_, n, type)
}
