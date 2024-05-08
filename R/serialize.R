
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Save an encrypted R object to file
#' 
#' @inheritParams encrypt_raw
#' @param robj R object
#' @param filename destination filename for encrypted R object
#' 
#' @return None
#' @export
#' @examples
#' file <- tempfile()
#' encrypt(head(mtcars), file, key = "hello")
#' decrypt(file, key = "hello")
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
encrypt <- function(robj, filename, key = getOption("MONOCYPHER_KEY", default = NULL), additional_data = NULL) {
  filename <- normalizePath(filename, mustWork = FALSE)
  .Call(serialize_, robj, filename, key, additional_data)
  invisible(filename)
}

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Read an encrypted R object from file
#' 
#' @inheritParams encrypt_raw
#' @param filename source filename containing an encrypted R object
#'
#' @return None
#' @export
#' @examples
#' file <- tempfile()
#' encrypt(head(mtcars), file, key = "hello")
#' decrypt(file, key = "hello")
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
decrypt <- function(filename, key = getOption("MONOCYPHER_KEY", default = NULL), additional_data = NULL) {
  filename <- normalizePath(filename)
  .Call(unserialize_, filename, key, additional_data)
}

