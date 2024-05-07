
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Save an encrypted R object to file
#' 
#' @inheritParams encrypt
#' @param robj R object
#' @param filename destination filename for encrypted R object
#' 
#' @return None
#' @export
#' @examples
#' file <- tempfile()
#' encrypt_obj(head(mtcars), file, key = "hello")
#' decrypt_obj(file, key = "hello")
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
encrypt_obj <- function(robj, filename, key) {
  filename <- normalizePath(filename, mustWork = FALSE)
  .Call(serialize_, robj, filename, key)
  invisible(filename)
}

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Read an encrypted R object from file
#' 
#' @inheritParams encrypt
#' @param filename source filename containing an encrypted R object
#'
#' @return None
#' @export
#' @examples
#' file <- tempfile()
#' encrypt_obj(head(mtcars), file, key = "hello")
#' decrypt_obj(file, key = "hello")
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
decrypt_obj <- function(filename, key) {
  filename <- normalizePath(filename)
  .Call(unserialize_, filename, key)
}

