
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Create keyshares for sharing a secret with a group using Shamir's Secret
#' Sharing algorithm
#' 
#' @inheritParams encrypt_raw
#' @param n total number of shares to create
#' @param k number of shares needed to recreate key. Must be less than or 
#'        equal to \code{n}
#' @param shares list of keyshares. Each keyshare can either be a 33-byte
#'        raw vector or 66-character hexadecimal string (the shares are 1-byte
#'        larger than the key)
#' @param type return type. 'string' or 'raw'. Default: 'string' returns the 
#'        shares or key as hexadecimal character string. Otherwise returns
#'        a raw vector
#'
#' @return \code{create_keyshares()} takes a key and returns a list of keyshares.
#'         \code{combine_keyshares()} takes a list of keyshares and returns
#'         the origina key
#'         
#' @export
#' 
#' @examples
#' orig_key <- "337ca9406391140208844c76b536c111f44531adef8d5cebcc68f83ab43cc745"
#' shares <- create_keyshares(orig_key, n = 6, k = 3)
#' length(shares)
#' combine_keyshares(shares[1:3])
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
create_keyshares <- function(key, n, k, type = 'string') {
  .Call(create_keyshares_, key, n, k, type)
}


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Recreate the original key using \code{k} of \code{n} keyshares
#' @rdname create_keyshares
#' @export
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
combine_keyshares <- function(shares, type = 'string') {
  .Call(combine_keyshares_, shares, type)
}

if (FALSE) {
  orig_key <- as.raw(1:32)
  shares <- create_keyshares(orig_key, n = 6, k = 3, type = 'string')
  shares
  combine_keyshares(shares[1:3], type = 'string')
}