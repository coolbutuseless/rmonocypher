

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Create a public key from your secret key for public key cryptography.
#' 
#' Use your secret key and public key with \code{create_shared_key()} to 
#' exchange keys over an insecure channel (i.e. public-key cryptography)
#' 
#' @inheritParams argon2
#' @param your_secret_key Your secret key. Can be a character string, a 32-byte raw vector
#'        or a 64-character hex string (encoding 32 bytes). When a shorter character string 
#'        is given, a 32-byte key is derived using the Argon2 algorithm.
#' 
#' @return 32-byte public key
#' 
#' @export
#' @examples
#' your_secret_key <- argon2('hello')
#' create_public_key(your_secret_key)
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
create_public_key <- function(your_secret_key, type = 'string') {
  .Call(create_public_key_, your_secret_key, type)
}



#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Key exchange over an insecure channel.
#' 
#' This function implements public-key cryptography using x25519. 
#' X25519 is an elliptic curve Diffie-Hellman key exchange using Curve25519. 
#' It allows two parties to jointly agree on a shared secret using an insecure channel.
#' 
#' @inheritParams create_public_key
#' @param their_public_key Other party's secret key. Can be a character string, a 32-byte raw vector
#'        or a 64-character hex string (encoding 32 bytes). When a shorter character string 
#'        is given, a 32-byte key is derived using the Argon2 algorithm.
#' 
#' @return A shared encryption key to use with \code{mc_encrypt()} and
#'         \code{cryptfile()}
#' 
#' @export
#' @examples
#' # The following example shows how a common encryption key may 
#' # be derived by two parties without disclosing any secret
#' # information to each other.
#' 
#' # You: Create a secret key and a public key.
#' # You: Share the public key with other party
#' your_secret <- argon2("hello")
#' your_public <- create_public_key(your_secret)
#' 
#' # They: Create a secret key and a public key
#' # They: Share their public key with you
#' their_secret <- argon2("goodbye")
#' their_public <- create_public_key(their_secret)
#' 
#' # You: Use their public key and your secret key
#' #      to derive the common shared key
#' create_shared_key(their_public, your_secret)
#' 
#' # They: Use your public key and their secret key
#' #       to derive the same shared key!
#' create_shared_key(your_public, their_secret)
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
create_shared_key <- function(their_public_key, your_secret_key, type = 'string') {
  .Call(create_shared_key_, their_public_key, your_secret_key, type)
}


if (FALSE) {
  # You: Create a secret key and a public key.
  # You: Share the public key with other party
  your_secret <- argon2("hello")
  your_public <- create_public_key(your_secret)
  
  # They: Create a secret key and a public key
  # They: Share their public key with you
  their_secret <- argon2("goodbye")
  their_public <- create_public_key(their_secret)
  
  # You: Use their public key and your secret key
  #      to derive the common shared key
  create_shared_key(their_public, your_secret)
  
  # They: Use your public key and their secret key
  #       to derive the same shared key!
  create_shared_key(your_public, their_secret)
}




