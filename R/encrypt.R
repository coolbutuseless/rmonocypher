
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Encrypt/Decrypt Data with 'Authenticated Encryption with Additional Data' (AEAD)
#' 
#' Implements authenticated encryption as documented here \url{https://monocypher.org/manual/aead}
#' 
#' @description
#' This is a low-level function for encrypting/decrypting data using
#' 'Authenticated Encryption with Additional Data' (AEAD).  This encryption
#' scheme assures data confidentiality (privacy) i.e. the encrypted data is
#' impossible to understand with the knowledge of the secret \emph{key}.
#' 
#' The authenticity of the message is also assured i.e. the message is 
#' unforgeable.
#' 
#' Additional data can optionally be included in the encryption process. This data is 
#' not encrypted, nor is it included with the output. Instead this 
#' data is a part of the message authentication. See below for more details.
#' 
#' @param x Data to encrypt. Character string or raw vector.
#' @param key The encryption key. Can be a character string, a 32-byte raw vector
#'        or a 64-character hex string (encoding 32 bytes). When a shorter character string 
#'        is given, a 32-byte key is derived using the Argon2 algorithm and 
#'        a default, fixed code (note: this is insecure).  
#'        If this argument is not explicitly set by the user 
#'        when calling the function, an attempt is made to fetch \code{'MONOCYPHER_KEY'} from
#'        the session global options. 
#'        It is recommended that a key be created external to this function call.
#' @param src Raw vector of data to decrypt
#' @param type Return type for decrypted data. Possible values: 'raw', or 'string'.
#'        Default: 'raw'
#' @param additional_data Additional data to include in the
#'        authentication.  Raw vector or character string. Default: NULL.  
#'        This additional data is \emph{not}
#'        included with the encrypted data, but represents an essential
#'        component of the message authentication. The same \code{additional_data} 
#'        must be presented during both encryption and decryption for the message
#'        to be authenticated.  See section below on 'Additional Data'.
#' 
#' @section Additional Data:
#' 
#' Additional data (or 'associated data') may be included in the encryption
#' process. This additional data is part of the message authentication, but 
#' not part of the encrypted message.
#' 
#' A common way additional data is used is for encrypted data which has an 
#' unencrypted header containing meta-information.  This header must be readable
#' before the message is decrypted, but also must not allow tampering.
#' 
#' An example of the use of encrypted data is an encrypted network packet.  The
#' packet header must be readable to allow routing, but the encrypted payload
#' needs to remain confidential.  In this case, the header is the \emph{additional data} -
#' it is sent with the data, but not encrypted.  Because the header forms
#' part of the message authentication, any modification of the header will 
#' affect the authentication of the encrypted payload.
#' 
#' 
#' @return \code{mc_encrypt()} returns a raw vector containing the \emph{nonce},
#'         \emph{mac}, \emph{size of the encrypted data}, and the encrypted
#'         data itself.
#'         
#'         \code{mc_decrypt()} returns the decrypted data as a raw vector or
#'         string depending upon the \code{type} argument.
#'         
#' @export
#' 
#' @examples
#' # Encrypt/Decrypt a string or raw vector
#' # Data to encrypt
#' dat <- "Follow the white rabbit"
#' 
#' # Create an encryption key
#' key <- argon2("my secret key") # Keep this key secret!
#' key
#' 
#' # Encrypt the data
#' enc <- mc_encrypt(dat, key)
#' enc
#' 
#' # Using the same key, decrypt the data as bytes
#' mc_decrypt(enc, key)
#' # Decrypt as a string
#' mc_decrypt(enc, key, type = 'string')
#' 
#' # The following is an advanced feature
#' # Using additional data to encrypt a message
#' key      <- argon2("my secret key")
#' message  <- 'Meet me in St Louis'
#' envelope <- 'To: Judy'
#' enc      <- mc_encrypt(message, key, additional_data = envelope)
#' 
#' # Package the additional data and deliver to recipient
#' letter <- list(envelope = envelope, contents = enc)
#' letter
#' 
#' # Recipient decodes message. If envelope or contents are tampered with, 
#' # the message decryption will fail.
#' mc_decrypt(letter$contents, key = key, type = 'string', additional_data = letter$envelope)
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
mc_encrypt <- function(x, key = getOption("MONOCYPHER_KEY", default = NULL), additional_data = NULL) {
  .Call(mc_encrypt_, x, key, additional_data)
}


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' @rdname mc_encrypt
#' @export
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
mc_decrypt <- function(src, key = getOption("MONOCYPHER_KEY", default = NULL), type = 'raw', additional_data = NULL) {
  .Call(mc_decrypt_, src, key, type, additional_data)
}
