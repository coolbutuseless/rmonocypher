
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Low Level Encryption/Decryption or Raw Vectors with 'Authenticated Encryption with Additional Data' (AEAD)
#' 
#' Implements authenticated encryption as documented here \url{https://monocypher.org/manual/aead}
#' 
#' @description
#' This is a low-level function for encrypting/decrypting data using
#' 'Authenticated Encryption with Additional Data' (AEAD).  This encryption
#' scheme assures data confidentiality (privacy) i.e. the encrypted data is
#' impossible to understand without the knowledge of the secret \emph{key}.
#' 
#' The authenticity of the message is also assured i.e. the message is 
#' unforgeable.
#' 
#' Additional data can optionally be included in the encryption process. This data is 
#' not encrypted, nor is it included with the output. Instead this 
#' data is a part of the message authentication. See below for more details.
#' 
#' @param x Data to encrypt. Character string or raw vector.
#' @param key The encryption key. This may be a character string, a 32-byte raw vector
#'        or a 64-character hex string (which encodes 32 bytes). When a shorter character string 
#'        is given, a 32-byte key is derived using the Argon2 key derivation
#'        function.  
#'        If a key is not explicitly set by the user 
#'        when calling the function, an attempt is made to fetch \code{'MONOCYPHER_KEY'} from
#'        the session global options. 
#' @param src Raw vector of data to decrypt
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
#' @section Technical Notes:
#' The encryption functions in this package implement RFC 8439 ChaCha20-Poly1305
#' authenticated encryption with additional data. This algorithm combines
#' the ChaCha20 stream cipher with the Poly1305 message authentication code.
#' 
#' @return \code{encrypt_raw()} returns a raw vector containing the \emph{nonce},
#'         \emph{mac} and the encrypted data
#'         
#'         \code{decrypt_raw()} returns the decrypted data as a raw vector
#'         
#' @export
#' 
#' @examples
#' # Encrypt/Decrypt a string or raw vector
#' # Data to encrypt
#' dat <- "Follow the white rabbit" |> charToRaw()
#' 
#' # Create an encryption key
#' key <- argon2("my secret key") # Keep this key secret!
#' key
#' 
#' # Encrypt the data
#' enc <- encrypt_raw(dat, key)
#' enc
#' 
#' # Using the same key, decrypt the data 
#' decrypt_raw(enc, key) |> rawToChar()
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
encrypt_raw <- function(x, key = getOption("MONOCYPHER_KEY", default = NULL), additional_data = NULL) {
  .Call(encrypt_, x, key, additional_data)
}


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' @rdname encrypt_raw
#' @export
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
decrypt_raw <- function(src, key = getOption("MONOCYPHER_KEY", default = NULL), additional_data = NULL) {
  .Call(decrypt_, src, key, additional_data)
}



#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Save an encrypted RDS
#' 
#' @inheritParams encrypt_raw
#' @param robj R object
#' @param dst Either a filename or NULL. Default: NULL write results to a raw vector
#' @param compress compression type. Default: 'none'.  Possible values:
#'        'none', 'gzip', 'bzip2', 'xz'
#'
#' @return Raw vector containing encrypted object written to file or returned
#' @export
#' 
#' @examples
#' key <- argon2('my key')
#' encrypt(mtcars, key = key) |> 
#'   decrypt(key = key)
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
encrypt <- function(robj, dst = NULL, key = getOption("MONOCYPHER_KEY", default = NULL), additional_data = NULL,
                    compress = c('none', 'gzip', 'bzip2', 'xz')) {
  
  # Serialize the object to a raw vector
  dat <- serialize(robj, connection = NULL, ascii = FALSE, xdr = FALSE)
  
  # Optionally compress data
  compress <- match.arg(compress)
  if (compress != 'none') {
    dat <- memCompress(dat, type = compress)
  }
  
  # Encrypt the raw vector
  enc <- .Call(encrypt_, dat, key, additional_data)
  
  # return raw vector or write to file
  if (is.null(dst)) {
    enc
  } else {
    writeBin(enc, dst)
    invisible(dst)
  }
}


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#' Decrypt an ecnrypted object
#' 
#' @inheritParams encrypt_raw
#' @param src Raw vector or filename
#'
#' @return Decrypted, unserialized R object
#' @export
#' 
#' @examples
#' key <- argon2('my key')
#' encrypt(mtcars, key = key) |> 
#'   decrypt(key = key)
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
decrypt <- function(src, key = getOption("MONOCYPHER_KEY", default = NULL), additional_data = NULL) {

  # If 'src' is not a raw vector then it must be a filename
  if (!is.raw(src)) {
    src <- readBin(src, 'raw', n = file.size(src))
  }  

  # Decrypt the encrypted data in the raw vector
  dec <- .Call(decrypt_, src, key, additional_data)
  
  # decompress
  dec <- memDecompress(dec)
  
  # Unserialize the object 
  unserialize(dec)
}











