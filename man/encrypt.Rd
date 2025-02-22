% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/encrypt.R
\name{encrypt}
\alias{encrypt}
\title{Save an encrypted RDS}
\usage{
encrypt(robj, dst = NULL, key, additional_data = NULL, compress = "none")
}
\arguments{
\item{robj}{R object}

\item{dst}{Either a filename or NULL. Default: NULL write results to a raw vector}

\item{key}{The encryption key. This may be a character string, a 32-byte raw vector
or a 64-character hex string (which encodes 32 bytes). When a shorter character string 
is given, a 32-byte key is derived using the Argon2 key derivation
function.}

\item{additional_data}{Additional data to include in the
authentication.  Raw vector or character string. Default: NULL.  
This additional data is \emph{not}
included with the encrypted data, but represents an essential
component of the message authentication. The same \code{additional_data} 
must be presented during both encryption and decryption for the message
to be authenticated.  See vignette on 'Additional Data'.}

\item{compress}{compression type. Default: 'none'.  Valid values are any of
the accepted compression types for R \code{memCompress()}}
}
\value{
Raw vector containing encrypted object written to file or returned
}
\description{
Save an encrypted RDS
}
\examples{
key <- argon2('my key')
encrypt(mtcars, key = key) |> 
  decrypt(key = key)
}
