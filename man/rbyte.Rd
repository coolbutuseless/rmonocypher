% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/rbyte.R
\name{rbyte}
\alias{rbyte}
\title{Generate random bytes from the platform-specific cryptographically secure
pseudorandom number generator}
\usage{
rbyte(n, type = "chr")
}
\arguments{
\item{n}{Number of random bytes to generate.
Note: if the entropy pool is exhausted on your
system it may not be able to provide the requested number of bytes -
in this case an error is thrown.}

\item{type}{Type of returned values - 'raw' or "chr". Default: "chr".}
}
\value{
A raw vector or a hexadecimal string
}
\description{
Generate random bytes from the platform-specific cryptographically secure
pseudorandom number generator
}
\section{Platform notes}{

The method used for generating random values varies depending on the 
operating system (OS):
 
\itemize{
  \item{For macOS and BSDs: \code{arc4random_buf()}}
  \item{For linux: \code{syscall(SYS_getrandom())}}
  \item{For win32: \code{BCryptGenRandom()}}
}

All these random number generators are internally seeded by the OS using entropy 
gathered from multiple sources and are considered cryptographically secure.
}

\examples{
rbyte(16, type = "chr")
rbyte(16, type = 'raw')
}
