

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#if defined(_WIN32)  
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/syscall.h>
#endif


#include <R.h>
#include <Rinternals.h>
#include <Rdefines.h>

#include "utils.h"



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Get random bytes from the system RNG  (C Callable)
//
// @param buf pre-allocated buffer in which to put the random bytes
// @param n number of bytes.  Note: when a system RNG runs out of entropy
//        it may return fewer bytes than expected. This function throws an 
//        error in this situation
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void rcrypto(void *buf, size_t n) {
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // macOS and BSD support arc4random_buf()
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  // void arc4random_buf(void buf[.n], size_t n);
  arc4random_buf(buf, n); 
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Windows: use BCryptGenRandom
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#elif defined(_WIN32)  
  // NTSTATUS BCryptGenRandom(
  //     [in, out] BCRYPT_ALG_HANDLE hAlgorithm,
  //     [in, out] PUCHAR            pbBuffer,
  //     [in]      ULONG             cbBuffer,
  //     [in]      ULONG             dwFlags
  // );
  // dwFlags = BCRYPT_USE_SYSTEM_PREFERRED_RNG - Use the system-preferred random 
  // number generator algorithm. The hAlgorithm parameter must be NULL. 
  size_t status = (size_t)BCryptGenRandom( NULL, ( PUCHAR ) buf, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
  // Return value is 'NTSTATUS' value. STATUS_SUCCESS = 0.
  if (status != 0) {
    error("cryptorng_windows() error: Status = %zu.\n", status);
  }
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Linux use 'Sys_getrandom()'
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#elif defined(__linux__)
  long status = (long)syscall( SYS_getrandom, buf, n, 0 );
  if (status < 0 || status != n) {
    error("cryptorng_linux() error: Status = %zu.\n", status);
  }
  
#else
#error no secrure random() implemented for this platform
#endif 
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Get random bytes from the system RNG  (R Callable)
//
// @param n_ number of bytes
// @param type_ 'raw' or 'string'
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SEXP rcrypto_(SEXP n_, SEXP type_) {
  
  if (asInteger(n_) <= 0) {
    error("rcrypto_(): 'n' must be a positive integer");
  }
  size_t n = (size_t)asInteger(n_);
  void *buf = R_alloc(n, 1);
  
  rcrypto(buf, n);
  
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // Wrap bytes for R and return
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  SEXP res_ = PROTECT(wrap_bytes_for_return((uint8_t *)buf, n, type_));
  UNPROTECT(1);
  return res_;
}





