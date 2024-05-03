
#include <R.h>
#include <Rinternals.h>

extern SEXP cryptfile_(SEXP description_, SEXP key_, SEXP mode_, SEXP additional_data_, SEXP verbosity_);

extern SEXP encrypt_(SEXP x_  , SEXP key_,             SEXP additional_data_);
extern SEXP decrypt_(SEXP src_, SEXP key_, SEXP type_, SEXP additional_data_);

extern SEXP argon2_(SEXP password_, SEXP salt_, SEXP hash_length_, SEXP type_);
extern SEXP rcrypto_(SEXP n_, SEXP type_);

SEXP create_public_key_(SEXP your_secret_key_, SEXP type_);
SEXP create_shared_key_(SEXP their_public_key_, SEXP your_secret_key_, SEXP type_);

SEXP create_keyshares_(SEXP key_, SEXP n_, SEXP k_, SEXP type_);
SEXP combine_keyshares_(SEXP shares_, SEXP type_);

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// .C      R_CMethodDef
// .Call   R_CallMethodDef
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
static const R_CallMethodDef CEntries[] = {
  
  {"cryptfile_", (DL_FUNC) &cryptfile_, 5},
  
  {"encrypt_", (DL_FUNC) &encrypt_, 3},
  {"decrypt_", (DL_FUNC) &decrypt_, 4},
  
  {"rcrypto_", (DL_FUNC) &rcrypto_, 2},
  {"argon2_" , (DL_FUNC) &argon2_ , 4},
  
  {"create_public_key_", (DL_FUNC) &create_public_key_, 2},
  {"create_shared_key_", (DL_FUNC) &create_shared_key_, 3},
  
  {"create_keyshares_" , (DL_FUNC) &create_keyshares_ , 4},
  {"combine_keyshares_", (DL_FUNC) &combine_keyshares_, 2},
  
  {NULL, NULL, 0}
};


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Register the methods
//
// Change the '_simplecall' suffix to match your package name
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void R_init_rmonocypher(DllInfo *info) {
  R_registerRoutines(
    info,      // DllInfo
    NULL,      // .C
    CEntries,  // .Call
    NULL,      // Fortran
    NULL       // External
  );
  R_useDynamicSymbols(info, FALSE);
}
