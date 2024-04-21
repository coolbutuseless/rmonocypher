
#include <R.h>
#include <Rinternals.h>

extern SEXP cryptfile_(SEXP description_, SEXP key_, SEXP mode_, SEXP additional_data_, SEXP verbosity_);

extern SEXP mc_encrypt_(SEXP x_  , SEXP key_,             SEXP additional_data_);
extern SEXP mc_decrypt_(SEXP src_, SEXP key_, SEXP type_, SEXP additional_data_);

extern SEXP argon2_(SEXP password_, SEXP salt_, SEXP hash_length_);
extern SEXP isaac_(SEXP n_);

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// .C      R_CMethodDef
// .Call   R_CallMethodDef
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
static const R_CallMethodDef CEntries[] = {
  
  {"cryptfile_", (DL_FUNC) &cryptfile_, 5},
  
  {"mc_encrypt_", (DL_FUNC) &mc_encrypt_, 3},
  {"mc_decrypt_", (DL_FUNC) &mc_decrypt_, 4},
  
  {"argon2_", (DL_FUNC) &argon2_, 3},
  {"isaac_", (DL_FUNC) &isaac_, 1},
  
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