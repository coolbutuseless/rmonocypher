
void dump(SEXP key_, int n);
void dump_uint8(uint8_t *key, int n);
void unpack_key(SEXP key_, uint8_t key[32]);
void unpack_salt(SEXP salt_, uint8_t salt[16]);
void unpack_bytes(SEXP bytes_, uint8_t *buf, size_t N);
int hexstring_to_bytes(const char *str, uint8_t *buf, int nbytes);
char *bytes_to_hex(uint8_t *buf, size_t len);
SEXP wrap_bytes_for_return(uint8_t *buf, size_t N, SEXP type_);
