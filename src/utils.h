
void dump(SEXP key_, int n);
void dump_uint8(uint8_t *key, int n);
void fill_rand(uint8_t *buf, int n);
void unpack_key(SEXP key_, uint8_t key[32]);
void unpack_salt(SEXP salt_, uint8_t salt[16]);
int hexstring_to_bytes(const char *str, uint8_t *buf, int nbytes);