
#include <gcrypt.h>

#ifndef KEY_TYPES_H
#define KEY_TYPES_H

typedef enum{kType_rsa, kType_ecc_Ed25519} key_types;

/* Get Key Type*/
int get_key_type(key_types *key_type, gcry_sexp_t key);

/* returns key type string value*/
const char* key_type_to_str(key_types key_type);

#endif
