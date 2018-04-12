#ifndef ELLI_H
# define ELLI_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

/* Based on Ladar Levison's ECIES module code. */

#define ECIES_DEFAULT_CURVE NID_secp521r1
//#define ECIES_CURVE NID_secp112r1
#define ECIES_DEFAULT_CIPHER EVP_aes_256_cbc()

typedef char* elli_ctx_t;

elli_ctx_t *elli_ctx_create(const char *curve_name, char **error_str);
char *elli_ctx_last_error(elli_ctx_t *ctx);
void elli_ctx_free(elli_ctx_t *ctx);

/*
 to generate a key file use this:
   openssl ecparam -name secp112r1 -genkey -out key.pem
 you can use any curve type instead of secp112r1, see full list with this command:
   openssl ecparam -list_curves
*/

/*
 keys is specified in HEX form, use this command:
   openssl ec -in key.pem -text -noout
 and remove the colons from the output.
 */
char *elli_encrypt(elli_ctx_t *ctx, char *public_key_hex, char *data, size_t *length);
char *elli_decrypt(elli_ctx_t *ctx, char *private_key_hex, char *encrypted, size_t *length);

#endif /* ELLI_H */
