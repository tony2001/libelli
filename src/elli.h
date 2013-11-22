#ifndef ELLI_H
# define ELLI_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

/* Based on Ladar Levison's ECIES module code. */

//#define ECIES_CURVE NID_secp521r1
#define ECIES_CURVE NID_secp112r1
#define ECIES_CIPHER EVP_aes_256_cbc()

typedef enum {
	ELLI_secp160r1
} elli_curve_t;

typedef char* verbum_t;
typedef char* elli_ctx_t;
uint64_t verbum_total_length(verbum_t *encrypted);

elli_ctx_t *elli_ctx_create();
char *elli_ctx_last_error(elli_ctx_t *ctx);
void elli_ctx_free(elli_ctx_t *ctx);

verbum_t *elli_encrypt(elli_ctx_t *ctx, char *key, unsigned char *data, size_t length);
unsigned char *elli_decrypt(elli_ctx_t *ctx, char *key, verbum_t *encrypted, size_t *length);

#endif /* ELLI_H */
