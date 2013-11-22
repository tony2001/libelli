#ifndef ELLI_INTERNAL_H
# define ELLI_INTERNAL_H

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/stack.h>

#include "elli_config.h"
#include "elli_version.h"
#include "elli.h"

typedef struct {
	struct {
		uint64_t key;
		uint64_t mac;
		uint64_t orig;
		uint64_t body;
	} length;
} verbum_head_t;

#define ELLI_ERROR_BUF_SIZE 1024

typedef struct {
	int curve_type;
	EVP_CIPHER *cipher;
	EVP_MD *hasher;
	EC_GROUP *elliptic;
	char last_error[1024];
} elli_ctx_internal_t;

#define elli_error(ctx, ...) snprintf((ctx)->last_error, sizeof((ctx)->last_error), __VA_ARGS__)

void *verbum_key_data(verbum_t *cryptex);
void *verbum_mac_data(verbum_t *cryptex);
void *verbum_body_data(verbum_t *cryptex);
uint64_t verbum_key_length(verbum_t *cryptex);
uint64_t verbum_mac_length(verbum_t *cryptex);
uint64_t verbum_body_length(verbum_t *cryptex);
uint64_t verbum_orig_length(verbum_t *cryptex);
void *verbum_alloc(uint64_t key, uint64_t mac, uint64_t orig, uint64_t body);

int elli_group_init(elli_ctx_internal_t *ctx);
void elli_group_free(elli_ctx_internal_t *ctx);
EC_GROUP *elli_group(elli_ctx_internal_t *ctx);

void elli_key_free(EC_KEY *key);

EC_KEY *elli_key_create(elli_ctx_internal_t *ctx);
EC_KEY *elli_key_create_public_hex(elli_ctx_internal_t *ctx, char *hex);
EC_KEY *elli_key_create_private_hex(elli_ctx_internal_t *ctx, char *hex);
EC_KEY *elli_key_create_public_octets(elli_ctx_internal_t *ctx, unsigned char *octets, size_t length);

char *elli_key_public_get_hex(elli_ctx_internal_t *ctx, EC_KEY *key);
char *elli_key_private_get_hex(elli_ctx_internal_t *ctx, EC_KEY *key);

#endif /*ELLI_INTERNAL_H */
