#include "elli_internal.h"

void elli_group_init(elli_ctx_internal_t *ctx) /* {{{ */
{
	EC_GROUP *group;

	if (!(group = EC_GROUP_new_by_curve_name(ctx->curve_type))) {
		printf("EC_GROUP_new_by_curve_name failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
	}

	else if (EC_GROUP_precompute_mult(group, NULL) != 1) {
		printf("EC_GROUP_precompute_mult failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
	}

	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);
	ctx->elliptic = group;
}
/* }}} */

void elli_group_free(elli_ctx_internal_t *ctx) /* {{{ */
{
	EC_GROUP *group = ctx->elliptic;

	ctx->elliptic = NULL;

	if (group) {
		EC_GROUP_free(group);
	}
}
/* }}} */

EC_GROUP *elli_group(elli_ctx_internal_t *ctx) /* {{{ */
{
	EC_GROUP *group;

	if (ctx->elliptic) {
		return EC_GROUP_dup(ctx->elliptic);
	}

	if (!(group = EC_GROUP_new_by_curve_name(ctx->curve_type))) {
		printf("EC_GROUP_new_by_curve_name failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	else if (EC_GROUP_precompute_mult(group, NULL) != 1) {
		printf("EC_GROUP_precompute_mult failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		return NULL;
	}

	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);

	return EC_GROUP_dup(group);
}
/* }}} */

void elli_key_free(EC_KEY *key) /* {{{ */
{
	EC_KEY_free(key);
}
/* }}} */

EC_KEY *elli_key_create(elli_ctx_internal_t *ctx) /* {{{ */
{
	EC_GROUP *group;
	EC_KEY *key = NULL;

	if (!(key = EC_KEY_new())) {
		printf("EC_KEY_new failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if (!(group = elli_group(ctx))) {
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_KEY_set_group(key, group) != 1) {
		printf("EC_KEY_set_group failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_free(group);

	if (EC_KEY_generate_key(key) != 1) {
		printf("EC_KEY_generate_key failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	return key;
}
/* }}} */

EC_KEY *elli_key_create_public_octets(elli_ctx_internal_t *ctx, unsigned char *octets, size_t length) /* {{{ */
{
	EC_GROUP *group;
	EC_KEY *key = NULL;
	EC_POINT *point = NULL;

	if (!(key = EC_KEY_new())) {
		printf("EC_KEY_new failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if (!(group = elli_group(ctx))) {
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_KEY_set_group(key, group) != 1) {
		printf("EC_KEY_set_group failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	if (!(point = EC_POINT_new(group))) {
		printf("EC_POINT_new failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_POINT_oct2point(group, point, octets, length, NULL) != 1) {
		printf("EC_POINT_oct2point failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_KEY_set_public_key(key, point) != 1) {
		printf("EC_KEY_set_public_key failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_POINT_free(point);
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_free(group);
	EC_POINT_free(point);

	if (EC_KEY_check_key(key) != 1) {
		printf("EC_KEY_check_key failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	return key;
}
/* }}} */

EC_KEY *elli_key_create_public_hex(elli_ctx_internal_t *ctx, char *hex) /* {{{ */
{
	EC_GROUP *group;
	EC_KEY *key = NULL;
	EC_POINT *point = NULL;

	if (!(key = EC_KEY_new())) {
		printf("EC_KEY_new\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if (!(group = EC_GROUP_new_by_curve_name(ctx->curve_type))) {
		printf("EC_GROUP_new_by_curve_name failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);

	if (EC_KEY_set_group(key, group) != 1) {
		printf("EC_KEY_set_group\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	if (!(point = EC_POINT_hex2point(group, hex, NULL, NULL))) {
		printf("EC_POINT_hex2point\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_KEY_set_public_key(key, point) != 1) {
		printf("EC_KEY_set_public_key\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_POINT_free(point);
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_free(group);
	EC_POINT_free(point);

	if (EC_KEY_check_key(key) != 1) {
		printf("EC_KEY_check_key\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	return key;
}
/* }}} */

char *elli_key_public_get_hex(EC_KEY *key) /* {{{ */
{
	char *hex;
	const EC_POINT *point;
	const EC_GROUP *group;

	if (!(point = EC_KEY_get0_public_key(key))) {
		printf("EC_KEY_get0_public_key\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if (!(group = EC_KEY_get0_group(key))) {
		printf("EC_KEY_get0_group\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if (!(hex = EC_POINT_point2hex(group, point, 
					POINT_CONVERSION_COMPRESSED, NULL))) {
		printf("EC_POINT_point2hex\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	//printf("PUB: %s\n", hex);
	return hex;
}
/* }}} */

EC_KEY *elli_key_create_private_hex(elli_ctx_internal_t *ctx, char *hex)  /* {{{ */
{
	EC_GROUP *group;
	BIGNUM *bn = NULL;
	EC_KEY *key = NULL;

	if (!(key = EC_KEY_new())) {
		printf("EC_KEY_new\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if (!(group = EC_GROUP_new_by_curve_name(ctx->curve_type))) {
		printf("EC_GROUP_new_by_curve_name failed. {error = %s}\n", 
				ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);

	if (EC_KEY_set_group(key, group) != 1) {
		printf("EC_KEY_set_group\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_free(group);

	if (!(BN_hex2bn(&bn, hex))) {
		printf("BN_hex2bn\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_KEY_set_private_key(key, bn) != 1) {
		printf("EC_KEY_set_public_key\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		BN_free(bn);
		return NULL;
	}

	BN_free(bn);

	return key;
}
/* }}} */

char *elli_key_private_get_hex(EC_KEY *key) /* {{{ */
{
	char *hex;
	const BIGNUM *bn;

	if (!(bn = EC_KEY_get0_private_key(key))) {
		printf("EC_KEY_get0_private_key\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if (!(hex = BN_bn2hex(bn))) {
		printf("BN_bn2hex\n");
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	//printf("PRIV: %s\n", hex);
	return hex;
}
/* }}} */
