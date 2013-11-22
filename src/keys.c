#include "elli_internal.h"

int elli_group_init(elli_ctx_internal_t *ctx) /* {{{ */
{
	EC_GROUP *group;

	group = EC_GROUP_new_by_curve_name(ctx->curve_type);
	if (!group) {
		elli_error(ctx, "EC_GROUP_new_by_curve_name() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	if (EC_GROUP_precompute_mult(group, NULL) != 1) {
		elli_error(ctx, "EC_GROUP_precompute_mult() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		return 0;
	}

	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);
	ctx->elliptic = group;
	return 1;
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

	group = EC_GROUP_new_by_curve_name(ctx->curve_type);
	if (!group) {
		elli_error(ctx, "EC_GROUP_new_by_curve_name() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if (EC_GROUP_precompute_mult(group, NULL) != 1) {
		elli_error(ctx, "EC_GROUP_precompute_mult() failed: %s", ERR_error_string(ERR_get_error(), NULL));
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

	key = EC_KEY_new();
	if (!key) {
		elli_error(ctx, "EC_KEY_new() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	group = elli_group(ctx);
	if (!group) {
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_KEY_set_group(key, group) != 1) {
		elli_error(ctx, "EC_KEY_set_group() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_free(group);

	if (EC_KEY_generate_key(key) != 1) {
		elli_error(ctx, "EC_KEY_generate_key() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	return key;
}
/* }}} */

EC_KEY *elli_key_create_public_octets(elli_ctx_internal_t *ctx, unsigned char *octets, size_t length) /* {{{ */
{
	EC_GROUP *group;
	EC_KEY *key;
	EC_POINT *point;

	key = EC_KEY_new();
	if (!key) {
		elli_error(ctx, "EC_KEY_new() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	group = elli_group(ctx);
	if (!group) {
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_KEY_set_group(key, group) != 1) {
		elli_error(ctx, "EC_KEY_set_group() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	point = EC_POINT_new(group);
	if (!point) {
		elli_error(ctx, "EC_POINT_new() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_POINT_oct2point(group, point, octets, length, NULL) != 1) {
		elli_error(ctx, "EC_POINT_oct2point() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_KEY_set_public_key(key, point) != 1) {
		elli_error(ctx, "EC_KEY_set_public_key() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_POINT_free(point);
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_free(group);
	EC_POINT_free(point);

	if (EC_KEY_check_key(key) != 1) {
		elli_error(ctx, "EC_KEY_check_key() failed: %s", ERR_error_string(ERR_get_error(), NULL));
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

	key = EC_KEY_new();
	if (!key) {
		elli_error(ctx, "EC_KEY_new() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	group = EC_GROUP_new_by_curve_name(ctx->curve_type);
	if (!group) {
		elli_error(ctx, "EC_GROUP_new_by_curve_name() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);

	if (EC_KEY_set_group(key, group) != 1) {
		elli_error(ctx, "EC_KEY_set_group() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	point = EC_POINT_hex2point(group, hex, NULL, NULL);
	if (!point) {
		elli_error(ctx, "EC_POINT_hex2point() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_KEY_set_public_key(key, point) != 1) {
		elli_error(ctx, "EC_KEY_set_public_key() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_POINT_free(point);
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_free(group);
	EC_POINT_free(point);

	if (EC_KEY_check_key(key) != 1) {
		elli_error(ctx, "EC_KEY_check_key() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	return key;
}
/* }}} */

char *elli_key_public_get_hex(elli_ctx_internal_t *ctx, EC_KEY *key) /* {{{ */
{
	char *hex;
	const EC_POINT *point;
	const EC_GROUP *group;

	if (!(point = EC_KEY_get0_public_key(key))) {
		elli_error(ctx, "EC_KEY_get0_public_key() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if (!(group = EC_KEY_get0_group(key))) {
		elli_error(ctx, "EC_KEY_get0_group() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_COMPRESSED, NULL);
	if (!hex) {
		elli_error(ctx, "EC_POINT_point2hex() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	return hex;
}
/* }}} */

EC_KEY *elli_key_create_private_hex(elli_ctx_internal_t *ctx, char *hex)  /* {{{ */
{
	EC_GROUP *group;
	BIGNUM *bn = NULL;
	EC_KEY *key = NULL;

	key = EC_KEY_new();
	if (!key) {
		elli_error(ctx, "EC_KEY_new() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	group = EC_GROUP_new_by_curve_name(ctx->curve_type);
	if (!group) {
		elli_error(ctx, "EC_GROUP_new_by_curve_name() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);

	if (EC_KEY_set_group(key, group) != 1) {
		elli_error(ctx, "EC_KEY_set_group() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_GROUP_free(group);
		EC_KEY_free(key);
		return NULL;
	}

	EC_GROUP_free(group);

	if (!(BN_hex2bn(&bn, hex))) {
		elli_error(ctx, "BN_hex2bn() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		return NULL;
	}

	if (EC_KEY_set_private_key(key, bn) != 1) {
		elli_error(ctx, "EC_KEY_set_private_key() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(key);
		BN_free(bn);
		return NULL;
	}

	BN_free(bn);
	return key;
}
/* }}} */

char *elli_key_private_get_hex(elli_ctx_internal_t *ctx, EC_KEY *key) /* {{{ */
{
	char *hex;
	const BIGNUM *bn;

	if (!(bn = EC_KEY_get0_private_key(key))) {
		elli_error(ctx, "EC_KEY_get0_private_key() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if (!(hex = BN_bn2hex(bn))) {
		elli_error(ctx, "BN_bn2hex() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	return hex;
}
/* }}} */
