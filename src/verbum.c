#include "elli_internal.h"

uint64_t verbum_key_length(verbum_t *encrypted)  /* {{{ */
{
	verbum_head_t *head = (verbum_head_t *)encrypted;
	return head->length.key;
}
/* }}} */

uint64_t verbum_mac_length(verbum_t *encrypted) /* {{{ */
{
	verbum_head_t *head = (verbum_head_t *)encrypted;
	return head->length.mac;
}
/* }}} */

uint64_t verbum_body_length(verbum_t *encrypted) /* {{{ */
{
	verbum_head_t *head = (verbum_head_t *)encrypted;
	return head->length.body;
}
/* }}} */

uint64_t verbum_orig_length(verbum_t *encrypted) /* {{{ */
{
	verbum_head_t *head = (verbum_head_t *)encrypted;
	return head->length.orig;
}
/* }}} */

uint64_t verbum_total_length(verbum_t *encrypted) /* {{{ */
{
	verbum_head_t *head = (verbum_head_t *)encrypted;
	return sizeof(verbum_head_t) + (head->length.key + head->length.mac + head->length.body);
}
/* }}} */

void * verbum_key_data(verbum_t *encrypted) /* {{{ */
{
	return (char *)encrypted + sizeof(verbum_head_t);
}
/* }}} */

int verbum_check_length(char *encrypted, size_t data_len) /* {{{ */
{
	if (data_len <= sizeof(verbum_head_t)) {
		return -1;
	}

	if (data_len != verbum_total_length(encrypted)) {
		return -1;
	}
	return 0;
}
/* }}} */

void * verbum_mac_data(verbum_t *encrypted) /* {{{ */
{
	verbum_head_t *head = (verbum_head_t *)encrypted;
	return (char *)encrypted + (sizeof(verbum_head_t) + head->length.key);
}
/* }}} */

void * verbum_body_data(verbum_t *encrypted) /* {{{ */
{
	verbum_head_t *head = (verbum_head_t *)encrypted;
	return (char *)encrypted + (sizeof(verbum_head_t) + head->length.key + head->length.mac);
}
/* }}} */

void * verbum_alloc(uint64_t key, uint64_t mac, uint64_t orig, uint64_t body) /* {{{ */
{
	verbum_t *encrypted = malloc(sizeof(verbum_head_t) + key + mac + body);
	verbum_head_t *head = (verbum_head_t *)encrypted;
	head->length.key = key;
	head->length.mac = mac;
	head->length.orig = orig;
	head->length.body = body;
	return encrypted;
}
/* }}} */

