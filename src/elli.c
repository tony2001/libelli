#include "elli_internal.h"

static inline void *elli_key_derivation(const void *input, size_t ilen, void *output, size_t *olen) /* {{{ */
{
	if (*olen < SHA512_DIGEST_LENGTH) {
		return NULL;
	}
	
	*olen = SHA512_DIGEST_LENGTH;
	return SHA512(input, ilen, output);
}
/* }}} */

elli_ctx_t *elli_ctx_create() /* {{{ */
{
	elli_ctx_internal_t *int_ctx;

	int_ctx = calloc(1, sizeof(*int_ctx));
	int_ctx->curve_type = ECIES_CURVE;
	int_ctx->cipher = ECIES_CIPHER;
	int_ctx->hasher = ECIES_HASHER;
	elli_group_init(int_ctx);
	return (elli_ctx_t *)int_ctx;
}
/* }}} */

char *elli_ctx_last_error(elli_ctx_t *ctx) /* {{{ */
{
	elli_ctx_internal_t *int_ctx = (elli_ctx_internal_t *)ctx;

	return int_ctx->last_error;
}
/* }}} */

void elli_ctx_free(elli_ctx_t *ctx) /* {{{ */
{
	elli_ctx_internal_t *int_ctx = (elli_ctx_internal_t *)ctx;

	if (int_ctx->elliptic) {
		EC_GROUP_free(int_ctx->elliptic);
	}
	free(int_ctx);
}
/* }}} */

verbum_t *elli_encrypt(elli_ctx_t *ctx, char *key, unsigned char *data, size_t length) /* {{{ */
{
	void *body;
	HMAC_CTX hmac;
	int body_length;
	verbum_t *encrypted;
	EVP_CIPHER_CTX cipher;
	unsigned int mac_length;
	EC_KEY *user, *ephemeral;
	size_t envelope_length, block_length, key_length;
	unsigned char envelope_key[SHA512_DIGEST_LENGTH], iv[EVP_MAX_IV_LENGTH], block[EVP_MAX_BLOCK_LENGTH];
	elli_ctx_internal_t *int_ctx = (elli_ctx_internal_t *)ctx;

	// Simple sanity check.
	if (!key || !data || !length) {
		printf("Invalid parameters passed in.\n");
		return NULL;
	}

	// Make sure we are generating enough key material for the symmetric ciphers.
	if ((key_length = EVP_CIPHER_key_length(ECIES_CIPHER)) * 2 > SHA512_DIGEST_LENGTH) {
		printf("The key derivation method will not produce enough envelope key material for the chosen ciphers. {envelope = %i / required = %zu}", SHA512_DIGEST_LENGTH / 8,
				(key_length * 2) / 8);
		return NULL;
	}

	// Convert the user's public key from hex into a full EC_KEY structure.
	if (!(user = elli_key_create_public_hex(int_ctx, key))) {
		printf("Invalid public key provided.\n");
		return NULL;
	}

	// Create the ephemeral key used specifically for this block of data.
	else if (!(ephemeral = elli_key_create(int_ctx))) {
		printf("An error occurred while trying to generate the ephemeral key.\n");
		EC_KEY_free(user);
		return NULL;
	}

	// Use the intersection of the provided keys to generate the envelope data used by the ciphers below. The elli_key_derivation() function uses
	// SHA 512 to ensure we have a sufficient amount of envelope key material and that the material created is sufficiently secure.
	else if (ECDH_compute_key(envelope_key, SHA512_DIGEST_LENGTH, EC_KEY_get0_public_key(user), ephemeral, elli_key_derivation) !=
			SHA512_DIGEST_LENGTH) {
		printf("An error occurred while trying to compute the envelope key. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(ephemeral);
		EC_KEY_free(user);
		return NULL;
	}

	// Determine the envelope and block lengths so we can allocate a buffer for the result.
	else if ((block_length = EVP_CIPHER_block_size(ECIES_CIPHER)) == 0 || block_length > EVP_MAX_BLOCK_LENGTH ||
			(envelope_length = EC_POINT_point2oct(EC_KEY_get0_group(ephemeral), EC_KEY_get0_public_key(ephemeral),
												  POINT_CONVERSION_COMPRESSED, NULL, 0, NULL)) == 0) {
		printf("Invalid block or envelope length. {block = %zu /envelope = %zu}\n", block_length, envelope_length);
		EC_KEY_free(ephemeral);
		EC_KEY_free(user);
		return NULL;
	}

	// We use a conditional to pad the length if the input buffer is notevenly divisible by the block size.
	else if (!(encrypted = verbum_alloc(envelope_length, EVP_MD_size(ECIES_HASHER), length, length + (length % block_length ? (block_length - (length % block_length)) : 0)))) {
		printf("Unable to allocate a verbum_t buffer to hold the encrypted result.\n");
		EC_KEY_free(ephemeral);
		EC_KEY_free(user);
		return NULL;
	}

	// Store the public key portion of the ephemeral key.
	else if (EC_POINT_point2oct(EC_KEY_get0_group(ephemeral), EC_KEY_get0_public_key(ephemeral), POINT_CONVERSION_COMPRESSED, verbum_key_data(encrypted), envelope_length,                        NULL) != envelope_length) {
		printf("An error occurred while trying to record the public portion of the envelope key. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(ephemeral);
		EC_KEY_free(user);
		free(encrypted);
		return NULL;
	}

	// The envelope key has been stored so we no longer need to keep the keys around.
	EC_KEY_free(ephemeral);
	EC_KEY_free(user);

	// For now we use an empty initialization vector.
	memset(iv, 0, EVP_MAX_IV_LENGTH);

	// Setup the cipher context, the body length, and store a pointer to the body buffer location.
	EVP_CIPHER_CTX_init(&cipher);
	body = verbum_body_data(encrypted);
	body_length = verbum_body_length(encrypted);

	// Initialize the cipher with the envelope key.
	if (EVP_EncryptInit_ex(&cipher, ECIES_CIPHER, NULL, envelope_key, iv) != 1 || EVP_CIPHER_CTX_set_padding(&cipher, 0) != 1 || EVP_EncryptUpdate(&cipher, body,                        &body_length, data, length - (length % block_length)) != 1) {
		printf("An error occurred while trying to secure the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_cleanup(&cipher);
		free(encrypted);
		return NULL;
	}

	// Check whether all of the data was encrypted. If they don't match up, we either have a partial block remaining, or an error occurred.
	else if (body_length != length) {

		// Make sure all that remains is a partial block, and their wasn't an error.
		if (length - body_length >= block_length) {
			printf("Unable to secure the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
			EVP_CIPHER_CTX_cleanup(&cipher);
			free(encrypted);
			return NULL;
		}

		// Copy the remaining data into our partial block buffer. The memset() call ensures any extra bytes will be zero'ed out.
		memset(block, 0, EVP_MAX_BLOCK_LENGTH);
		memcpy(block, data + body_length, length - body_length);

		// Advance the body pointer to the location of the remaining space, and calculate just how much room is still available.
		body += body_length;
		if ((body_length = verbum_body_length(encrypted) - body_length) < 0) {
			printf("The symmetric cipher overflowed!\n");
			EVP_CIPHER_CTX_cleanup(&cipher);
			free(encrypted);
			return NULL;
		}

		// Pass the final partially filled data block into the cipher as a complete block. The padding will be removed during the decryption process.
		else if (EVP_EncryptUpdate(&cipher, body, &body_length, block, block_length) != 1) {
			printf("Unable to secure the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
			EVP_CIPHER_CTX_cleanup(&cipher);
			free(encrypted);
			return NULL;
		}
	}

	// Advance the pointer, then use pointer arithmetic to calculate how much of the body buffer has been used. The complex logic is needed so that we get
	// the correct status regardless of whether there was a partial data block.
	body += body_length;
	if ((body_length = verbum_body_length(encrypted) - (body - verbum_body_data(encrypted))) < 0) {
		printf("The symmetric cipher overflowed!\n");
		EVP_CIPHER_CTX_cleanup(&cipher);
		free(encrypted);
		return NULL;
	}

	else if (EVP_EncryptFinal_ex(&cipher, body, &body_length) != 1) {
		printf("Unable to secure the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_cleanup(&cipher);
		free(encrypted);
		return NULL;
	}

	EVP_CIPHER_CTX_cleanup(&cipher);

	// Generate an authenticated hash which can be used to validate the data during decryption.
	HMAC_CTX_init(&hmac);
	mac_length = verbum_mac_length(encrypted);

	// At the moment we are generating the hash using encrypted data. At some point we may want to validate the original text instead.
	if (HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ECIES_HASHER, NULL) != 1 || HMAC_Update(&hmac, verbum_body_data(encrypted), verbum_body_length(encrypted))
			!= 1 || HMAC_Final(&hmac, verbum_mac_data(encrypted), &mac_length) != 1) {
		printf("Unable to generate a data authentication code. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
		HMAC_CTX_cleanup(&hmac);
		free(encrypted);
		return NULL;
	}

	HMAC_CTX_cleanup(&hmac);

	return encrypted;
}
/* }}} */

unsigned char *elli_decrypt(elli_ctx_t *ctx, char *key, verbum_t *encrypted, size_t *length)  /* {{{ */
{
	
	HMAC_CTX hmac;
	size_t key_length;
	int output_length;
	EVP_CIPHER_CTX cipher;
	EC_KEY *user, *ephemeral;
	unsigned int mac_length = EVP_MAX_MD_SIZE;
	unsigned char envelope_key[SHA512_DIGEST_LENGTH], iv[EVP_MAX_IV_LENGTH], md[EVP_MAX_MD_SIZE], *block, *output;
	elli_ctx_internal_t *int_ctx = (elli_ctx_internal_t *)ctx;
	
	// Simple sanity check.
	if (!key || !encrypted || !length) {
		printf("Invalid parameters passed in.\n");
		return NULL;
	}
	
	// Make sure we are generating enough key material for the symmetric ciphers.
	else if ((key_length = EVP_CIPHER_key_length(ECIES_CIPHER)) * 2 > SHA512_DIGEST_LENGTH) {
		printf("The key derivation method will not produce enough envelope key material for the chosen ciphers. {envelope = %i / required = %zu}", SHA512_DIGEST_LENGTH / 8, (key_length * 2) / 8);
		return NULL;
	}
	
	// Convert the user's public key from hex into a full EC_KEY structure.
	else if (!(user = elli_key_create_private_hex(int_ctx, key))) {
		printf("Invalid private key provided.\n");
		return NULL;
	}
	
	// Create the ephemeral key used specifically for this block of data.
	else if (!(ephemeral = elli_key_create_public_octets(int_ctx, verbum_key_data(encrypted), verbum_key_length(encrypted)))) {
		printf("An error occurred while trying to recreate the ephemeral key.\n");
		EC_KEY_free(user);
		return NULL;
	}
	
	// Use the intersection of the provided keys to generate the envelope data used by the ciphers below. The elli_key_derivation() function uses
	// SHA 512 to ensure we have a sufficient amount of envelope key material and that the material created is sufficiently secure.
	else if (ECDH_compute_key(envelope_key, SHA512_DIGEST_LENGTH, EC_KEY_get0_public_key(ephemeral), user, elli_key_derivation) != SHA512_DIGEST_LENGTH) {
		printf("An error occurred while trying to compute the envelope key. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(ephemeral);
		EC_KEY_free(user);
		return NULL;
	}
	
	// The envelope key material has been extracted, so we no longer need the user and ephemeral keys.
	EC_KEY_free(ephemeral);
	EC_KEY_free(user);
	
	// Use the authenticated hash of the ciphered data to ensure it was not modified after being encrypted.
	HMAC_CTX_init(&hmac);
	
	// At the moment we are generating the hash using encrypted data. At some point we may want to validate the original text instead.
	if (HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ECIES_HASHER, NULL) != 1 || HMAC_Update(&hmac, verbum_body_data(encrypted),
																										   verbum_body_length(encrypted))
		!= 1 || HMAC_Final(&hmac, md, &mac_length) != 1) {
		printf("Unable to generate the authentication code needed for validation. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
		HMAC_CTX_cleanup(&hmac);
		return NULL;
	}
	
	HMAC_CTX_cleanup(&hmac);
	
	// We can use the generated hash to ensure the encrypted data was not altered after being encrypted.
	if (mac_length != verbum_mac_length(encrypted) || memcmp(md,
														   verbum_mac_data(encrypted), mac_length)) {
		printf("The authentication code was invalid! The ciphered data has been corrupted!\n");
		return NULL;
	}
	
	// Create a buffer to hold the result.
	output_length = verbum_body_length(encrypted);
	if (!(block = output = malloc(output_length + 1))) {
		printf("An error occurred while trying to allocate memory for the decrypted data.\n");
		return NULL;
	}
	
	// For now we use an empty initialization vector. We also clear out the result buffer just to be on the safe side.
	memset(iv, 0, EVP_MAX_IV_LENGTH);
	memset(output, 0, output_length + 1);
	
	EVP_CIPHER_CTX_init(&cipher);
	
	// Decrypt the data using the chosen symmetric cipher.
	if (EVP_DecryptInit_ex(&cipher, ECIES_CIPHER, NULL, envelope_key, iv)
		!= 1 || EVP_CIPHER_CTX_set_padding(&cipher, 0) != 1 ||
		EVP_DecryptUpdate(&cipher, block,
						  &output_length, verbum_body_data(encrypted),
						  verbum_body_length(encrypted)) != 1) {
			printf("Unable to decrypt the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
			EVP_CIPHER_CTX_cleanup(&cipher);
			free(output);
			return NULL;
        }
	
	block += output_length;
	if ((output_length = verbum_body_length(encrypted) - output_length) != 0)
	{
		printf("The symmetric cipher failed to properly decrypt the correct amount of data!\n");
		EVP_CIPHER_CTX_cleanup(&cipher);
		free(output);
		return NULL;
	}
	
	if (EVP_DecryptFinal_ex(&cipher, block, &output_length) != 1) {
		printf("Unable to decrypt the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_cleanup(&cipher);
		free(output);
		return NULL;
	}
	
	EVP_CIPHER_CTX_cleanup(&cipher);
	
	*length = verbum_orig_length(encrypted);
	return output;
}
/* }}} */

