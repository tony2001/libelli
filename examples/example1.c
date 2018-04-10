#include "elli.h"

int main()
{
	char *priv_key = "3c68dabe0503675301426bbc6a27";
	//char *wrong_priv_key = "00d0173b1bd0ac0640a4087417c10a";
	char *pub_key = "04354854411b55dc7b7f5b5fbf45433ce7ced5950305ede546fead71f5";
	elli_ctx_t *ctx;
	verbum_t *encrypted_data;
	unsigned char *dec_data;
	size_t dec_data_len;
	char *err_str;

	ctx = elli_ctx_create("secp112r1", &err_str);
	if (!ctx) {
		printf("Failed to initialize elli context. Error: %s\n", err_str);
		return -1;
	}

	encrypted_data = elli_encrypt(ctx, pub_key, (unsigned char *)"test", sizeof("test") - 1);
	if (!encrypted_data) {
		printf("Failed to encrypt data. Error: %s\n", elli_ctx_last_error(ctx));
		elli_ctx_free(ctx);
		return -1;
	}

	dec_data = elli_decrypt(ctx, priv_key, encrypted_data, &dec_data_len);
	if (dec_data) {
		printf("%s\n", dec_data);
		free(dec_data);
	} else {
		printf("Failed to decode data. Error: %s\n", elli_ctx_last_error(ctx));
	}

	free(encrypted_data);
	elli_ctx_free(ctx);
	return 0;
}
