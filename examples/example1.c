#include "elli.h"

int main()
{
	char *priv_key = "3c68dabe0503675301426bbc6a27";
	char *pub_key = "04354854411b55dc7b7f5b5fbf45433ce7ced5950305ede546fead71f5";
	elli_ctx_t *ctx;
	verbum_t *encrypted_data;
	unsigned char *dec_data;
	size_t dec_data_len;

	ctx = elli_ctx_create();
	encrypted_data = elli_encrypt(ctx, pub_key, (unsigned char *)"test", sizeof("test") - 1);

	dec_data = elli_decrypt(ctx, priv_key, encrypted_data, &dec_data_len);
	if (dec_data) {	
		printf("%s\n", dec_data);
	} else {
		printf("failed to decode data\n", dec_data);
	}

	free(encrypted_data);
	elli_ctx_free(ctx);
	return 0;
}
