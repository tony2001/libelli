#include <sys/time.h>
#include "elli.h"

typedef struct {
	char *curve_name;
	char *private_key;
	char *public_key;
} bench_key_t;

bench_key_t keys[] = 
{
#include "keys/keys.h"
};

char data[] = "Elliptic curve cryptography (ECC) is an approach to public-key cryptography based on the algebraic structure of elliptic curves over finite fields.";

#define REPEAT 1000
#define tv_to_double(tv) (tv)->tv_sec + (tv)->tv_usec / 1000000.00

int main()
{
	elli_ctx_t *ctx;
	char *encrypted_data;
	char *dec_data;
	size_t dec_data_len, data_len;
	int i, j;
	double start, end;
	struct timeval tv;

	data_len = strlen(data);

	for (i = 0; i < sizeof(keys)/sizeof(bench_key_t); i++) {
		bench_key_t *key = keys + i;

		ctx = elli_ctx_create(key->curve_name, NULL);

		if (!ctx) {
			printf ("curve '%s' not found, skipping..\n", key->curve_name);
			continue;
		}

		encrypted_data = elli_encrypt(ctx, key->public_key, data, &data_len);
		printf("%s (%zd bytes)\n", key->curve_name, data_len);
		free(encrypted_data);
		
		printf("  encrypting %d times\n", REPEAT);

		gettimeofday(&tv, NULL);
		start = tv_to_double(&tv);

		for (j = 0; j < REPEAT; j++) {
			data_len = strlen(data);
			encrypted_data = elli_encrypt(ctx, key->public_key, data, &data_len);
			free(encrypted_data);
		}
		gettimeofday(&tv, NULL);
		end = tv_to_double(&tv);
		printf("    %.4f sec\n", end - start);
		
		printf("  decrypting %d times\n", REPEAT);

		encrypted_data = elli_encrypt(ctx, key->public_key, data, &data_len);
		
		gettimeofday(&tv, NULL);
		start = tv_to_double(&tv);
		
		for (j = 0; j < REPEAT; j++) {
			dec_data_len = data_len;
			dec_data = elli_decrypt(ctx, key->private_key, encrypted_data, &dec_data_len);
			free(dec_data);
		}
		gettimeofday(&tv, NULL);
		end = tv_to_double(&tv);
		printf("    %.4f sec\n", end - start);

		free(encrypted_data);

		elli_ctx_free(ctx);
	}
	return 0;
}
