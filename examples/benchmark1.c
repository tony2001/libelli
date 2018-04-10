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
	verbum_t *encrypted_data;
	unsigned char *dec_data;
	size_t dec_data_len;
	int i, j, data_len;
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

		encrypted_data = elli_encrypt(ctx, key->public_key, (unsigned char *)data, data_len);
		printf("%s (%d bytes)\n", key->curve_name, verbum_total_length(encrypted_data));
		free(encrypted_data);
		
		printf("  encrypting %d times\n", REPEAT);

		gettimeofday(&tv, NULL);
		start = tv_to_double(&tv);

		for (j = 0; j < REPEAT; j++) {
			encrypted_data = elli_encrypt(ctx, key->public_key, (unsigned char *)data, data_len);
			free(encrypted_data);
		}
		gettimeofday(&tv, NULL);
		end = tv_to_double(&tv);
		printf("    %.4f sec\n", end - start);
		
		printf("  decrypting %d times\n", REPEAT);

		encrypted_data = elli_encrypt(ctx, key->public_key, (unsigned char *)data, data_len);
		
		gettimeofday(&tv, NULL);
		start = tv_to_double(&tv);
		
		for (j = 0; j < REPEAT; j++) {
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
