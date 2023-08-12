#ifndef SRC_CRYPTO_H_
#define SRC_CRYPTO_H_

typedef struct {
	void *(*ctx_new)();
	int (*ctx_free)(void *ctx);
	const void *(*cipher)();
	struct {
		int (*init)(void *ctx, const void *cipher, const unsigned char *key, const unsigned char *iv);
		int (*update)(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
		int (*final)(void *ctx, unsigned char *out, int *outl);
	} enc, dec;

} cipher;

cipher aes();

#endif /* SRC_CRYPTO_H_ */
