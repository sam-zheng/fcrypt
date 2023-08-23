#ifndef SRC_CRYPTO_H_
#define SRC_CRYPTO_H_

typedef enum {
	CRYPTO,
	TINYAES
} type;

typedef struct {
	void *impl;
	void *(*ctx_new)();
	int (*ctx_free)(void *ctx);
	const void *(*cipher)();
	struct {
		int (*init)(void *ctx, const void *cipher, const unsigned char *key, const unsigned char *iv);
		int (*update)(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
		int (*final)(void *ctx, unsigned char *out, int *outl);
	} enc, dec;
	type type;
} cipher;

void crypto_init();

void crypto_uninit();

cipher *aes();

#endif /* SRC_CRYPTO_H_ */
