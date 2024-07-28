#include <dlfcn.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "aes.h"
#include "crypto.h"

typedef EVP_CIPHER_CTX *f_EVP_CIPHER_CTX_new(void);
typedef void f_EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);

typedef const EVP_CIPHER *f_EVP_aes_128_cbc(void);

typedef int f_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
        const EVP_CIPHER *cipher, ENGINE *impl,
        const unsigned char *key,
        const unsigned char *iv);
typedef int f_EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
        const EVP_CIPHER *cipher, ENGINE *impl,
        const unsigned char *key,
        const unsigned char *iv);

typedef int f_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
typedef int f_EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);

typedef int f_EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
        int *outl);
typedef int f_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                   int *outl);

typedef void f_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);

typedef struct AES_ctx AES_ctx;
static void *aes_ctx_new() {
	void *p = malloc(sizeof(AES_ctx));
	if (!p) {
		fprintf(stderr, "out of memory");
		fflush(stderr);
		exit(ENOMEM);
	}
	return (AES_ctx*)p;
}

static int aes_init(void *ctx, const void *cipher, const unsigned char *key, const unsigned char *iv) {
	AES_ctx *c = (AES_ctx *)ctx;
	AES_init_ctx_iv(c, (uint8_t*)key, (uint8_t*)iv);
	return 0;
}

static int aes_enc_update(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
	memcpy(out, in, inl);
	AES_CBC_encrypt_buffer((AES_ctx *)ctx, out, inl);
	*outl = inl;
	return inl;
}

static int aes_dec_update(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
	memcpy(out, in, inl);
	AES_CBC_decrypt_buffer((AES_ctx *)ctx, out, inl);
	*outl = inl;
	return inl;
}

static int aes_ctx_free(void *ctx) {
	if (ctx) {
		free(ctx);
	}
	return 0;
}

f_EVP_CIPHER_CTX_new   *ctx_new;
f_EVP_aes_128_cbc      *cbc;
f_EVP_CIPHER_CTX_free  *ctx_free;

f_EVP_EncryptInit_ex   *init;
f_EVP_EncryptUpdate    *update;
f_EVP_EncryptFinal_ex  *final;

f_EVP_DecryptInit_ex   *dinit;
f_EVP_DecryptUpdate    *dupdate;
f_EVP_DecryptFinal_ex  *dfinal;

f_EVP_CIPHER_CTX_set_flags *set_flags;


static int crypto_enc_init(void *ctx, const void *cipher, const unsigned char *key, const unsigned char *iv) {
	set_flags(ctx, EVP_CIPH_NO_PADDING);
	return init(ctx, cipher, NULL, key, iv);
}

static int crypto_dec_init(void *ctx, const void *cipher, const unsigned char *key, const unsigned char *iv) {
	set_flags(ctx, EVP_CIPH_NO_PADDING);
	return dinit(ctx, cipher, NULL, key, iv);
}

static cipher *_cipher = (void *)0;

void crypto_init() {
	if (_cipher) {
		return;
	}
	_cipher = malloc(sizeof(cipher));
	memset(_cipher, 0, sizeof(*_cipher));
	void *p = dlopen("libcrypto.so", RTLD_NOW | RTLD_LOCAL);
	if (!p) {
		// no openssl, try tinyAES
		_cipher->ctx_new = aes_ctx_new;
		_cipher->ctx_free = aes_ctx_free;
		_cipher->enc.init = aes_init;
		_cipher->enc.update = aes_enc_update;

		_cipher->dec.init = aes_init;
		_cipher->dec.update = aes_dec_update;
		_cipher->impl = (void *)0;
		_cipher->type = TINYAES;
		return;
	}


	ctx_new  = dlsym(p, "EVP_CIPHER_CTX_new");
	set_flags = dlsym(p, "EVP_CIPHER_CTX_set_flags");
	cbc      = dlsym(p, "EVP_aes_128_cbc");
	ctx_free = dlsym(p, "EVP_CIPHER_CTX_free");

	init     = dlsym(p, "EVP_EncryptInit_ex");
	update   = dlsym(p, "EVP_EncryptUpdate");
	final    = dlsym(p, "EVP_EncryptFinal_ex");

	dinit    = dlsym(p, "EVP_DecryptInit_ex");
	dupdate  = dlsym(p, "EVP_DecryptUpdate");
	dfinal   = dlsym(p, "EVP_DecryptFinal_ex");

	_cipher->ctx_new = ctx_new;
	_cipher->ctx_free = ctx_free;
	_cipher->cipher = cbc;

	_cipher->enc.init = crypto_enc_init;
	_cipher->enc.update = update;
	_cipher->enc.final = final;

	_cipher->dec.init = crypto_dec_init;
	_cipher->dec.update = dupdate;
	_cipher->dec.final = dfinal;
	_cipher->impl = p;
	_cipher->type = CRYPTO;
}

void crypto_uninit() {
	if (_cipher && _cipher->type == CRYPTO && _cipher->impl) {
		dlclose(_cipher->impl);
	}
}

cipher *aes() {
	return _cipher;
}



