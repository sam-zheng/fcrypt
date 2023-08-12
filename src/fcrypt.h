#ifndef SRC_FCRYPT_H_
#define SRC_FCRYPT_H_
#include <openssl/evp.h>

#include "aes.h"
#include "work.h"
#include "output.h"
#include "crypto.h"

#define VERSION 0
#define ID "FC"
#define SUFFIX ".fc"
#define ENOFILE 1
#define EMKFILE 2
#define ERDFILE 3
#define EWRFILE 4
#define EPASS 5

#define min(a, b) (a) < (b) ? (a) : (b)

#define PASS_MAX 64

typedef EVP_CIPHER_CTX *f_EVP_CIPHER_CTX_new(void);
typedef int f_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
        const EVP_CIPHER *cipher, ENGINE *impl,
        const unsigned char *key,
        const unsigned char *iv);
typedef int f_EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
        const EVP_CIPHER *cipher, ENGINE *impl,
        const unsigned char *key,
        const unsigned char *iv);

typedef const EVP_CIPHER *f_EVP_aes_128_cbc(void);

typedef int f_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
typedef int f_EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
typedef int f_EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
        int *outl);
typedef int f_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                   int *outl);

typedef void f_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);

typedef struct header {
	char id[2];
	uint16_t version;
	uint32_t reserved; // alignment, reserved for future use
	uint8_t salt[AES_BLOCKLEN];
	uint64_t size;
	uint8_t sum[AES_BLOCKLEN]; // encrypted sum of fields above
} header;

typedef struct progress {
	void (*progress)(struct progress *c, float p);
	void (*done)(struct progress *c);
} progress;

typedef struct ctx {
	FILE *f;
	char *name;
	char *out;
	char salt[AES_BLOCKLEN];
	cipher cipher;
	uint8_t key[AES_BLOCKLEN];
	int enc;
	char buf[sizeof(header)];
	int buf_pos;
	size_t buf_len;
	char password[PASS_MAX];
	progress progress;
	size_t size;
	work_pool *wp;
	struct out_man *om;
	struct out *output;
	int remove_origin;
	void *x;
} ctx;

typedef struct _work {
	ctx *c;
	char *file;
	void *extra;
} cryptwork;

void fcrypt(ctx *c);

inline void *malloc_e(size_t n) {
	void *p = malloc(n);
	if (!p) {
		fprintf(stderr, "out of memory");
		fflush(stderr);
		exit(ENOMEM);
	}
	return p;
}

#endif /* SRC_FCRYPT_H_ */
