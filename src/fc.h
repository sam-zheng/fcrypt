#ifndef SRC_FC_H_
#define SRC_FC_H_

#include "aes.h"
#include "work.h"
#include "output.h"

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
	struct AES_ctx *ctx;
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

#endif /* SRC_FC_H_ */
