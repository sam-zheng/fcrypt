#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <crypt.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <linux/limits.h>
#include <ctype.h>
//#include <pthread.h>
#include <stdint.h>

#include "crc.h"
#include "aes.h"

#define VERSION 0
#define ID "FC"
#define SUFFIX ".fc"
#define ENOFILE 1
#define EMKFILE 2
#define ERDFILE 3
#define EWRFILE 4
#define EPASS 5

typedef struct header {
	char id[2];
	uint16_t version;
	uint32_t reserved; // alignment, reserved for future use
	uint8_t salt[AES_BLOCKLEN];
	uint64_t size;
	uint8_t sum[AES_BLOCKLEN]; // encrypted sum of fields above
} header;

static inline size_t min(size_t a, size_t b) {
	return a < b ? a : b;
}

// ./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
// https://en.wikipedia.org/wiki/Crypt_(C)
const char b64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#define PASS_MAX 64

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
	void (*progress)(float progress);
} ctx;

// forward declaration
static int rr64(char c);
static void r64(unsigned char *p, int pn, unsigned char* r, int rn);
static void derive_key(unsigned char *p, int pn, unsigned char *k, int kn);
static int read_from_ctx(ctx *c, char *b, size_t n);
static int read_file(FILE *f, char *name, char *b, size_t n);
static void encrypt_sum(header *h, ctx *ctx, uint8_t *sum);
static int check_sum(header *h, ctx *ctx);
static uint32_t decrypt_sum(header *h, ctx *ctx);
static void _write(char *b, size_t n, FILE *f, char *name);
static FILE *create_file(char *name);
static void encrypt(ctx *c);
static int do_dir(ctx *ctx, char *dir);
static int do_file(ctx *ctx, char *file);
static void *malloc_e(size_t n);
static int _feof(ctx *c);
static int next_block(ctx *c, char *b, int pad);
static int do_filep(ctx *c, FILE *fp, char *file);

static void r64(unsigned char *p, int pn, unsigned char* r, int rn) {
	assert(pn / 3 * 4 == rn);
	for (int i =0, j = 0; i < pn; i+=3, j+=4) {
		r[j] = b64[p[i] >>2];
		r[j+1] = b64[(p[i] & 3) << 4 | p[i+1] >> 4];
		r[j+2] = b64[(p[i+1] & 0xf) << 2 | p[i+2] >> 6];
		r[j+3] = b64[p[i+2] & 63];
	}

}
static int rr64(char c) {
	switch (c) {
	case '.':
		return 0;
	case '/':
		return 1;
	default:
		if (c >= '0' && c <= '9') {
			return 2 + c - '0';
		}
		if (c >= 'A' && c <= 'Z') {
			return 2 + 10 + c - 'A';
		}
		if (c >= 'a' && c <= 'z') {
			return 2 + 10 + 26 + c - 'a';
		}
	}
	exit(0xff);
}

static void derive_key(unsigned char *p, int pn, unsigned char *k, int kn) {
	assert(pn / 4 * 3 == kn);
	for (int i = 0, j = 0; i < pn; i += 4, j += 3) {
		k[j] = rr64(p[i]) << 2 | rr64(p[i+1]) >> 4;
		k[j+1] = (rr64(p[i+1]) & 0xf) << 4 | rr64(p[i+2]) >> 2;
		k[j+2] = (rr64(p[i+2]) & 3) << 6 | rr64(p[i+3]);
	}
}


static void usage() {
	fprintf(stdout, "Usage:\n"
			"	fc [options] <file> ...\n"
			"	-h show this help message\n"
			"	-o specifies output file, only makes sense for single file\n"
			"	-e encrypt\n"
			"	-d decrypt\n"
			"	in case of no option, perform decryption if the file was an encrypted file, otherwise encrypt\n"
	);
}

static int read_from_ctx(ctx *c, char *b, size_t n) {
	int r = 0;
	if (c->buf_len > 0) {
		size_t l = min(c->buf_len, n);
		memcpy(b, c->buf + c->buf_pos, l);
		c->buf_len -= l;
		c->buf_pos += l;
		n -= l;
		r += l;
		b += l;
	}
	if (n > 0 && !feof(c->f)) {
		r += read_file(c->f, c->name, b, n);
	}
	return r;
}

static int read_file(FILE *f, char *name, char *b, size_t n) {
	int r = fread(b, 1, n, f);
	if (ferror(f)) {
		fprintf(stderr, "error reading file: %s\n", name);
		exit(ERDFILE);
	}
	return r;
}


static int next_block(ctx *c, char *b, int pad) {
	int n = -2;
	while (1) {
		if (ferror(c->f)) {
			return -1;
		}
		if (n > 0 || _feof(c)) {
			break;
		}
		n = read_from_ctx(c, b, AES_BLOCKLEN);
	}
	if (pad && n >= 0 && n < AES_BLOCKLEN) { // pad
		char d = (char)(AES_BLOCKLEN - n);
		for (int i = n; i < AES_BLOCKLEN; i++) {
			b[i] = d;
		}
		n = AES_BLOCKLEN;
	}
	return n;

}

static void _write(char *b, size_t n, FILE *f, char *name) {
	if (fwrite(b, 1, n, f) < n) {
		fprintf(stderr, "errir writting file: %s\n", name);
		exit(EWRFILE);
	}
}

static FILE *create_file(char *name) {
	if (!access(name, F_OK)) {
		fprintf(stderr, "file already exists: %s\n", name);
		exit(EMKFILE);
	}
	FILE *f = fopen(name, "w+");
	if (!f) {
		fprintf(stderr, "error creating file: %s\n", name);
		exit(EMKFILE);
	}
	return f;
}

static void encrypt_sum(header *h, ctx *ctx, uint8_t *sum) {
	uint32_t s = calc_crc((char*)h, offsetof(header, sum));
	uint8_t b[AES_BLOCKLEN];
	*(uint32_t *)b = s;
	memset(b + sizeof(s), 0, AES_BLOCKLEN - sizeof(s));
	struct AES_ctx c;
	memset(&c, 0, sizeof(c));
	AES_init_ctx_iv(&c, ctx->key, (uint8_t *)ctx->salt);
	AES_CBC_encrypt_buffer(&c, b, sizeof(b));
	memcpy(sum, b, AES_BLOCKLEN);
}

static uint32_t decrypt_sum(header *h, ctx *ctx) {
	struct AES_ctx c;
	memset(&c, 0, sizeof(c));
	AES_init_ctx_iv(&c, ctx->key, (uint8_t *)ctx->salt);
	char b[sizeof(h->sum)];
	memcpy(b, h->sum, sizeof(b));
	AES_CBC_decrypt_buffer(&c, (uint8_t *)b, sizeof(h->sum));
	return *(uint32_t *)b;
}

static int check_sum(header *h, ctx *ctx) {
	uint32_t s = calc_crc((char*)h, offsetof(header, sum));
	uint32_t d = decrypt_sum(h, ctx);
	return s == d;
}

static void *malloc_e(size_t n) {
	void *p = malloc(n);
	if (!p) {
		fprintf(stderr, "out of memory");
		exit(33);
	}
	return p;
}

static void encrypt(ctx *c) {
	char *name = c->out;
	int namealloc = 0;
	if (!name) {
		int nl = strlen(c->name);
		int sl = strlen(SUFFIX);
		name = malloc_e(nl + sl + 1);
		memcpy(name, c->name, nl);
		memcpy(name + nl, SUFFIX, sl);
		name[nl + sl] = '\0';
		namealloc = 1;
	}
	FILE *fout = create_file(name);
	char b[AES_BLOCKLEN];
	int r;
	header h;
	memset(&h, 0, sizeof(h));
	memcpy(h.id, ID, sizeof(h.id));
	memcpy(h.salt, c->salt, sizeof(h.salt));

	_write((char *)&h, sizeof(h), fout, name);
	int n = 0;
	while ((r = next_block(c, b, 1) > 0)) {
		AES_CBC_encrypt_buffer(c->ctx, (uint8_t *)b, r);
		_write(b, AES_BLOCKLEN, fout, name);
		n+=AES_BLOCKLEN;
	}
	if (r == -1) {
		// error
		fprintf(stderr, "errir reading file: %s\n", c->name);
		exit(EWRFILE);
	}
	h.size = n;
	encrypt_sum(&h, c, h.sum);
	fflush(fout);
	rewind(fout);
	// write header again with size and sum
	_write((char *)&h, sizeof(h), fout, name);
	fclose(fout);
	if (namealloc) {
		free(name);
	}
}

static void init_AESctx(ctx *c) {
	if (c->enc) {
		char *rd = "/dev/random";
		FILE *fp = fopen(rd, "r");
		if (!fp) {
			fprintf(stderr, "error opening %s\n", rd);
			exit(ENOFILE);
		}
		char b[12];
		size_t n = read_file(fp, rd, b, sizeof(b));
		if (n != sizeof(b)) {
			fprintf(stderr, "error reading /dev/random\n");
			exit(ERDFILE);
		}
		fclose(fp);
		r64((unsigned char *)b, sizeof(b), (unsigned char *)c->salt, sizeof(c->salt));
	}

	char salt[sizeof(c->salt) + 3 + 1];
	memcpy(salt, "$5$", 3); // sha256
	memcpy(salt + 3, c->salt, sizeof(c->salt));
	salt[sizeof(c->salt) + 3] = '\0';

	errno = 0; // clear error
	char *h = crypt(c->password, salt);
	if (errno) {
		fprintf(stderr, "error encrypting password\n");
		exit(errno);
	}

	char *a = h + 20;
	char key[18]; // only 16 bytes needed, next multiple of 3 is 18
	derive_key((unsigned char *)a, 24, (unsigned char *)key, sizeof(key));
	memcpy(c->key, key, sizeof(c->key));
	struct AES_ctx *ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "out of memory");
		exit(33);
	}
	AES_init_ctx_iv(ctx, (uint8_t *)key, (uint8_t *)c->salt);
	c->ctx = ctx;
}

static void uninit_AESctx(ctx *c) {
	if (c->ctx) {
		free(c->ctx);
	}
}

static int _feof(ctx *c) {
	return c->buf_len == 0 && feof(c->f);
}

static int end_with(char *s, char *suffix) {
	int slen = strlen(s), n = strlen(suffix);
	if (slen < n) {
		return 0;
	}
	s += (slen - n);
	for (; *s; s++, suffix++) {
		if (*s != *suffix) {
			return 0;
		}
	}
	return 1;
}

static void decrypt(ctx *c) {
	// in this case, header is already in c->buf
	header *h = (header *)c->buf;
	if (!check_sum(h, c)) {
		fprintf(stderr, "decryption failed, password not correct\n");
		exit(77);
	}
	char *name = c->out;
	int namealloc = 0;
	if (!name) {
		int nl = strlen(c->name);
		int sl = strlen(SUFFIX);
		name = malloc_e(nl + sl + 1);
		memcpy(name, c->name, nl);
		if (end_with(c->name, SUFFIX)) {
			name[strlen(c->name) - strlen(SUFFIX)] = '\0';
		} else {
			memcpy(name + nl, SUFFIX, sl);
			name[nl + sl] = '\0';
		}
		namealloc = 1;
	}
	FILE *fout = create_file(name);
	char b[AES_BLOCKLEN];
	int r;
	char last[AES_BLOCKLEN];
	int first = 1;
	while ((r = next_block(c, b, 0) > 0)) {
		AES_CBC_decrypt_buffer(c->ctx, (uint8_t*) b, r);
		if (first) {
			first = 0;
		} else {
			_write(last, AES_BLOCKLEN, fout, name);
		}
		memcpy(last, b, sizeof(b));
	}
	if (r == -1) {
		// error
		fprintf(stderr, "errir reading file: %s\n", c->name);
		exit(EWRFILE);
	}
	// remove padding
	if (last[sizeof(last) - 1] < AES_BLOCKLEN) {
		_write(last, AES_BLOCKLEN - last[sizeof(last) - 1], fout, name);
	} // else whole block was padding
	fclose(fout);
	if (namealloc) {
		free(name);
	}
}

void fcrypt(ctx *c) {
	int n = read_from_ctx(c, c->buf, sizeof(c->buf));
	header *h  = (header *)c->buf;
	if (n < sizeof(header) || strncmp(ID, h->id, sizeof(h->id))) { // not an encrypted file, to encrypt
		if (!c->enc) { // decrypt
			fprintf(stderr, "error reading header, unable to decrypt: %s", c->name);
			exit(11);
		}
		// otherwise encrypt
		c->buf_len = n;
		c->buf_pos = 0;
		c->enc = 1;
	} else { // already encrypted
		if (c->enc == 1) {
			c->buf_len = n; // let it encrpt again
			c->buf_pos = 0;
		} else {
			c->enc = 0;
			c->buf_len = 0;
			memcpy(c->salt, h->salt, sizeof(h->salt)); // salt already in c->buf
		}
	}

	init_AESctx(c);
	if (c->enc) {
		encrypt(c);
	} else {
		decrypt(c);
	}
	uninit_AESctx(c);
}

static void get_pass(ctx *c) {
	static int pass_read = 0;
	if (pass_read) {
		return;
	}
	char *p = getpass("password:");
	memcpy(c->password, p, min(sizeof(c->password), strlen(p)));
	pass_read = 1;
}

int main(int argc, char **argv) {
	FILE *f = NULL;
	ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.enc = -1; // check the file header to determine whether to encrypt or decrypt
	int c;
	while ((c = getopt(argc, argv, "hedo:")) != -1) {
		switch (c) {
		case 'h':
			usage();
			exit(0);
		case 'e': // encrypt
			ctx.enc = 1;
			break;
		case 'd': // decrypt
			ctx.enc = 0;
			break;
		case 'o':
			ctx.out = optarg;
			break;
		case '?':
			if (optopt == 'o')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return 255;
		default:
			abort();
		}
	}

	if (optind < argc) {
		for (int i = optind; i < argc; i++) {
			char *fn = argv[i];
			if (!access(fn, F_OK)) {
				struct stat st;
				if (stat(fn, &st) == -1) {
					fprintf(stderr, "unable to stat file: %s\n", fn);
					return 255;
				}
				if (S_ISREG(st.st_mode)) {
					get_pass(&ctx);
					do_file(&ctx, fn);
				} else if (S_ISDIR(st.st_mode)) {
					get_pass(&ctx);
					do_dir(&ctx, fn);
				}
			} else {
				fprintf(stderr, "file %s doesn't exist\n", argv[1]);
			}
		}
	} else {
		// stdin
		f = stdin;
		ctx.name = "_stdin_";
		ctx.out = "_stdin_.fc";
		get_pass(&ctx);
		do_filep(&ctx, f, ctx.name);
	}
}

static int do_filep(ctx *c, FILE *fp, char *file) {
	// new context for each file
	ctx cn;
	memcpy(&cn, c, sizeof(cn));
	cn.f = fp;
	cn.name = file;
	fcrypt(&cn);
	return 0;
}

static int do_file(ctx *c, char *file) {
	FILE *f = fopen(file, "r");
	if (!f) {
		fprintf(stderr, "unable to open file: %s\n", file);
		return 1;
	}
	int r = do_filep(c, f, file);
	fclose(f);
	return r;
}

static int do_dir(ctx *ctx, char *dir) {
	ctx->out = NULL; // can't specify output file for all files in a directory
	struct dirent *e;
	DIR *d;

	if ((d = opendir(dir)) == NULL) {
		fprintf(stderr, "Can't open %s\n", dir);
		return 1;
	}

	char path[1024];
	while ((e = readdir(d)) != NULL) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) {
			continue;
		}
		struct stat st;
		sprintf(path, "%s/%s", dir, e->d_name);
		if (stat(path, &st) == -1) {
			fprintf(stderr, "Unable to stat file: %s\n", path);
			continue;
		}
		if (S_ISREG(st.st_mode)) {
			do_file(ctx, path);
		} else if (S_ISDIR(st.st_mode)) {
			do_dir(ctx, path);
		} else {
			fprintf(stderr, "not a file or directory: %s\n", path);
		}

	}
	return 0;
}

