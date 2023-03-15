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
#include <pthread.h>
#include <stdint.h>
#include <termios.h>
#include <linux/futex.h>
#include <sys/time.h>

#include "crc.h"
#include "aes.h"
#include "work.h"
#include "output.h"
#include "fcrypt.h"

#define STDIN "_stdin_"

// ./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
// https://en.wikipedia.org/wiki/Crypt_(C)
const char b64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// forward declarations
static int ri64(char c);
static void r64(unsigned char *p, int pn, unsigned char* r, int rn);
static void rr64(unsigned char *p, int pn, unsigned char *k, int kn);
static int read_from_ctx(ctx *c, char *b, size_t n);
static int read_file(FILE *f, char *name, char *b, size_t n);
static void encrypt_sum(header *h, ctx *ctx, uint8_t *sum);
static int check_sum(header *h, ctx *ctx);
static uint32_t decrypt_sum(header *h, ctx *ctx);
static void _write(char *b, size_t n, FILE *f, char *name);
static FILE *create_file(ctx *c, char *name);
static void encrypt(ctx *c);
static int do_dir(ctx *ctx, char *dir);
static int do_file(ctx *ctx, char *file);
static void *malloc_e(size_t n);
static int _feof(ctx *c);
static int next_block(ctx *c, char *b, int pad);
static int do_filep(ctx *c, FILE *fp, char *file);
static void add_work(ctx *c, char *file, FILE *filep);
static int do_crypt(void *d);
static void handle_file(ctx *ctx, char* file);

static void r64(unsigned char *p, int pn, unsigned char* r, int rn) {
	assert(pn / 3 * 4 == rn);
	for (int i =0, j = 0; i < pn; i+=3, j+=4) {
		r[j] = b64[p[i] >>2];
		r[j+1] = b64[(p[i] & 3) << 4 | p[i+1] >> 4];
		r[j+2] = b64[(p[i+1] & 0xf) << 2 | p[i+2] >> 6];
		r[j+3] = b64[p[i+2] & 63];
	}

}
static int ri64(char c) {
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

static void rr64(unsigned char *p, int pn, unsigned char *k, int kn) {
	assert(pn / 4 * 3 == kn);
	for (int i = 0, j = 0; i < pn; i += 4, j += 3) {
		k[j] = ri64(p[i]) << 2 | ri64(p[i+1]) >> 4;
		k[j+1] = (ri64(p[i+1]) & 0xf) << 4 | ri64(p[i+2]) >> 2;
		k[j+2] = (ri64(p[i+2]) & 3) << 6 | ri64(p[i+3]);
	}
}


static void usage() {
	fprintf(stdout, "Usage:\n"
			"	fc [options] <file> ...\n"
			"	-h show this help message\n"
			"	-o specifies output file, only makes sense for encrypting/decrypting a single file\n"
			"	-e encrypt\n"
			"	-d decrypt\n"
			"	-r remove the original file after encrypting/decrypting it, original file is kept if this option is not present\n"
			"	-p <password>, if not present, user will be prompted to input password\n"
			"	in case of no option, perform decryption if the file was an encrypted file, otherwise encrypt\n"
	);
	exit(2);
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
		fflush(stderr);
		exit(ERDFILE);
	}
	return r;
}


static void pad_block(char *b, int n) {
	char d = (char)(AES_BLOCKLEN - n);
	for (int i = n; i < AES_BLOCKLEN; i++) {
		b[i] = d;
	}
}

static int next_block(ctx *c, char *b, int pad) {
	long x = (long)c->x;
	if (x == 1) { // last block was returned
		return -1;
	}
	if (ferror(c->f)) {
		return -2;
	}
	int n = 0;
	if (!_feof(c)) {
		n = read_from_ctx(c, b, AES_BLOCKLEN);
	}

//	int n = -2;
//	while (1) {
//		if (ferror(c->f)) {
//			return -1;
//		}
//		if (n > 0 || _feof(c)) {
//			break;
//		}
//		n = read_from_ctx(c, b, AES_BLOCKLEN);
//	}
	if (pad && n >= 0 && n < AES_BLOCKLEN) { // pad
		pad_block(b, n);
//		char d = (char)(AES_BLOCKLEN - n);
//		for (int i = n; i < AES_BLOCKLEN; i++) {
//			b[i] = d;
//		}
		n = AES_BLOCKLEN;
		c->x = (void *)1;
	}
	return n;

}

static void _write(char *b, size_t n, FILE *f, char *name) {
	if (fwrite(b, 1, n, f) < n) {
		fprintf(stderr, "errir writting file: %s\n", name);
		fflush(stderr);
		exit(EWRFILE);
	}
}

static FILE *create_file(ctx *c, char *name) {
	if (!access(name, F_OK)) {
		output(c->output, "file already exists: %s\n", name);
		return NULL;
	}
	FILE *f = fopen(name, "w+");
	if (!f) {
		output(c->output, "error creating file: %s\n", name);
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
		fflush(stderr);
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
	FILE *fout = create_file(c, name);
	if (!fout) {
		goto out;
	}
	char b[AES_BLOCKLEN];
	int r;
	header h;
	memset(&h, 0, sizeof(h));
	memcpy(h.id, ID, sizeof(h.id));
	memcpy(h.salt, c->salt, sizeof(h.salt));

	_write((char *)&h, sizeof(h), fout, name);
	int n = 0;
	float progress = 0;
	c->x = (void *)0;
	while ((r = next_block(c, b, 1) > 0)) {
		AES_CBC_encrypt_buffer(c->ctx, (uint8_t *)b, r);
		_write(b, AES_BLOCKLEN, fout, name);
		n+=AES_BLOCKLEN;
		progress = n / (float)c->size;
		if (c->progress.progress) {
			c->progress.progress(&c->progress, progress);
		}
	}

	if (r == -1) {
		// error
		fprintf(stderr, "errir reading file: %s\n", c->name);
		fflush(stderr);
		exit(EWRFILE);
	}
	h.size = n;
	encrypt_sum(&h, c, h.sum);
	fflush(fout);
	rewind(fout);
	// write header again with size and sum
	_write((char *)&h, sizeof(h), fout, name);
	fclose(fout);

	if (c->remove_origin && strncmp(STDIN, c->name, sizeof(STDIN))) {
		remove(c->name);
	}

	if (c->progress.done) {
		c->progress.done(&c->progress);
	}

out:
	if (namealloc) {
		free(name);
	}
}

static void init_AESctx(ctx *c) {
	if (c->enc) {
		char *rd = "/dev/urandom";
		FILE *fp = fopen(rd, "r");
		if (!fp) {
			fprintf(stderr, "error opening %s\n", rd);
			fflush(stderr);
			exit(ENOFILE);
		}
		char b[12];
		size_t n = read_file(fp, rd, b, sizeof(b));
		if (n != sizeof(b)) {
			fprintf(stderr, "error reading /dev/urandom\n");
			fflush(stderr);
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
	struct crypt_data cd;
	memset(&cd, 0, sizeof(cd));
	char *h = crypt_r(c->password, salt, &cd);;
	if (errno) {
		fprintf(stderr, "error encrypting password\n");
		fflush(stderr);
		exit(errno);
	}

	char *a = h + 20;
	char key[18]; // only 16 bytes needed, next multiple of 3 is 18
	rr64((unsigned char *)a, 24, (unsigned char *)key, sizeof(key));
	memcpy(c->key, key, sizeof(c->key));
	struct AES_ctx *ctx = malloc_e(sizeof(*ctx));
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
		fflush(stderr);
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
	FILE *fout = create_file(c, name);
	if (!fout) {
		goto out;
	}
	char b[AES_BLOCKLEN];
	int r;
	char last[AES_BLOCKLEN];
	int first = 1;
	size_t l = 0;
	c->x = (void *)0;
	while ((r = next_block(c, b, 0) > 0)) {
		AES_CBC_decrypt_buffer(c->ctx, (uint8_t*) b, r);
		if (first) {
			first = 0;
		} else {
			_write(last, AES_BLOCKLEN, fout, name);
		}
		memcpy(last, b, sizeof(b));
		l += AES_BLOCKLEN;
		if (c->progress.progress) {
			c->progress.progress(&c->progress, l / (float)c->size);
		}
	}
	if (r == -1) {
		// error
		fprintf(stderr, "errir reading file: %s\n", c->name);
		fflush(stderr);
		exit(EWRFILE);
	}
	// remove padding
	if (last[sizeof(last) - 1] < AES_BLOCKLEN) {
		_write(last, AES_BLOCKLEN - last[sizeof(last) - 1], fout, name);
	} // else whole block was padding


	fclose(fout);

	if (c->remove_origin && strncmp(STDIN, c->name, sizeof(STDIN))) {
		remove(c->name);
	}

	if (c->progress.done) {
		c->progress.done(&c->progress);
	}

out:
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
			fflush(stderr);
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
	if (pass_read || c->password[0] != '\0') {
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
	while ((c = getopt(argc, argv, "hedrp:o:")) != -1) {
		switch (c) {
		case 'h':
			usage();
			break;
		case 'e': // encrypt
			ctx.enc = 1;
			break;
		case 'd': // decrypt
			ctx.enc = 0;
			break;
		case 'r':
			ctx.remove_origin = 1;
			break;
		case 'o':
			ctx.out = optarg;
			break;
		case 'p':
			memcpy(ctx.password, optarg, sizeof(ctx.password));
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

	ctx.wp = init_work_pool();
	ctx.om = init_out_man();

	if (optind < argc) {
		ctx.om->outf = stdout;
		for (int i = optind; i < argc; i++) {
			char *fn = argv[i];
			handle_file(&ctx, fn);
		}
	} else {
		// stdin
		ctx.om->outf = NULL;
		f = stdin;
		ctx.name = STDIN;
		ctx.out = STDIN ".fc";
		add_work(&ctx, ctx.name, f);
	}
	// finished scanning
	no_more_work(ctx.wp);
	wait_until_done(ctx.wp);
	destroy_out_man(ctx.om);
}

static void progress_out(progress *prog, float p) {
	if (p > 1) {
		p = 1;
	}
	char b[4];
	sprintf(b, "%d", (int)(p * 100));
	ctx *c = (ctx *)((uint64_t)(prog) - offsetof(ctx, progress));
	output(c->output, "%s: %3.3s%%", c->name, b);
//	if (prog->first) {
//		prog->first = 0;
////		fprintf(stdout, "%s: %3.3s%%", c->name, b);
////		fflush(stdout);
//	} else {
//		fprintf(stdout, "\b\b\b\b%3.3s%%", b);
//		fflush(stdout);
//	}
}

static void progress_done(progress *prog) {
	ctx *c = (ctx *)((uint64_t)(prog) - offsetof(ctx, progress));
	output(c->output, "%s: 100%%", c->name);
}

static int do_filep(ctx *c, FILE *fp, char *file) {
	c->output = alloc_out(c->om);
	// new context for each file
	//ctx cn;
	//memcpy(&cn, c, sizeof(cn));
	c->f = fp;
	c->name = file;

	// set size
	int fd = fileno(fp);
	if (fd == -1) {
		fprintf(stderr, "error fileno\n");
		fflush(stderr);
		exit(EXIT_FAILURE);
	}
	struct stat st;
	if (fstat(fd, &st) == -1) {
		fprintf(stderr, "error stat file\n");
		fflush(stderr);
		exit(EXIT_FAILURE);
	}
	c->size = st.st_size;
	c->progress.progress = progress_out;
	c->progress.done = progress_done;
	fcrypt(c);
	output_done(c->output);
	return 0;
}

static ctx *dup_ctx(ctx *c) {
	ctx *ctx = malloc_e(sizeof(*ctx));
	*ctx = *c;
	return ctx;
}

static char *dup_str(char *s) {
	if (!s) {
		return NULL;
	}
	char *r = malloc_e(strlen(s) + 1);
	strcpy(r, s);
	return r;
}

static void add_work(ctx *c, char *file, FILE *filep) {
	get_pass(c);
	ctx *ctx = dup_ctx(c);
	cryptwork *cw = malloc_e(sizeof(*cw));
	memset(cw, 0, sizeof(*cw));
	if (!cw) {
		exit(ENOMEM);
	}
	cw->c = ctx;
	cw->file = dup_str(file);
	cw->extra = filep;
	new_work(ctx->wp, cw, do_crypt);
}

static int do_crypt(void *d) {
	cryptwork *w = (cryptwork *)d;
	int r;
	if (w->extra) {
		r = do_filep(w->c, (FILE*)w->extra, w->file);
	} else {
		r = do_file(w->c, w->file);
	}
	free(w->file);
	free(w->c);
	free(w);
	return r;
}

static int do_file(ctx *c, char *file) {
	FILE *f = fopen(file, "r");
	if (!f) {
		oob_out(c->om, "unable to open file: %s", file);
		return 1;
	}
	int r = do_filep(c, f, file);
	fclose(f);
	return r;
}

static void handle_file(ctx *ctx, char* file) {
	if (!access(file, F_OK)) {
		struct stat st;
		if (stat(file, &st) == -1) {
			oob_out(ctx->om, "unable to stat file: %s", file);
			return;
		}
		if (S_ISREG(st.st_mode)) {
			add_work(ctx, file, NULL);
		} else if (S_ISDIR(st.st_mode)) {
			do_dir(ctx, file);
		}
	} else {
		oob_out(ctx->om, "unable to access file %s", file);
	}
}

static int do_dir(ctx *ctx, char *dir) {
	ctx->out = NULL; // can't specify output file for all files in a directory
	struct dirent *e;
	DIR *d;

	if ((d = opendir(dir)) == NULL) {
		oob_out(ctx->om, "Can't open %s", dir);
		return 1;
	}

	char path[1024];
	while ((e = readdir(d)) != NULL) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) {
			continue;
		}
		sprintf(path, "%s/%s", dir, e->d_name);
		handle_file(ctx, path);
	}
	return 0;
}

