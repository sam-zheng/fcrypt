
#ifndef OUTPUT_H_
#define OUTPUT_H_

#include "list.h"


#define BUF_LEN 256

struct out_man {
	list head;
	int last_out;
	int last_out_lines;
	pthread_mutex_t mutex; // protect head
	pthread_t thread;
	FILE* outf;
	int done __attribute__((aligned(4)));
};

enum OS {
	OUT,
	DONE
};

struct out {
	list link;
	struct out_man *om;
	enum OS state __attribute__((aligned (4)));
	pthread_mutex_t mutex;
	char buf[BUF_LEN];
};

struct out_man *init_out_man();

struct out *alloc_out(struct out_man *om);

void output(struct out *o, char*,...);

void oob_out(struct out_man *om, char*,...);

void destroy_out_man(struct out_man *om);

void output_done(struct out *o);

#endif /* OUTPUT_H_ */
