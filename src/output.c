#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdarg.h>
#include "output.h"
#include "list.h"

static void *do_output(void *a);

struct out_man *init_out_man() {
	struct out_man *o = malloc(sizeof(*o));
	memset(o, 0, sizeof(*o));
	INIT_LIST(&o->head);
	pthread_mutex_init(&o->mutex, NULL);
	pthread_create(&o->thread, NULL, do_output, o);
	return o;
}

static int _out(struct out *o) {
	if (!strlen(o->buf)) {
		return 0;
	}
	int r = fprintf(stdout, "%s\n", o->buf);
	fflush(stdout);
	return r;
}

static void clear(struct out_man *om) {
	if (om->last_out_lines > 0) {
		fprintf(stdout, "\033[%dA\033[%dM", om->last_out_lines, om->last_out_lines);
//
//		char *clr = malloc(om->last_out + 1);
//		memset(clr, '\b', om->last_out);
//		clr[om->last_out] = '\0';
//		fprintf(stdout, clr);
		fflush(stdout);
	}
}

static void __do_out(struct out_man *o, char *oob, va_list arg) {
	pthread_mutex_lock(&o->mutex);
	clear(o);

	// oob
	if (oob) {
		vfprintf(stdout, oob, arg);
	}

	list *e = NULL;
	for_each(e, &o->head) {
		struct out *ot = LIST_OBJ(e, struct out, link);
		if (ot->state == DONE) {
			_out(ot);
			e = ot->link.prev; // move back the iterator var
			list_remove(&ot->link);
			free(ot);
		}

	}

	o->last_out_lines = 0;

	int count = 0;
	for_each(e, &o->head) {
		struct out *ot = LIST_OBJ(e, struct out, link);
		pthread_mutex_lock(&ot->mutex);
		count += _out(ot);
		o->last_out_lines++;
		pthread_mutex_unlock(&ot->mutex);

	}
	o->last_out = count;
	pthread_mutex_unlock(&o->mutex);
}

static void *do_output(void *a) {
	struct out_man *o = (struct out_man *)a;
	struct timespec ts = {.tv_sec = 0, .tv_nsec = 500000000} ;
	while (1) {
		__do_out(o, NULL, NULL);
		if (o->done) {
			break;
		}
		nanosleep(&ts, NULL);
	}
	return NULL;
}

struct out *alloc_out(struct out_man *om) {
	struct out *o = malloc(sizeof(*o));
	memset(o, 0, sizeof(*o));
	pthread_mutex_init(&o->mutex, NULL);
	INIT_LIST(&o->link);
	o->state = OUT;
	o->om = om;
	pthread_mutex_lock(&om->mutex);
	list_add(&o->link, &om->head);
	pthread_mutex_unlock(&om->mutex);
	return o;
}

void output(struct out *o, char* s,...) {
	pthread_mutex_lock(&o->mutex);
	va_list arg;
	va_start(arg, s);
	vsnprintf(o->buf, BUF_LEN, s, arg);
	va_end(arg);
	pthread_mutex_unlock(&o->mutex);
}

void output_done(struct out *o) {
	__sync_val_compare_and_swap(&o->state, 0, 1);
}

void destroy_out_man(struct out_man *om) {
	om->done = 1;
	pthread_join(om->thread, NULL);
	list *e = NULL;
	for_each(e, &om->head) {
		struct out *ot = LIST_OBJ(e, struct out, link);
		if (ot) {
			free(ot);
		}
	}
}

void oob_out(struct out_man *om, char* s,...) {
	va_list arg;
	va_start(arg, s);
	__do_out(om, s, arg);
	va_end(arg);
}
