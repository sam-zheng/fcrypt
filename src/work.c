#include <stddef.h>
#include <pthread.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <stdio.h>

#include "work.h"

typedef struct work_pool {
	pthread_mutex_t mutex;
	list wh;
	int no_more_work __attribute__ ((aligned (4)));
	pthread_t *workers;
	int nw;
} work_pool;

static void *worker(void *a);

work_pool *init_work_pool() {
	struct work_pool *wp = malloc(sizeof(*wp));
	pthread_mutex_init(&wp->mutex, NULL);
	int cpus = get_nprocs();
	wp->workers = malloc(sizeof(pthread_t) * cpus);
	wp->nw = cpus;
	wp->no_more_work = 0;
	INIT_LIST(&wp->wh);
	for (int i = 0; i < cpus; i++) {
		pthread_create(wp->workers + i, NULL, worker, wp);
	}
	return wp;
}

static void wakeup_all(work_pool *pool) {
	syscall(SYS_futex, &pool->no_more_work, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}

static void wakeup_one(work_pool *pool) {
	syscall(SYS_futex, &pool->no_more_work, FUTEX_WAKE, 1, NULL, NULL, 0);
}

void no_more_work(work_pool *pool) {
	pool->no_more_work = 1;
	wakeup_all(pool);
}

void wait_until_done(work_pool *pool) {
	for (int i = 0; i < pool->nw; i++) {
		pthread_join(*(pool->workers + i), NULL);
	}
	free(pool->workers);
	pthread_mutex_destroy(&pool->mutex);
	free(pool);
}

static void enqueue_work(work_pool *pool, work *w) {
	pthread_mutex_lock(&pool->mutex);
	list_add(&w->link, &pool->wh);
//
//	w->link.prev = pool->wh.prev;
//	if (w->link.prev) {
//		w->link.prev->next = &w->link;
//	}
//	w->link.next = &pool->wh;
//	pool->wh.prev = &w->link;
	pthread_mutex_unlock(&pool->mutex);

	wakeup_one(pool);
}

void new_work(work_pool *pool, void *data, int (*func)(void *)) {
	work *w = malloc(sizeof(*w));
	memset(w, 0, sizeof(*w));
	w->data = data;
	w->func = func;
	enqueue_work(pool, w);
}

static work *dequeue_work(work_pool *pool) {
	pthread_mutex_lock(&pool->mutex);
	if (list_empty(&pool->wh)/*pool->wh.next == &pool->wh*/) {
		pthread_mutex_unlock(&pool->mutex);
		return NULL;
	}
	work *w = (work *)list_remove(pool->wh.next);
//
//	work *w = (work *)pool->wh.next;
//	pool->wh.next = w->link.next;
//	if (pool->wh.next) {
//		pool->wh.next->prev = &pool->wh;
//	}
	pthread_mutex_unlock(&pool->mutex);
	return w;
}

static void *worker(void *a) {
	work_pool *p = (work_pool *)a;
	int n = 0;
	int done_checked = 0;
	while (1) {
		work * w = dequeue_work(p);
		if (!w) { // no more work
			if (p->no_more_work) {
				// race
				if (done_checked) { // really done
					break;
				}
				done_checked = 1;
				continue;
			}
			long i = syscall(SYS_futex , &p->no_more_work, FUTEX_WAIT, 0, NULL, NULL, NULL);
			if (i && i != EAGAIN) {
				exit(2);
			}
		} else {
			w->func(w->data);
			n++;
			free(w);
		}
	}
	return (void*)n;
}
