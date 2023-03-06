#ifndef WORK_H_
#define WORK_H_

#include "list.h"

//typedef struct head {
//	struct head *prev;
//	struct head *next;
//} head;

typedef struct work {
	list link;
	int (*func)(void *w);
	void *data;
} work;

typedef struct work_pool work_pool;

work_pool *init_work_pool();

void new_work(work_pool *pool, void *data, int (*func)(void *));

void no_more_work(work_pool *pool);

void wait_until_done(work_pool *pool);

#endif /* WORK_H_ */
