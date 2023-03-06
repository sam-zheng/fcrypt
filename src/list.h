#ifndef LIST_H_
#define LIST_H_

#include <stdint.h>
#include <assert.h>

struct list {
	struct list *prev;
	struct list *next;
};

typedef struct list list;

#define LIST_OBJ(ptr, type, m) (type *)(((uint64_t)ptr) - offsetof(type, m))

#define INIT_LIST(l) (l)->prev = (l)->next = (l)

#define for_each(i, head) \
	for (i = (head)->next; i != (head); i = i->next)

static inline void list_add(list *new, list *head) {
	assert(new && head);
	new->prev = head->prev;
	new->prev->next = new;
	new->next = head;
	head->prev = new;
}

static inline list *list_remove(list *r) {
	assert(r);
	r->prev->next = r->next;
	r->next->prev = r->prev;
	r->prev = r->next = r;
	return r;
}

static inline int list_empty(list *head) {
	return head->next == head;
}

#endif /* LIST_H_ */
