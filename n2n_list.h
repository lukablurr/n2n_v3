/*
 * n2n_list.h
 *
 *  Created on: Aug 31, 2012
 *      Author: Costin Lupu
 */

#ifndef N2N_LIST_H_
#define N2N_LIST_H_



struct n2n_list
{
    struct n2n_list *next;
};



#define CONTAINER_OF(ptr, type, member) ({                  \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type, member) );})

#define LIST_ENTRY(ptr, type, member) \
    CONTAINER_OF(ptr, type, member)

/*************************************/

#define LIST_FIRST(head)   (head)->next

#define LIST_FOR_EACH(pos, head) \
    for (pos = (head)->next; pos != NULL; pos = pos->next)

#define LIST_FOR_EACH_SAFE(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != NULL; pos = n, n = pos->next)

/*************************************/

#define LIST_FIRST_ENTRY(head, type, member) \
    LIST_ENTRY((head)->next, type, member)

#define LIST_NEXT_ENTRY(ptr, member) \
    LIST_ENTRY((ptr)->member.next, typeof(*ptr), list)

#define LIST_FOR_EACH_ENTRY(pos, head, member)                      \
    for (pos = LIST_ENTRY((head)->next, typeof(*pos), member);      \
         pos != NULL;                                               \
         pos = LIST_ENTRY(pos->member.next, typeof(*pos), member))

#define LIST_FOR_EACH_ENTRY_SAFE(pos, n, head, member)              \
    for (pos = LIST_ENTRY((head)->next, typeof(*pos), member),      \
         n = LIST_ENTRY(pos->member.next, typeof(*pos), member);    \
         &pos->member != NULL;                                      \
         pos = n, n = LIST_ENTRY(n->member.next, typeof(*n), member))

/*************************************/

#define N2N_LIST_FIRST_ENTRY(head, type) \
    LIST_FIRST_ENTRY(head, type, list)

#define N2N_LIST_NEXT_ENTRY(ptr) \
    LIST_NEXT_ENTRY(ptr, list)

#define N2N_LIST_FOR_EACH_ENTRY(pos, head) \
    LIST_FOR_EACH_ENTRY(pos, head, list)

#define N2N_LIST_FOR_EACH_ENTRY_SAFE(pos, n, head) \
    LIST_FOR_EACH_ENTRY_SAFE(pos, n, head, list)

/*************************************/

typedef int (*cmp_func)(const void *a, const void *b);


void    list_add(struct n2n_list *head, struct n2n_list *new);
size_t  list_clear(struct n2n_list *head);
size_t  list_size(const struct n2n_list *list);
void    list_reverse(struct n2n_list *list);
void    list_sort(struct n2n_list *list, cmp_func func);


static inline void list_init(struct n2n_list *list)
{
    list->next = NULL;
}

static inline int list_empty(const struct n2n_list *head)
{
    return (head->next == NULL);
}

/*************************************/

#include <stdio.h>

typedef struct n2n_list *(*read_entry_func)(FILE *f);
typedef void (*write_entry_func)(FILE *f, const void *entry);

int read_list_from_file(const char *filename, struct n2n_list *list, read_entry_func read_entry);
int write_list_to_file(const char *filename, struct n2n_list *list, write_entry_func write_entry);



#endif /* N2N_LIST_H_ */
