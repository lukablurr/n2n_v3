/*
 * n2n_list.h
 *
 *  Created on: Aug 31, 2012
 *      Author: Costin Lupu
 */

#ifndef N2N_LIST_H_
#define N2N_LIST_H_

#include <stddef.h>

#ifdef _MSC_VER
# define inline  __inline
# if _MSC_VER < 1600
#  define NO_TYPEOF
# else
#  define typeof  decltype
# endif
#endif


/**
 * CONTAINER_* macros adapted from:
 * http://ccodearchive.net/info/container_of.html
 * Author: Rusty Russell <rusty@rustcorp.com.au>
 */

/**
 * CONTAINER_OF - get pointer to enclosing structure
 * @member_ptr: pointer to the structure member
 * @containing_type: the type this member is within
 * @member: the name of this member within the structure.
 *
 * Given a pointer to a member of a structure, this macro does pointer
 * subtraction to return the pointer to the enclosing type.
 */
#define CONTAINER_OF(member_ptr, containing_type, member) \
     ((containing_type *) ((char *)(member_ptr) - offsetof(containing_type, member)))

/**
 * CONTAINER_OFF_VAR - get offset of a field in enclosing structure
 * @container_var: a pointer to a container structure
 * @member: the name of a member within the structure.
 *
 * Given (any) pointer to a structure and a its member name, this
 * macro does pointer subtraction to return offset of member in a
 * structure memory layout.
 *
 */
#ifdef NO_TYPEOF
#define CONTAINER_OFF_VAR(var, member) \
    ((char *) &(var)->member - (char *) (var))
#else
#define CONTAINER_OFF_VAR(var, member) \
    offsetof(typeof(*var), member)
#endif



/**
 * List structures, macros and functions adapted from:
 * http://ccodearchive.net/info/list.html
 * Author: Rusty Russell <rusty@rustcorp.com.au>
 */

/**
 * struct n2n_list_node - an entry in a singly-linked list
 * @next: next entry
 */
struct n2n_list_node
{
    struct n2n_list_node *next;
};

typedef struct n2n_list_node n2n_list_node_t;


/**
 * struct n2n_list_head - the head of a singly-linked list
 * @node: the list_head (containing next pointer)
 */
struct n2n_list_head
{
    n2n_list_node_t node;
};

typedef struct n2n_list_head n2n_list_head_t;



/**
 * LIST_HEAD - define and initialize an empty list_head
 * @name: the name of the list.
 *
 * The LIST_HEAD macro defines a list_head and initializes it to an empty
 * list.  It can be prepended by "static" to define a static list_head.
 */
#define LIST_HEAD(name) \
    n2n_list_head_t name = {{ &name.node }}

/**
 * list_head_init - initialize a list_head
 * @head: the list_head to set to the empty list
 */
static inline void list_head_init(n2n_list_head_t *head)
{
    head->node.next = &head->node;
}

/**
 * list_add - add an entry at the start of a linked list.
 * @head: the list_head to add the node to
 * @node: the list_node to add to the list.
 *
 * The list_node does not need to be initialized; it will be overwritten.
 */
static inline void list_add(n2n_list_head_t *head, n2n_list_node_t *node)
{
    node->next = head->node.next;
    head->node.next = node;
}

/**
 * list_empty - is a list empty?
 * @head: the list_head
 */
static inline int list_empty(const n2n_list_head_t *head)
{
    return (head->node.next == &head->node);
}

/**
 * LIST_FIRST_NODE - returns the first node of a list.
 * @head: the list_head
 */
#define LIST_FIRST_NODE(head) \
        (head)->node.next

/**
 * LIST_FOR_EACH_NODE - iterate through a list of nodes.
 * @head: the list_head
 * @n: the list_node
 */
#define LIST_FOR_EACH_NODE(head, n) \
    for (n = LIST_FIRST_NODE(head); n != &(head)->node; n = n->next)

/**
 * LIST_FOR_EACH_NODE_SAFE - iterate through a list of nodes, maybe
 * during deletion
 * @head: the list_head
 * @n: the list_node
 * @nxt: the next list_node
 */
#define LIST_FOR_EACH_NODE_SAFE(head, n, nxt) \
    for (n = LIST_FIRST_NODE(head), nxt = n->next; \
         n != &(head)->node; \
         n = nxt, nxt = nxt->next)

/**
 * LIST_ENTRY - convert a list_node back into the structure containing it.
 * @node: the list_node
 * @type: the type of the entry
 * @member: the list_node member of the type
 */
#define LIST_ENTRY(node, type, member) \
        CONTAINER_OF(node, type, member)

/**
 * LIST_FIRST_ENTRY - convert the first list_node back into the structure
 * containing it.
 * @node: the list_node
 * @type: the type of the entry
 * @member: the list_node member of the type
 */
#define LIST_FIRST_ENTRY(head, type, member) \
    (list_empty(head) ? NULL : LIST_ENTRY((head)->node.next, type, member))

/* Offset helper functions so we only single-evaluate. */
static inline void *list_node_to_off_(n2n_list_node_t *node, size_t off)
{
    return (void *) ((char *) node - off);
}

static inline n2n_list_node_t *list_node_from_off_(void *ptr, size_t off)
{
    return (n2n_list_node_t *) ((char *) ptr + off);
}

/**
 * LIST_FOR_EACH_OFF - iterate through a list of memory regions.
 * @head: the list_head
 * @i: the pointer to a memory region which contains list node data.
 * @off: offset(relative to @i) at which list node data resides.
 *
 * This is a low-level wrapper to iterate @i over the entire list, used to
 * implement all other, more high-level, for-each constructs. It's a for loop,
 * so you can break and continue as normal.
 */
#define LIST_FOR_EACH_OFF(head, i, off) \
  for (i = list_node_to_off_((head)->node.next, (off)); \
       list_node_from_off_((void *) i, (off)) != &(head)->node; \
       i = list_node_to_off_(list_node_from_off_((void *) i, (off))->next, (off)))

/**
 * LIST_FOR_EACH - iterate through a list.
 * @head: the list_head (warning: evaluated multiple times!)
 * @i: the structure containing the list_node
 * @member: the list_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 */
#define LIST_FOR_EACH(head, i, member) \
    LIST_FOR_EACH_OFF(head, i, CONTAINER_OFF_VAR(i, member))

/**
 * LIST_FOR_EACH_SAFE_OFF - iterate through a list of memory regions, maybe
 * during deletion
 * @head: the list_head
 * @i: the pointer to a memory region wich contains list node data.
 * @nxt: the structure containing the list_node
 * @off: offset(relative to @i) at which list node data resides.
 */
#define LIST_FOR_EACH_SAFE_OFF(head, i, nxt, off) \
  for (i = list_node_to_off_((head)->node.next, (off)), \
       nxt = list_node_to_off_(list_node_from_off_(i, (off))->next, (off)); \
       list_node_from_off_(i, (off)) != &(head)->node; \
       i = nxt, \
       nxt = list_node_to_off_(list_node_from_off_(i, (off))->next, (off)))

/**
 * LIST_FOR_EACH_SAFE - iterate through a list, maybe during deletion
 * @head: the list_head
 * @i: the structure containing the list_node
 * @nxt: the structure containing the list_node
 * @member: the list_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.  The extra variable
 * @nxt is used to hold the next element, so you can delete @i from the list.
 */
#define LIST_FOR_EACH_SAFE(head, i, nxt, member) \
    LIST_FOR_EACH_SAFE_OFF(head, i, nxt, CONTAINER_OFF_VAR(i, member))

/**
 * End of adapted code
 */


/**
 * N2N customizations:
 * - The member name in N2N is always 'list'
 */

#define N2N_LIST_ENTRY(node, type) \
    LIST_ENTRY(node, type, list)

#define N2N_LIST_FIRST_ENTRY(head, type) \
    LIST_FIRST_ENTRY(head, type, list)

#define N2N_LIST_NEXT_ENTRY(ptr, type) \
    CONTAINER_OF(ptr->list.next, type, list)

#define N2N_LIST_FOR_EACH(head, node) \
    LIST_FOR_EACH(head, node, list)

#define N2N_LIST_FOR_EACH_SAFE(head, node, next) \
    LIST_FOR_EACH_SAFE(head, node, next, list)

/*************************************/

typedef int (*cmp_func_t)(const void *a, const void *b);

size_t  list_size(const n2n_list_head_t *head);
size_t  list_clear(n2n_list_head_t *head);
void    list_reverse(n2n_list_head_t *head);
void    list_sort(n2n_list_head_t *head, cmp_func_t func);

/*************************************/

#include <stdio.h>

typedef n2n_list_node_t *(*rd_entry_func_t)(FILE *f);
typedef void             (*wr_entry_func_t)(FILE *f, const void *entry);

int read_list_from_file(const char *filename, n2n_list_head_t *head, rd_entry_func_t rd_entry_func);
int  write_list_to_file(const char *filename, n2n_list_head_t *head, wr_entry_func_t wr_entry_func);



#endif /* N2N_LIST_H_ */
