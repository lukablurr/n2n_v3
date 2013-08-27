/*
 * n2n_list.c
 *
 *  Created on: Aug 31, 2012
 *      Author: Costin Lupu
 */

#include "n2n.h"
#include "n2n_list.h"
#include "n2n_log.h"
#include <assert.h>



/**
 * Return the number of elements in the list.
 */
size_t list_size(const n2n_list_head_t *head)
{
    size_t count = 0;
    const n2n_list_node_t *node = NULL;
    LIST_FOR_EACH_NODE(head, node)
    {
        ++count;
    }
    return count;
}

/**
 * Purge all items from the list and return the number
 * of items that were removed.
 */
size_t list_clear(n2n_list_head_t *head)
{
    size_t count = 0;
    n2n_list_node_t *scan = NULL;
    n2n_list_node_t *next = NULL;

    LIST_FOR_EACH_NODE_SAFE(head, scan, next)
    {
        free(scan); /* free list entry */
        ++count;
    }
    list_head_init(head);

    return count;
}

void list_reverse(n2n_list_head_t *head)
{
    n2n_list_head_t aux = *head;
    n2n_list_node_t *scan = NULL;
    n2n_list_node_t *next = NULL;

    list_head_init(head);
    LIST_FOR_EACH_NODE_SAFE(&aux, scan, next)
    {
        list_add(head, scan);
    }
}

/**
 * Merge sort
 */
static void merge(n2n_list_node_t *left,  size_t left_size,
                  n2n_list_node_t *right, size_t right_size,
                  n2n_list_head_t *merged,
                  cmp_func_t cmp);

static void merge_sort(n2n_list_head_t *head, size_t size, cmp_func_t func)//TODO may just sort first 'size' entries
{
    size_t i, middle;
    LIST_HEAD(left);
    LIST_HEAD(right);
    LIST_HEAD(merged);
    n2n_list_node_t *left_last = NULL;

    if (size < 2)
        return;
    /* else list size is > 1, so split the list into two sublists */

    middle = size / 2;

    LIST_FIRST_NODE(&left) = LIST_FIRST_NODE(head);
    for (i = 0, left_last = LIST_FIRST_NODE(head); i < middle - 1; i++)
    {
        left_last = left_last->next;
    }

    LIST_FIRST_NODE(&right) = left_last->next;
    left_last->next = NULL;

    merge_sort(&left, middle, func);
    merge_sort(&right, size - middle, func);
    merge(LIST_FIRST_NODE(&left), middle, LIST_FIRST_NODE(&right), size - middle, &merged, func);

    LIST_FIRST_NODE(head) = LIST_FIRST_NODE(&merged);
}

static void merge(n2n_list_node_t *left,  size_t left_size,
                  n2n_list_node_t *right, size_t right_size,
                  n2n_list_head_t *merged,
                  cmp_func_t cmp)
{
    n2n_list_node_t *last_added = &merged->node;

    while (left_size > 0 && right_size > 0)
    {
        if (cmp(left, right) <= 0)
        {
            last_added->next = left;
            last_added = left;
            left = left->next;
            left_size--;
        }
        else
        {
            last_added->next = right;
            last_added = right;
            right = right->next;
            right_size--;
        }
    }

    if (left_size > 0)
    {
        last_added->next = left;
    }
    else if (right_size > 0)
    {
        last_added->next = right;
    }
}

void list_sort(n2n_list_head_t *head, cmp_func_t func)
{
    size_t size = list_size(head);
    merge_sort(head, size, func);
}

/********************************************/


#include <fcntl.h>//TODO remove after fixing file open



static FILE *open_list_file_for_read(const char *filename)
{
#if defined(WIN32)
    FILE *f = fopen(filename, "a+");
    fseek(f, 0L, SEEK_SET);
    return f;
#else//TODO remove
    int fd = open(filename, O_CREAT | O_RDONLY, 0666);
    if (fd < 0)
        return NULL;

    return fdopen(fd, "r");
#endif
}

int read_list_from_file(const char *filename, n2n_list_head_t *head, rd_entry_func_t rd_entry_func)
{
    FILE *f = NULL;
    n2n_list_node_t *new_item = NULL;

    traceInfo("opening file %s for reading", filename);

    f = open_list_file_for_read(filename);
    if (!f)
    {
        traceError("couldn't open file. %s", strerror(errno));
        return -1;
    }

    while ((new_item = rd_entry_func(f)) != NULL)
    {
        list_add(head, new_item);
    }

    list_reverse(head);

    fclose(f);
    return 0;

out_err:
    list_clear(head);
    fclose(f);
    return -1;
}

int write_list_to_file(const char *filename, n2n_list_head_t *head, wr_entry_func_t wr_entry_func)
{
    n2n_list_node_t *node;

    FILE *f = fopen(filename, "w");
    if (!f)
    {
        traceError("couldn't open community file");
        return -1;
    }

    LIST_FOR_EACH_NODE(head, node)
    {
        wr_entry_func(f, node);
    }

    fclose(f);
    return 0;

out_err:
    fclose(f);
    return -1;
}


