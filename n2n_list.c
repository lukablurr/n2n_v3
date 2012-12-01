/*
 * n2n_list.c
 *
 *  Created on: Aug 31, 2012
 *      Author: Costin Lupu
 */


#include <stdlib.h>

#include "n2n_list.h"



void list_add(struct n2n_list *head, struct n2n_list *new)
{
    new->next  = head->next;
    head->next = new;
}

/** Purge all items from the list and return the number
 *  of items that were removed.
 */
size_t list_clear(struct n2n_list *head)
{
    size_t count = 0;
    struct n2n_list *scan = head->next;

    while (scan)
    {
        struct n2n_list *crt = scan;
        scan = scan->next;
        free(crt); /* free list entry */
        count++;
    }
    head->next = NULL;

    return count;
}

/** Return the number of elements in the list.
 *
 */
size_t list_size(const struct n2n_list *head)
{
    size_t count = 0;
    LIST_FOR_EACH(head, head)
    {
        ++count;
    }
    return count;
}

void list_reverse(struct n2n_list *head)
{
    struct n2n_list *aux = head->next, *next = NULL;
    head->next = NULL;

    while (aux)
    {
        next = aux->next;
        list_add(head, aux);
        aux = next;
    }
}


/*
 * SORTING
 */

static void merge(struct n2n_list *left,  size_t left_size,
                  struct n2n_list *right, size_t right_size,
                  struct n2n_list *sorted,
                  cmp_func cmp);

static void merge_sort(struct n2n_list *list, size_t size, cmp_func func)//TODO may just sort first 'size' entries
{
    size_t i, middle;
    struct n2n_list left, right;
    struct n2n_list *entry = NULL;

    if (size < 2)
        return;
    /* else list size is > 1, so split the list into two sublists */

    middle = size / 2;

    LIST_FIRST(&left) = LIST_FIRST(list);
    for (i = 0, entry = &left; i < middle; i++)
    {
        entry = entry->next;
    }

    LIST_FIRST(&right) = entry->next;
    entry->next = NULL;

    merge_sort(&left,  middle, func);
    merge_sort(&right, size - middle, func);

    LIST_FIRST(list) = NULL;
    merge(&left, middle, &right, size - middle, list, func);
}

static void merge(struct n2n_list *left,  size_t left_size,
                  struct n2n_list *right, size_t right_size,
                  struct n2n_list *sorted,
                  cmp_func cmp)
{
    struct n2n_list *next = NULL;

    while (left_size > 0 || right_size > 0)
    {
        if (left_size > 0 && right_size > 0)
        {
            if (cmp(LIST_FIRST(left), LIST_FIRST(right)) <= 0)
            {
                next = LIST_FIRST(left)->next;
                list_add(sorted, LIST_FIRST(left));
                LIST_FIRST(left) = next;
                left_size--;
            }
            else
            {
                next = LIST_FIRST(right)->next;
                list_add(sorted, LIST_FIRST(right));
                LIST_FIRST(right) = next;
                right_size--;
            }
        }
        else if (left_size > 0)
        {
            next = LIST_FIRST(left)->next;
            list_add(sorted, LIST_FIRST(left));
            LIST_FIRST(left) = next;
            left_size--;
        }
        else if (right_size > 0)
        {
            next = LIST_FIRST(right)->next;
            list_add(sorted, LIST_FIRST(right));
            LIST_FIRST(right) = next;
            right_size--;
        }
    }

    list_reverse(sorted);
}


void list_sort(struct n2n_list *list, cmp_func func)
{
    size_t size = list_size(list);
    merge_sort(list, size, func);
}

/********************************************/


#include "n2n.h"



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

int read_list_from_file(const char *filename, struct n2n_list *list, read_entry_func read_entry)
{
    FILE *f = NULL;

    traceInfo("opening file %s for reading", filename);

    f = open_list_file_for_read(filename);
    if (!f)
    {
        traceError("couldn't open file. %s", strerror(errno));
        return -1;
    }

    struct n2n_list *new_item = NULL;

    while ((new_item = read_entry(f)) != NULL)
    {
        list_add(list, new_item);
    }

    list_reverse(list);

    fclose(f);
    return 0;

out_err:
    list_clear(list);
    fclose(f);
    return -1;
}

int write_list_to_file(const char *filename, struct n2n_list *list, write_entry_func write_entry)
{
    struct n2n_list *pos;

    FILE *f = fopen(filename, "w");
    if (!f)
    {
        traceError("couldn't open community file");
        return -1;
    }

    LIST_FOR_EACH(pos, list)
    {
        write_entry(f, pos);
    }

    fclose(f);
    return 0;

out_err:
    fclose(f);
    return -1;
}


