/*
 * sn_multiple_test.c
 *
 *  Created on: Mar 25, 2012
 *      Author: Costin Lupu
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "n2n.h"
#include "n2n_list.h"
#include "sn_multiple.h"
#include "sn_multiple_wire.h"


typedef int (*enc_func) (uint8_t         *base,
                         size_t          *idx,
                         const snm_hdr_t *hdr,
                         const void      *msg);

typedef int (*dec_func) (void            *msg,
                         const snm_hdr_t *hdr,
                         const uint8_t   *base,
                         size_t          *rem,
                         size_t          *idx);


typedef void    (*rand_func)   (void *item);
typedef void    (*add_func)    (struct n2n_list *list, struct n2n_list *new);
typedef size_t  (*size_func)   (const struct n2n_list *list);
typedef size_t  (*clear_func)  (struct n2n_list *list);

struct list_ops {
    size_t             item_size;
    rand_func          rand;
    read_entry_func    read_entry;
    write_entry_func   write_entry;
};


/*
 * SUPERNODE
 */

static void rand_n2n_sock(n2n_sock_t *sn)
{
    sn->family = AF_INET;
    unsigned int ipv4 = random() % 0xFFFFFFFF;
    memcpy(sn->addr.v4, &ipv4, IPV4_SIZE);
    sn->port = random() % ((1 << 16) - 1);
}

static void rand_sn(void *item)
{
    struct sn_info *si = (struct sn_info *) item;
    list_init(&si->list);
    rand_n2n_sock(&si->sn);
}

struct list_ops sn_list_ops = {
    .item_size    = sizeof(struct sn_info),
    .rand         = rand_sn,
    .read_entry   = read_sn,
    .write_entry  = write_sn
};


/*
 * COMMUNITY
 */

static void rand_comm(void *item)
{
    struct comm_info *ci = (struct comm_info *) item;
    int i;

    list_init(&ci->list);

    ci->sn_num = random() % N2N_MAX_SN_PER_COMM;
    for (i = 0; i < ci->sn_num; i++)
    {
        rand_n2n_sock(&ci->sn_sock[i]);
    }
    for (; i < N2N_MAX_SN_PER_COMM; i++)
    {
        memset(&ci->sn_sock[i], 0, sizeof(n2n_sock_t));
    }

    int name_size = random() % (N2N_COMMUNITY_SIZE - 1) + 1;
    for (i = 0; i < name_size; i++)
    {
        ci->name[i] = random() % ('z' - 'a') + 'a';
    }
    ci->name[i] = 0;
}

struct list_ops comm_list_ops = {
    .item_size    = sizeof(struct comm_info),
    .rand         = rand_comm,
    .read_entry   = read_community,
    .write_entry  = write_community
};


/*
 * RANDOMIZE
 */

static size_t generate_random_list(struct n2n_list *list,
                                   struct list_ops *ops)
{
    int i = 0, size = random() % 100;
    traceEvent(TRACE_NORMAL, "Generating %d list items\n", size);

    for (i = 0; i < size; i++)
    {
        void *item = calloc(1, ops->item_size);
        ops->rand(item);
        list_add(list, item);
    }

    return size;
}


/*
 * COMPARE functions
 */

static int cmp_SNM_REQ(const void *a, const void *b)
{
    const n2n_SNM_REQ_t *reqA = (const n2n_SNM_REQ_t *) a;
    const n2n_SNM_REQ_t *reqB = (const n2n_SNM_REQ_t *) b;

    int i, diff = reqA->comm_num - reqB->comm_num;
    if (diff)
    {
        return diff;
    }
    for(i = 0; i < reqA->comm_num; i++)
    {
        diff = memcmp(reqA->comm_ptr[i].name,
                      reqB->comm_ptr[i].name,
                      reqA->comm_ptr[i].size);
        if (diff)
        {
            return diff;
        }
    }

    return 0;
}

static int cmp_SNM_INFO(const void *a, const void *b)
{
    const n2n_SNM_INFO_t *infoA = (const n2n_SNM_INFO_t *) a;
    const n2n_SNM_INFO_t *infoB = (const n2n_SNM_INFO_t *) b;

    int i, diff = infoA->sn_num - infoB->sn_num;
    if (diff)
    {
        return diff;
    }
    diff = infoA->comm_num - infoB->comm_num;
    if (diff)
    {
        return diff;
    }

    for(i = 0; i < infoA->sn_num; i++)
    {
        diff = sock_equal(infoA->sn_ptr + i, infoB->sn_ptr + i);
        if (diff)
        {
            return diff;
        }
    }

    for(i = 0; i < infoA->comm_num; i++)
    {
        diff = memcmp(infoA->comm_ptr[i].name,
                      infoB->comm_ptr[i].name,
                      infoA->comm_ptr[i].size);
        if (diff)
        {
            return diff;
        }
    }

    return 0;
}

static int cmp_SNM_ADV(const void *a, const void *b)
{
    const n2n_SNM_ADV_t *advA = (const n2n_SNM_ADV_t *) a;
    const n2n_SNM_ADV_t *advB = (const n2n_SNM_ADV_t *) b;

    int i, diff = memcmp(&advA->sn, &advB->sn, sizeof(n2n_sock_t));
    if (diff)
    {
        return diff;
    }
    diff = advA->comm_num - advB->comm_num;
    if (diff)
    {
        return diff;
    }

    for(i = 0; i < advA->comm_num; i++)
    {
        diff = memcmp(advA->comm_ptr[i].name,
                      advB->comm_ptr[i].name,
                      advA->comm_ptr[i].size);
        if (diff)
        {
            return diff;
        }
    }

    return 0;
}


/*
 * TESTING functions for MESSAGES
 */

struct SNM_msg_ops
{
    size_t     struct_size;
    enc_func   enc;
    dec_func   dec;
    cmp_func   cmp;
};

struct SNM_msg_ops SNM_REQ_ops = {
    .struct_size = sizeof(n2n_SNM_REQ_t),
    .enc         = (enc_func) encode_SNM_REQ,
    .dec         = (dec_func) decode_SNM_REQ,
    .cmp         = cmp_SNM_REQ
};

struct SNM_msg_ops SNM_INFO_ops = {
    .struct_size = sizeof(n2n_SNM_INFO_t),
    .enc         = (enc_func) encode_SNM_INFO,
    .dec         = (dec_func) decode_SNM_INFO,
    .cmp         = cmp_SNM_INFO
};

struct SNM_msg_ops SNM_ADV_ops = {
    .struct_size = sizeof(n2n_SNM_ADV_t),
    .enc         = (enc_func) encode_SNM_ADV,
    .dec         = (dec_func) decode_SNM_ADV,
    .cmp         = cmp_SNM_ADV
};

static int test_SNM_MSG(struct SNM_msg_ops *ops,
                        const snm_hdr_t *hdr,
                        const void      *msg,
                        size_t           size)
{
    uint8_t buf[1024 * 1024];
    snm_hdr_t new_hdr;
    void *new_msg = NULL;
    size_t idx = 0, rem = size;

    if (ops->enc(buf, &idx, hdr, msg) != idx)
    {
        traceEvent(TRACE_ERROR, "Error encoding message");
        return -1;
    }

    new_msg = calloc(1, ops->struct_size);

    rem = idx;
    idx = 0;
    if (decode_SNM_hdr(&new_hdr, buf, &rem, &idx) < 0)
    {
        traceEvent(TRACE_ERROR, "Failed to decode header");
        goto test_SNM_MSG_err;
    }

    log_SNM_hdr(&new_hdr);

    if (ops->dec(new_msg, &new_hdr, buf, &rem, &idx) < 0)
    {
        traceEvent(TRACE_ERROR, "Error decoding message");
        goto test_SNM_MSG_err;
    }
    if (ops->cmp(msg, new_msg))
    {
        traceEvent(TRACE_ERROR, "Mismatched messages");
        goto test_SNM_MSG_err;
    }

    if (hdr->type == SNM_TYPE_REQ_LIST_MSG)
    {
        log_SNM_REQ(new_msg);
        free_communities(&((n2n_SNM_REQ_t *) new_msg)->comm_ptr);
    }
    else if (hdr->type == SNM_TYPE_RSP_LIST_MSG)
    {
        log_SNM_INFO(new_msg);
        free_supernodes(&((n2n_SNM_INFO_t *) new_msg)->sn_ptr);
        free_communities(&((n2n_SNM_INFO_t *) new_msg)->comm_ptr);
    }
    else if(hdr->type == SNM_TYPE_ADV_MSG)
    {
        log_SNM_ADV(new_msg);
        free_communities(&((n2n_SNM_ADV_t *) new_msg)->comm_ptr);
    }

    free(new_msg);
    return 0;

test_SNM_MSG_err:
    free(new_msg);
    return -1;
}

static void test_REQ_LIST()
{
    snm_hdr_t      hdr = {SNM_TYPE_REQ_LIST_MSG, 0, 3134};
    n2n_SNM_REQ_t  req;
    size_t         size = 0;
    size_t         lst_size = 0;
    struct n2n_list communities = { NULL };

    traceEvent(TRACE_NORMAL, "---- Testing SNM REQUEST message");

    SET_N(hdr.flags);

    lst_size = generate_random_list(&communities, &comm_list_ops);

    req.comm_num = list_size(&communities);
    alloc_communities(&req.comm_ptr, req.comm_num);

    struct comm_info *ci = NULL;
    int i = 0;

    N2N_LIST_FOR_EACH_ENTRY(ci, &communities)
    {
        req.comm_ptr[i].size = strlen((char *) ci->name);
        memcpy(&req.comm_ptr[i].name, ci->name, sizeof(n2n_community_t));
        i++;
    }

    log_SNM_hdr(&hdr);
    log_SNM_REQ(&req);

    if (test_SNM_MSG(&SNM_REQ_ops, &hdr, &req, size))
    {
        traceEvent(TRACE_ERROR, "Error testing n2n_SNM_REQ_t");
    }

    free_communities(&req.comm_ptr);
    list_clear(&communities);

    traceEvent(TRACE_NORMAL, "---- End testing SNM REQUEST message");
}

static int sn_cmp_timestamp_asc(const void *l, const void *r)
{
    return (((const struct sn_info *)l)->timestamp -
            ((const struct sn_info *)r)->timestamp);
}

static void test_sn_sort(struct n2n_list *list)
{
    struct sn_info *sni = NULL;

    N2N_LIST_FOR_EACH_ENTRY(sni, list)
    {
        /* set random timestamps */
        sni->timestamp = random();
    }

    list_sort(list, sn_cmp_timestamp_asc);

    int prev_timestamp = 0;

    N2N_LIST_FOR_EACH_ENTRY(sni, list)
    {
        if (sni->timestamp < prev_timestamp)
        {
            traceEvent(TRACE_ERROR, "Sort testing failed");
            return;
        }

        //traceEvent(TRACE_NORMAL, "--- %d", sni->last_seen);
        prev_timestamp = sni->timestamp;
    }

    traceEvent(TRACE_NORMAL, "--- Sort testing succeeded");
}

static void test_INFO()
{
    snm_hdr_t      req_hdr = {SNM_TYPE_REQ_LIST_MSG, 0, 3134};
    n2n_SNM_REQ_t  req;
    snm_hdr_t      rsp_hdr;
    n2n_SNM_INFO_t rsp;
    size_t         size = 0;

    traceEvent(TRACE_NORMAL, "---- Testing SNM INFO message");

    SET_S(req_hdr.flags);
    SET_C(req_hdr.flags);

    sn_list_t supernodes = { {NULL}, {0} };
    generate_random_list(&supernodes.head, &sn_list_ops);

    comm_list_t communities = { {NULL}, {NULL}, {0} };
    generate_random_list(&communities.head, &comm_list_ops);

    test_sn_sort(&supernodes.head);

    build_snm_info(0, &supernodes, &communities, &req_hdr, &req, &rsp_hdr, &rsp);
    list_clear(&supernodes.head);
    list_clear(&communities.head);
    req_hdr.type = SNM_TYPE_RSP_LIST_MSG;

    log_SNM_hdr(&req_hdr);
    log_SNM_INFO(&rsp);

    if (test_SNM_MSG(&SNM_INFO_ops, &req_hdr, &rsp, size))
    {
        traceEvent(TRACE_ERROR, "Error testing n2n_SNM_INFO_t");
    }

    clear_snm_info(&rsp);

    traceEvent(TRACE_NORMAL, "---- End testing SNM INFO message");
}

static void test_ADV()
{
    snm_hdr_t        hdr = {SNM_TYPE_ADV_MSG, 0, 5463};
    n2n_SNM_ADV_t    adv;
    size_t           size = 0;

    comm_list_t communities = { {NULL}, {NULL}, {0} };

    traceEvent(TRACE_NORMAL, "---- Testing SNM ADV message");

    SET_N(hdr.flags);

    generate_random_list(&communities.head, &comm_list_ops);

    int sock = open_socket(45555, 1);
    build_snm_adv(sock, &communities.head, &hdr, &adv);
    closesocket(sock);

    if (test_SNM_MSG(&SNM_ADV_ops, &hdr, &adv, size))
    {
        traceEvent(TRACE_ERROR, "Error testing n2n_SNM_ADV_t");
    }

    traceEvent(TRACE_NORMAL, "---- End testing SNM ADV message");
}

/*
 * LISTS TESTS
 */


static int test_write_read_list(struct n2n_list  *list,
                                struct list_ops  *ops)
{
    const char *filename = "tmp_list";
    struct n2n_list new_list = { NULL };

    if (write_list_to_file(filename, list, ops->write_entry))
    {
        traceEvent(TRACE_ERROR, "Error writing list");
        goto out_err;
    }
    if (read_list_from_file(filename, &new_list, ops->read_entry))
    {
        traceEvent(TRACE_ERROR, "Error reading list");
        goto out_err;
    }

    size_t size = list_size(list);
    size_t new_size = list_size(&new_list);

    if (size != new_size)
    {
        traceEvent(TRACE_ERROR, "Mismatched list sizes: %d instead of %d", new_size, size);
        goto out_err;
    }

    struct n2n_list *old_entry = list->next;
    struct n2n_list *new_entry = NULL;
    int i = 0;

    LIST_FOR_EACH(new_entry, &new_list)
    {
#define HDR_SIZE           sizeof(struct n2n_list)
#define ITEM_DATA(item)    (void *) ((unsigned int) (item) + HDR_SIZE)

        if (memcmp(ITEM_DATA(old_entry), ITEM_DATA(new_entry), ops->item_size - HDR_SIZE))
        {
            traceEvent(TRACE_ERROR, "Mismatched item %d", i);
            goto out_err;
        }

        old_entry = old_entry->next;
        i++;
    }

    if (list_clear(&new_list) != size)
    {
        traceEvent(TRACE_ERROR, "Error clearing list");
        goto out_err;
    }

    unlink(filename);
    return 0;

out_err:
    unlink(filename);
    return -1;
}

static void test_list(struct list_ops *ops)
{
    struct n2n_list list = { NULL };
    size_t size = generate_random_list(&list, ops);

    if (list_size(&list) != size)
    {
        traceEvent(TRACE_ERROR, "Mismatched list size");
        return;
    }
    if (test_write_read_list(&list, ops))
    {
        traceEvent(TRACE_ERROR, "Error write/read test");
    }
    if (list_clear(&list) != size)
    {
        traceEvent(TRACE_ERROR, "Error clearing list");
    }
}

static void test_sn()
{
    traceEvent(TRACE_NORMAL, "--- Testing supernodes lists IO");
    test_list(&sn_list_ops);
    traceEvent(TRACE_NORMAL, "--- End testing supernodes lists IO");
}

static void test_comm()
{
    traceEvent(TRACE_NORMAL, "--- Testing community lists IO");
    test_list(&comm_list_ops);
    traceEvent(TRACE_NORMAL, "--- End testing community lists IO");
}

int main()
{
    srandom(time(NULL));
    test_REQ_LIST();
    test_INFO();
    test_ADV();
    test_sn();
    test_comm();
    return 0;
}
