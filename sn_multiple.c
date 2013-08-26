/*
 * sn_multiple.c
 *
 *  Created on: Mar 25, 2012
 *      Author: Costin Lupu
 */

#include "n2n.h"
#include "sn_multiple.h"





/*******************************************************************
 *                Operations on sn_info lists.                     *
 *******************************************************************/




struct n2n_list *read_sn(FILE *f)
{
    n2n_sock_str_t  sock_str;
    struct sn_info *sni = NULL;

    if (fscanf(f, "%s\n", sock_str) <= 0)
        return NULL;

    sni = calloc(1, sizeof(struct sn_info));
    if (!sni)
    {
        traceError("couldn't allocate a new supernode entry");
        return NULL;
    }

    sock_from_cstr(&sni->sn, sock_str);//TODO
/*

    if (sn_list_add_new(list, &sn, NULL) < 0)
    {
        traceError("couldn't add read supernode");
        goto out_err;
    }
*/
    return &sni->list;
}

void write_sn(FILE *f, const void *entry)
{
    n2n_sock_str_t sock_str;
    const struct sn_info *sni = (const struct sn_info *) entry;

    if (fprintf(f, "%s\n", sock2str(sock_str, &sni->sn)) < 0)
    {
        traceError("couldn't write supernode entry to file");
    }
}

struct sn_info *sn_find(struct n2n_list *head, const n2n_sock_t *sn)
{
    struct sn_info *sni = NULL;

    N2N_LIST_FOR_EACH_ENTRY(sni, head)
    {
        if (sn_cmp(&sni->sn, sn) == 0)
            return sni;
    }
    return NULL;
}

struct sn_info *add_new_supernode(struct n2n_list *list, const n2n_sock_t *sn)
{
    struct sn_info *new = calloc(1, sizeof(struct sn_info));
    if (!new)
    {
        traceError("not enough memory for new SN info");
        return NULL;
    }

    sn_cpy(&new->sn, sn);
    list_add(list, &new->list);

    return new;
}

int update_supernodes(sn_list_t *supernodes, const n2n_sock_t *sn)
{
    n2n_sock_str_t sock_str;
    struct sn_info *sni = sn_find(&supernodes->head, sn);

    if (sni)
    {
        /* existing supernode */
        sni->timestamp = time(NULL);
        return 0;
    }

    if (add_new_supernode(&supernodes->head, sn) == NULL)
        return -1;

    traceDebug("Added supernode %s", sock2str(sock_str, sn));
    return 1;
}

int update_and_save_supernodes(sn_list_t *supernodes, n2n_sock_t *sn_array, int sn_num)
{
    int need_write = 0, i = 0;

    for (; i < sn_num; i++)
    {
        need_write += update_supernodes(supernodes, &sn_array[i]);
    }

    if (need_write)
    {
        /* elements added */
        write_supernodes_to_file(supernodes->filename, &supernodes->head);
    }

    return need_write;
}

/*******************************************************************
 *                 Operations on comm_info lists.                  *
 *******************************************************************/



struct n2n_list *read_community(FILE *f)
{
    size_t sn_num = 0;
    n2n_community_t name;
    n2n_sock_str_t sock_str;
    unsigned int i = 0;

    struct comm_info *ci = NULL;

    memset(name, 0, sizeof(n2n_community_t));

    if (fscanf(f, "sn_num=%d name=%s\n", &sn_num, name) <= 0)
        return NULL;

    ci = calloc(1, sizeof(struct comm_info));
    if (!ci)
    {
        traceError("couldn't allocate a new community entry");
        return NULL;
    }

    ci->sn_num = sn_num;
    memcpy(ci->name, name, sizeof(n2n_community_t));

    for (i = 0; i < ci->sn_num; i++)
    {
        fscanf(f, "\t%s\n", sock_str);
        sock_from_cstr(&ci->sn_sock[i], sock_str);
    }

    return &ci->list;
}

void write_community(FILE *f, const void *entry)
{
    unsigned int i;
    n2n_sock_str_t sock_str;
    const struct comm_info *ci = (const struct comm_info *) entry;

    fprintf(f, "sn_num=%d name=%s\n", ci->sn_num, ci->name);

    for (i = 0; i < ci->sn_num; i++)
    {
        sock2str(sock_str, ci->sn_sock + i);
        fprintf(f, "\t%s\n", sock_str);
    }
}

struct comm_info *comm_find(struct n2n_list *list,
                            n2n_community_t comm_name,
                            size_t comm_name_len)
{
    struct comm_info *ci = NULL;

    N2N_LIST_FOR_EACH_ENTRY(ci, list)
    {
        if (!memcmp(ci->name, comm_name, comm_name_len))
            return ci;
    }
    return NULL;
}

int add_new_community(comm_list_t        *communities,
                      n2n_community_t     comm_name,
                      struct comm_info  **comm)
{
    int retval = 0;

    struct comm_info *ci = comm_find(&communities->head,
                                     comm_name,
                                     strlen((const char *) comm_name));
    if (!ci)
    {
        ci = calloc(1, sizeof(struct comm_info));
        if (!ci)
        {
            traceError("not enough memory for new community info");
            return -1;
        }

        memcpy(&ci->name, comm_name, sizeof(n2n_community_t));
        list_add(&communities->head, &ci->list);

        retval = 1;
    }

    if (comm)
        *comm = ci;

    return retval;
}

static int add_new_supernode_to_community(struct comm_info *comm, n2n_sock_t *supernode)
{
    size_t i;

    if (comm->sn_num == N2N_MAX_SN_PER_COMM)
        return -1;

    for (i = 0; i < comm->sn_num; i++)
    {
        if (!sn_cmp(supernode, &comm->sn_sock[i]))
            return -1; /* dupe */
    }

    sn_cpy(&comm->sn_sock[comm->sn_num++], supernode);
    return 0;
}

int update_communities( comm_list_t       *communities,
                        snm_comm_name_t   *community_name,
                        n2n_sock_t        *supernode )
{
    struct comm_info *ci = NULL;

    add_new_community(communities, community_name->name, &ci);
    if (!ci)
        return -1;

    if (supernode)
    {
        add_new_supernode_to_community(ci, supernode);
    }

    return 0;
}

static int communities_to_array(uint16_t          *out_size,
                                snm_comm_name_t  **out_array,
                                struct n2n_list  *list)
{
    struct comm_info *pos;
    snm_comm_name_t *cni = NULL;

    *out_size = list_size(list);
    if (alloc_communities(out_array, *out_size))
    {
        traceError("could not allocate communities array");
        return -1;
    }

    cni = *out_array;

    N2N_LIST_FOR_EACH_ENTRY(pos, list)
    {
        cni->size = strlen((char *) pos->name);
        memcpy(cni->name, pos->name, sizeof(n2n_community_t));
        cni++;
    }
    return 0;
}

/*******************************************************************
 *                   SNM INFO related functions                    *
 *******************************************************************/

int snm_info_add_sn(n2n_SNM_INFO_t *info, struct n2n_list *supernodes)
{
    struct sn_info *sni = NULL;
    n2n_sock_t *sn = NULL;

    info->sn_num = list_size(supernodes);
    if (alloc_supernodes(&info->sn_ptr, info->sn_num))
    {
        traceError("could not allocate supernodes array");
        return -1;
    }

    sn = info->sn_ptr;

    N2N_LIST_FOR_EACH_ENTRY(sni, supernodes)
    {
        sn_cpy(sn, &sni->sn);
        sn++;
    }
    return 0;
}

static int snm_info_add_comm( n2n_SNM_INFO_t *info, struct n2n_list *communities )
{
    return communities_to_array(&info->comm_num, &info->comm_ptr, communities);
}

int build_snm_info( int              sock,         /* for ADV */
                    sn_list_t       *supernodes,
                    comm_list_t     *communities,
                    snm_hdr_t       *req_hdr,
                    n2n_SNM_REQ_t   *req,
                    snm_hdr_t       *info_hdr,
                    n2n_SNM_INFO_t  *info )
{
    int retval = 0;
    snm_comm_name_t *comm = NULL;
    struct comm_info *ci = NULL;

    info_hdr->type    = SNM_TYPE_RSP_LIST_MSG;
    info_hdr->seq_num = req_hdr->seq_num;
    info_hdr->flags   = 0;

    memset(info, 0, sizeof(n2n_SNM_INFO_t));

    if (GET_E(req_hdr->flags))
    {
        /* INFO for edge */

        if (GET_N(req_hdr->flags))
        {
            if (req->comm_num != 1)
            {
                traceError("Invalid edge request: Community number=%d",
                           req->comm_num);
                return -1;
            }

            comm = &req->comm_ptr[0];
            ci = comm_find(&communities->head, comm->name, comm->size);

            if (ci)
            {
                CLR_S(req_hdr->flags);
                SET_N(info_hdr->flags);
                SET_A(info_hdr->flags);

                /* set community supernodes ADV addresses */
                info->sn_num = ci->sn_num + 1;
                if (alloc_supernodes(&info->sn_ptr, info->sn_num))
                {
                    traceError("could not allocate supernodes array");
                    return -1;
                }

                memcpy(info->sn_ptr, ci->sn_sock, ci->sn_num * sizeof(n2n_sock_t));
                sn_local_addr(sock, &info->sn_ptr[ci->sn_num]);

                /* set community name */
                info->comm_num = 1;
                if (alloc_communities(&info->comm_ptr, info->comm_num))
                {
                    traceError("could not allocate community array");
                    return -1;
                }
                info->comm_ptr[0] = req->comm_ptr[0];
            }
            else
            {
                info->comm_num = list_size(&communities->head);
            }
        }
    }
    else
    {
        /* INFO for supernode */

        if (GET_C(req_hdr->flags))
        {
            SET_C(info_hdr->flags);

            /* Set communities list */
            retval += snm_info_add_comm(info, &communities->head);
        }
        else if (GET_N(req_hdr->flags))
        {
            /* Set supernodes???TODO */
        }
    }

    if (GET_S(req_hdr->flags))
    {
        SET_S(info_hdr->flags);

        /* Set supernodes list */
        retval += snm_info_add_sn(info, &supernodes->head);
    }

    return retval;
}

void clear_snm_info( n2n_SNM_INFO_t *info )
{
    info->sn_num = 0;
    free_supernodes(&info->sn_ptr);
    info->comm_num = 0;
    free_communities(&info->comm_ptr);
}

/*
 * Process response
 */
int  process_snm_rsp( sn_list_t       *supernodes,
                      comm_list_t     *communities,
                      n2n_sock_t      *sender,
                      snm_hdr_t       *hdr,
                      n2n_SNM_INFO_t  *rsp )
{
    int i;

    int new_sn = 0;

    /* Update list of supernodes */
    if (GET_S(hdr->flags))
    {
        new_sn = update_and_save_supernodes(supernodes, rsp->sn_ptr, rsp->sn_num);
    }

    /* Update list of communities */
    if (GET_C(hdr->flags))
    {
        for (i = 0; i < rsp->comm_num; i++)
        {
            update_communities(communities, &rsp->comm_ptr[i], sender);
        }
    }

    return new_sn;
}

/*******************************************************************
 *                    SNM ADV related functions                    *
 *******************************************************************/

static int snm_adv_add_comm(n2n_SNM_ADV_t *adv, struct n2n_list *communities)
{
    return communities_to_array(&adv->comm_num, &adv->comm_ptr, communities);
}

int build_snm_adv(int                 sock,
                  struct n2n_list    *comm_list,
                  snm_hdr_t          *hdr,
                  n2n_SNM_ADV_t      *adv)
{
    int retval = 0;

    hdr->type    = SNM_TYPE_ADV_MSG;
    hdr->flags   = 0;
    hdr->seq_num = 0;

    memset(adv, 0, sizeof(n2n_SNM_ADV_t));

    sn_local_addr(sock, &adv->sn);

    if (comm_list)
    {
        SET_N(hdr->flags);
        retval += snm_adv_add_comm(adv, comm_list);
    }

    return retval;
}

void clear_snm_adv(n2n_SNM_ADV_t *adv)
{
    adv->comm_num = 0;
    free_communities(&adv->comm_ptr);
}

int  process_snm_adv(sn_list_t         *supernodes,
                     comm_list_t       *communities,
                     n2n_sock_t        *sn,
                     n2n_SNM_ADV_t     *adv)
{
    int i, communities_updated = 0;
    struct comm_info *ci = NULL;

    /* Adjust advertising address */
    if (sn_is_zero_addr(&adv->sn))
        sn_cpy_addr(&adv->sn, sn);

    /* Add senders address */
    update_and_save_supernodes(supernodes, sn, 1);

    /* Update list of communities from recvd from a supernode */
    for (i = 0; i < adv->comm_num; i++)
    {
        ci = comm_find(&communities->head,
                       adv->comm_ptr[i].name,
                       adv->comm_ptr[i].size);

        if (!ci)
            continue;

        if (add_new_supernode_to_community(ci, &adv->sn) == 0)
            communities_updated = 1;
    }

    if (communities_updated)
    {
        /* elements added */
        write_communities_to_file(communities->filename, &communities->head);
    }

    return communities_updated;
}


/*******************************************************************
 *                            Utils                                *
 *******************************************************************/

int sn_cmp(const n2n_sock_t *left, const n2n_sock_t *right)
{
    if (left->family != right->family)
        return (left->family - right->family);
    else if (left->port != right->port)
        return (left->port - right->port);
    else if (left->family == AF_INET)
        return memcmp(left->addr.v4, right->addr.v4, IPV4_SIZE);

    return memcmp(left->addr.v6, right->addr.v6, IPV6_SIZE);
}

void sn_cpy_addr(n2n_sock_t *dst, const n2n_sock_t *src)
{
    dst->family = src->family;
    if (src->family == AF_INET)
        memcpy(dst->addr.v4, src->addr.v4, IPV4_SIZE);
    else
        memcpy(dst->addr.v6, src->addr.v6, IPV6_SIZE);
}

void sn_cpy(n2n_sock_t *dst, const n2n_sock_t *src)
{
    dst->port = src->port;
    sn_cpy_addr(dst, src);
}

int sn_is_zero_addr(n2n_sock_t *sn)
{
    int i = (sn->family == AF_INET ? (IPV4_SIZE - 1) : (IPV6_SIZE - 1));

    for (; i >= 0; --i)
    {
        if (sn->addr.v6[i] != 0)
            return 0;
    }

    //return (*((unsigned int *) sn->addr.v4) == 0);
    return 1;
}

int sn_is_loopback(n2n_sock_t *sn, uint16_t local_port)
{
    if (sn->family == AF_INET  &&
        sn->port == local_port &&
        sn->addr.v4[0] == 127  &&
        sn->addr.v4[1] == 0    &&
        sn->addr.v4[2] == 0    &&
        sn->addr.v4[3] == 1)
    {
        return 1;
    }

    return 0;
}

int sn_local_addr(int sock, n2n_sock_t *sn)
{
    int retval = 0;
    struct sockaddr_in *sa = NULL;

    struct sockaddr addr;
    unsigned int addrlen = sizeof(struct sockaddr);
    retval += getsockname(sock, &addr, &addrlen);

    sa = (struct sockaddr_in *) &addr;
    sa->sin_port = ntohs(sa->sin_port);

    sn_cpy(sn, (n2n_sock_t *) sa);

    return retval;
}
