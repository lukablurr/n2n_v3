/*
 * sn_multiple.c
 *
 *  Created on: Mar 25, 2012
 *      Author: Costin Lupu
 */

#include "n2n.h"
#include "n2n_log.h"
#include "sn_multiple.h"
//#include "n2n_list.h"




/*******************************************************************
 *                Operations on sn_info lists.                     *
 *******************************************************************/






sn_info_t *create_supernode_info(const n2n_sock_t *sock)
{
    sn_info_t *sn = calloc(1, sizeof(sn_info_t));
    if (NULL == sn)
    {
        traceError("Error allocating new 'sn_info_t'");
        return NULL;
    }

    sock_cpy(&sn->sock, sock);
    return sn;
}


sn_info_t *add_supernode_info(n2n_list_head_t *head, const n2n_sock_t *sock)
{
    sn_info_t *sn = create_supernode_info(sock);
    if (sn != NULL)
        list_add(head, &sn->list);
    return sn;
}


sn_info_t *find_supernode_info(n2n_list_head_t *head, const n2n_sock_t *sock)
{
    sn_info_t *scan = NULL;

    N2N_LIST_FOR_EACH(head, scan)
    {
        if (sock_equal(&scan->sock, sock) == 0)
            return scan;
    }
    return NULL;
}


n2n_list_node_t *read_supernode_info(FILE *f)
{
    sn_info_t *sni = NULL;
    n2n_sock_t sock;
    n2n_sock_str_t sockbuf;

    if (fscanf(f, "%s\n", sockbuf) <= 0)
        return NULL;

    if (0 != str2sock(&sock, sockbuf))
    {
        traceError("Invalid address: %s\n", sockbuf);
        return NULL;
    }

    sni = create_supernode_info(&sock);
    return (sni ? &sni->list : NULL);
}


void write_supernode_info(FILE *f, const void *entry)
{
    const sn_info_t *sni = (const sn_info_t *) entry;
    n2n_sock_str_t sockbuf;

    if (fprintf(f, "%s\n", sock2str(sockbuf, &sni->sock)) < 0)
    {
        traceError("couldn't write supernode entry to file");
    }
}

#if 0

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

    sock_cpy(sn, (n2n_sock_t *) sa);

    return retval;
}

#endif
