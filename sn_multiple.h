/*
 *sn_multiple.h
 *
 * Created on: Mar 25, 2012
 *     Author: Costin Lupu
 */

#ifndef SN_MULTIPLE_H_
#define SN_MULTIPLE_H_

#include "n2n_list.h"
#include "n2n_wire.h"
#include "sn_multiple_wire.h"


#define N2N_SN_COMM_PORT                5646
#define N2N_PERSIST_FILENAME_LEN        64

#define N2N_MIN_SN_PER_COMM             3
#define N2N_MAX_SN_PER_COMM             4
#define N2N_MAX_COMM_PER_SN             3

#define N2N_SUPER_DISCOVERY_INTERVAL    3//60   /* seconds */

#define N2N_SNM_STATE_NONE          0
#define N2N_SNM_STATE_DISCOVERY     1
#define N2N_SNM_STATE_READY         2




enum n2n_snm_state
{
    n2n_snm_none = 0,
    n2n_snm_discovery = 1,
    n2n_snm_ready = 2
};

typedef enum n2n_snm_state n2n_snm_state_t;


struct sn_info
{
    n2n_list_node_t     list;
    n2n_sock_t          sock;
    size_t              edges_num;
    size_t              vouched;//TODO
    time_t              timestamp;
};

typedef struct sn_info sn_info_t;



struct sn_federation
{
    n2n_list_node_t     list;
    n2n_list_head_t     members;//TODO entry type
    size_t              count;
};

typedef struct sn_federation sn_federation_t;


typedef struct sn_list
{
    n2n_list_head_t     head;
    char                filename[N2N_PERSIST_FILENAME_LEN];
} sn_list_t;



/* functions */

sn_info_t * create_supernode_info(const n2n_sock_t *sock);
sn_info_t *    add_supernode_info(n2n_list_head_t *head, const n2n_sock_t *sock);
sn_info_t *   find_supernode_info(n2n_list_head_t *head, const n2n_sock_t *sock);

/* IO */
n2n_list_node_t *read_supernode_info(FILE *f);
void write_supernode_info(FILE *f, const void *entry);

static inline int read_supernodes_from_file(const char *filename, n2n_list_head_t *list)
{
    return read_list_from_file(filename, list, read_supernode_info);
}

static inline int write_supernodes_to_file(const char *filename, n2n_list_head_t *list)
{
    return write_list_to_file(filename, list, write_supernode_info);
}


int update_supernodes(sn_list_t *supernodes, const n2n_sock_t *sn);
int update_and_save_supernodes(sn_list_t *supernodes, n2n_sock_t *sn_array, int sn_num);




/*******************************************************************
 *                            Utils                                *
 *******************************************************************/

int  sn_cmp(const n2n_sock_t *left, const n2n_sock_t *right);
int  sn_is_zero_addr(n2n_sock_t *sn);
int  sn_is_loopback(n2n_sock_t *sn, uint16_t local_port); /* TODO hack until explicit binding */
int  sn_local_addr(int sock, n2n_sock_t *sn);


#endif /*SN_MULTIPLE_H_ */
