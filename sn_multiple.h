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

#define N2N_SNM_STATE_DISCOVERY    0
#define N2N_SNM_STATE_REQ_ADV      1
#define N2N_SNM_STATE_READY        2


struct sn_info
{
    struct n2n_list     list;
    n2n_sock_t          sn;
    size_t              communities_num;
    time_t              timestamp;
};

typedef struct sn_list
{
    struct n2n_list     head;
    char                filename[N2N_PERSIST_FILENAME_LEN];
} sn_list_t;



/* Operations on sn_info lists. */

struct n2n_list *read_sn(FILE *f);
void write_sn(FILE *f, const void *entry);



static inline int read_supernodes_from_file(const char *filename, struct n2n_list *list)
{
    return read_list_from_file(filename, list, read_sn);
}

static inline int write_supernodes_to_file(const char *filename, struct n2n_list *list)
{
    return write_list_to_file(filename, list, write_sn);
}


struct sn_info *sn_find(struct n2n_list *list, const n2n_sock_t *sn);

struct sn_info *add_new_supernode(struct n2n_list *list, const n2n_sock_t *sn);
int update_supernodes(sn_list_t *supernodes, const n2n_sock_t *sn);
int update_and_save_supernodes(sn_list_t *supernodes, n2n_sock_t *sn_array, int sn_num);

struct comm_info
{
    struct n2n_list     list;
    size_t              sn_num;
    n2n_sock_t          sn_sock[N2N_MAX_SN_PER_COMM];
    n2n_community_t     name;
};

typedef struct comm_list
{
    struct n2n_list     head;
    struct n2n_list     persist;
    char                filename[N2N_PERSIST_FILENAME_LEN];
} comm_list_t;

/* Operations on comm_info lists. */
struct n2n_list *read_community(FILE *f);
void write_community(FILE *f, const void *entry);

static inline int read_communities_from_file(const char *filename, struct n2n_list *list)
{
    return read_list_from_file(filename, list, read_community);
}

static inline int write_communities_to_file(const char *filename, struct n2n_list *list)
{
    return write_list_to_file(filename, list, write_community);
}

struct comm_info *comm_find( struct n2n_list *list,
                             n2n_community_t   comm_name,
                             size_t            comm_name_len );
int update_communities( comm_list_t       *communities,
                        snm_comm_name_t   *community_name,
                        n2n_sock_t        *supernode );

int add_new_community(comm_list_t        *communities,
                      n2n_community_t     comm_name,
                      struct comm_info  **comm);

/*******************************************************************
 *                   SNM INFO related functions                    *
 *******************************************************************/
int snm_info_add_sn(n2n_SNM_INFO_t *info, struct n2n_list *supernodes);

int build_snm_info( int              sock,         /* for ADV */
                    sn_list_t       *supernodes,
                    comm_list_t     *communities,
                    snm_hdr_t       *req_hdr,
                    n2n_SNM_REQ_t   *req,
                    snm_hdr_t       *info_hdr,
                    n2n_SNM_INFO_t  *info );
void clear_snm_info(n2n_SNM_INFO_t  *info);

int  process_snm_rsp( sn_list_t       *supernodes,
                      comm_list_t     *communities,
                      n2n_sock_t      *sender,
                      snm_hdr_t       *hdr,
                      n2n_SNM_INFO_t  *rsp );

/*******************************************************************
 *                    SNM ADV related functions                    *
 *******************************************************************/
int build_snm_adv(int                 sock,
                  struct n2n_list    *comm_list,
                  snm_hdr_t          *hdr,
                  n2n_SNM_ADV_t      *adv);
void clear_snm_adv(n2n_SNM_ADV_t *adv);
int  process_snm_adv(sn_list_t         *supernodes,
                     comm_list_t       *communities,
                     n2n_sock_t        *sn,
                     n2n_SNM_ADV_t     *adv);

/*******************************************************************
 *                            Utils                                *
 *******************************************************************/

int  sn_cmp(const n2n_sock_t *left, const n2n_sock_t *right);
void sn_cpy_addr(n2n_sock_t *dst, const n2n_sock_t *src);
void sn_cpy(n2n_sock_t *dst, const n2n_sock_t *src);
int  sn_is_zero_addr(n2n_sock_t *sn);
int  sn_is_loopback(n2n_sock_t *sn, uint16_t local_port); /* TODO hack until explicit binding */
int  sn_local_addr(int sock, n2n_sock_t *sn);


#endif /*SN_MULTIPLE_H_ */
