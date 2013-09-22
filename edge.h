/*
 * edge.h
 *
 *  Created on: Aug 22, 2013
 *      Author: wolf
 */

#ifndef EDGE_H_
#define EDGE_H_


#include "n2n_net.h"
#include "n2n_wire.h"
#include "n2n_transforms.h"
#include "n2n_list.h"
#include "tuntap.h"
#ifdef N2N_MULTIPLE_SUPERNODES
# include "sn_multiple.h"
#endif



#if defined(DEBUG)
#define SOCKET_TIMEOUT_INTERVAL_SECS    5
#define REGISTER_SUPER_INTERVAL_DFL     20 /* sec */
#else  /* #if defined(DEBUG) */
#define SOCKET_TIMEOUT_INTERVAL_SECS    10
#define REGISTER_SUPER_INTERVAL_DFL     6 /*TODO 60 sec */
#endif /* #if defined(DEBUG) */

#define REGISTER_SUPER_INTERVAL_MIN     2   /* TODO 20 sec */
#define REGISTER_SUPER_INTERVAL_MAX     6 /* TODO 3600 sec */

#define IFACE_UPDATE_INTERVAL           (30) /* sec. How long it usually takes to get an IP lease. */
#define TRANSOP_TICK_INTERVAL           (10) /* sec */

#define N2N_PATHNAME_MAXLEN             256
#define N2N_MAX_TRANSFORMS              16
#define N2N_EDGE_MGMT_PORT              5644



/** Positions in the transop array where various transforms are stored.
 *
 *  Used by transop_enum_to_index(). See also the transform enumerations in
 *  n2n_transforms.h */
#define N2N_TRANSOP_NULL_IDX    0
#define N2N_TRANSOP_TF_IDX      1
#define N2N_TRANSOP_AESCBC_IDX  2
/* etc. */

#define N2N_EDGE_SN_HOST_SIZE 48

typedef char n2n_sn_name_t[N2N_EDGE_SN_HOST_SIZE];

#ifdef N2N_MULTIPLE_SUPERNODESx
    #define N2N_EDGE_NUM_SUPERNODES           N2N_MAX_SN_PER_COMM
#else
    #define N2N_EDGE_NUM_SUPERNODES 2
#endif
#define N2N_EDGE_SUP_ATTEMPTS   3       /* Number of failed attmpts before moving on to next supernode. */



struct sn_list_entry
{
    n2n_list_node_t     list;
    n2n_sock_t          sock;
};

typedef struct sn_list_entry sn_list_entry_t;



/** Main structure type for edge. */
struct n2n_edge
{
    int                 daemon;                 /**< Non-zero if edge should detach and run in the background. */
    uint8_t             re_resolve_supernode_ip;

    n2n_sock_t *        supernode;

    size_t              sn_idx;                 /**< Currently active supernode. */
    size_t              sn_num;                 /**< Number of supernode addresses defined. */
    //n2n_sock_t          supernodes[N2N_EDGE_NUM_SUPERNODES];//TODO
    n2n_list_head_t     supernodes;

    int                 sn_wait;                /**< Whether we are waiting for a supernode response. */

    n2n_community_t     community_name;         /**< The community. 16 full octets. */
    char                keyschedule[N2N_PATHNAME_MAXLEN];
    int                 null_transop;           /**< Only allowed if no key sources defined. */

    int                 udp_sock;
    int                 udp_mgmt_sock;          /**< socket for status info. */

    tuntap_dev_t        device;                 /**< All about the TUNTAP device */
    ip_mode_t           ip_mode;                /**< Interface IP address allocation mode (eg. static, DHCP). */
    int                 allow_routing;          /**< Accept packet no to interface address. */
    int                 drop_multicast;         /**< Multicast ethernet addresses. */

    n2n_trans_op_t      transop[N2N_MAX_TRANSFORMS]; /* one for each transform at fixed positions */
    size_t              tx_transop_idx;         /**< The transop to use when encoding. */

    n2n_list_head_t     known_peers;            /**< Edges we are connected to. */
    n2n_list_head_t     pending_peers;          /**< Edges we have tried to register with. */
    time_t              last_register_req;      /**< Check if time to re-register with super*/
    size_t              register_lifetime;      /**< Time distance after last_register_req at which to re-register. */
    time_t              last_p2p;               /**< Last time p2p traffic was received. */
    time_t              last_sup;               /**< Last time a packet arrived from supernode. */
    size_t              sup_attempts;           /**< Number of remaining attempts to this supernode. */
    n2n_cookie_t        last_cookie;            /**< Cookie sent in last REGISTER_SUPER. */

    time_t              start_time;             /**< For calculating uptime */

    /* Statistics */
    size_t              tx_p2p;
    size_t              rx_p2p;
    size_t              tx_sup;
    size_t              rx_sup;

#ifdef N2N_MULTIPLE_SUPERNODES
    n2n_snm_state_t     snm_state;
    n2n_list_head_t     queried_supernodes;
    char                snm_filename[N2N_PATHNAME_MAXLEN];
#endif
};

typedef struct n2n_edge n2n_edge_t;



int edge_init_keyschedule(n2n_edge_t *eee);



#endif /* EDGE_H_ */
