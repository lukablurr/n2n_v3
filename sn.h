/*
 * sn.h
 *
 *  Created on: Aug 22, 2013
 *      Author: wolf
 */

#ifndef SN_H_
#define SN_H_

#include "n2n.h"
#include "n2n_list.h"


#define N2N_SN_LPORT_DEFAULT            7654
#define N2N_SN_PKTBUF_SIZE              2048

#define N2N_SN_MGMT_PORT                5645


struct sn_stats
{
    size_t errors;              /* Number of errors encountered. */
    size_t reg_super;           /* Number of REGISTER_SUPER requests received. */
    size_t reg_super_nak;       /* Number of REGISTER_SUPER requests declined. */
    size_t fwd;                 /* Number of messages forwarded. */
    size_t broadcast;           /* Number of messages broadcast to a community. */
    time_t last_fwd;            /* Time when last message was forwarded. */
    time_t last_reg_super;      /* Time when last REGISTER_SUPER was received. */
};

typedef struct sn_stats sn_stats_t;


struct n2n_sn
{
    time_t              start_time;     /* Used to measure uptime. */
    sn_stats_t          stats;
    int                 daemon;         /* If non-zero then daemonise. */
    uint16_t            lport;          /* Local UDP port to bind to. */
    int                 sock;           /* Main socket for UDP traffic with edges. */
    int                 mgmt_sock;      /* management socket. */
#ifdef N2N_MULTIPLE_SUPERNODES
    uint8_t             snm_discovery_state;
    int                 sn_port;
    int                 sn_sock;        /* multiple supernodes socket */
    unsigned int        seq_num;        /* sequence number for SN communication */
    sn_list_t           supernodes;
    comm_list_t         communities;
#endif
    n2n_list_head_t     edges;          /* Link list of registered edges. */
};

typedef struct n2n_sn n2n_sn_t;



#endif /* SN_H_ */
