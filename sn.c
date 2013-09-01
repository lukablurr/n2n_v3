/* Supernode for n2n-2.x */

/* (c) 2009 Richard Andrews <andrews@ntop.org> 
 *
 * Contributions by:
 *    Lukasz Taczuk
 *    Struan Bartlett
 */

#include "sn.h"
#include "n2n_log.h"



/**
 * Initialize the supernode structure
 */
static int init_sn(n2n_sn_t *sss)
{
#ifdef WIN32
    initWin32();
#endif

    memset(sss, 0, sizeof(n2n_sn_t));

    sss->daemon = 1; /* By defult run as a daemon. */
    sss->lport = N2N_SN_LPORT_DEFAULT;
    sss->mport = N2N_SN_MGMT_PORT;
    sss->sock = -1;
    sss->mgmt_sock = -1;
    list_head_init(&sss->edges);

#ifdef N2N_MULTIPLE_SUPERNODES
    list_head_init(&sss->federation);
    list_head_init(&sss->queried_supernodes);
#endif

    return 0; /* OK */
}

/**
 * Deinitialize the supernode structure and deallocate any memory owned by
 * it.
 */
static void deinit_sn(n2n_sn_t *sss)
{
    if (sss->sock >= 0)
    {
        closesocket(sss->sock);
    }
    sss->sock = -1;

    if (sss->mgmt_sock >= 0)
    {
        closesocket(sss->mgmt_sock);
    }
    sss->mgmt_sock = -1;

    purge_peer_list(&(sss->edges), 0xffffffff);

#ifdef N2N_MULTIPLE_SUPERNODES
    list_clear(&sss->federation);
    list_clear(&sss->queried_supernodes);
#endif
}


/**
 * Determine the appropriate lifetime for new registrations.
 *
 * If the supernode has been put into a pre-shutdown phase then this lifetime
 * should not allow registrations to continue beyond the shutdown point.
 */
static uint16_t reg_lifetime(n2n_sn_t *sss)
{
    return 120;
}


/**
 * Update the edge table with the details of the edge which contacted the
 * supernode.
 */
static int update_edge(n2n_sn_t *sss,
                       const n2n_mac_t edge_mac,
                       const n2n_community_t community,
                       const n2n_sock_t *sender_sock,
                       time_t now)
{
    peer_info_t        *scan;
    macstr_t            macbuf;
    n2n_sock_str_t      sockbuf;

    traceDebug("update_edge for %s [%s]",
               mac2str(macbuf, edge_mac), sock2str(sockbuf, sender_sock));

    scan = find_peer_by_mac(&sss->edges, edge_mac);

    if (NULL == scan)
    {
        /* Not known */

        /* Entry will be deallocated in purge_expired_registrations */
        scan = (peer_info_t *) calloc(1, sizeof(peer_info_t));

        memcpy(scan->community_name, community, sizeof(n2n_community_t));
        memcpy(&scan->mac_addr, edge_mac, sizeof(n2n_mac_t));
        memcpy(&scan->sock, sender_sock, sizeof(n2n_sock_t));

        /* insert this guy at the head of the edges list */
        list_add(&sss->edges, &scan->list);

        traceInfo("update_edge created   %s ==> %s", macbuf, sockbuf);
    }
    else
    {
        /* Known */
        if ( !community_equal(community, scan->community_name) ||
             (0 != sock_equal(sender_sock, &(scan->sock))) )
        {
            memcpy(scan->community_name, community, sizeof(n2n_community_t));
            memcpy(&scan->sock, sender_sock, sizeof(n2n_sock_t));

            traceInfo("update_edge updated   %s ==> %s", macbuf, sockbuf);
        }
        else
        {
            traceDebug("update_edge unchanged %s ==> %s", macbuf, sockbuf);
        }
    }

    scan->last_seen = now;
    return 0;
}


/**
 * Try to forward a message to a unicast MAC. If the MAC is unknown then
 * broadcast to all edges in the destination community.
 */
static int try_forward(n2n_sn_t *sss,
                       const n2n_common_t *cmn, const n2n_mac_t dst_mac,
                       const uint8_t *pktbuf, size_t pktsize)
{
    struct peer_info   *scan;
    macstr_t            macbuf;
    n2n_sock_str_t      sockbuf;

    scan = find_peer_by_mac(&sss->edges, dst_mac);

    if (NULL != scan)
    {
        int data_sent_len;
        data_sent_len = sendto_sock(sss->sock, pktbuf, pktsize, &scan->sock);

        if (data_sent_len == pktsize)
        {
            ++(sss->stats.fwd);
            traceDebug("unicast %lu to [%s] %s",
                       pktsize,
                       sock2str(sockbuf, &(scan->sock)),
                       mac2str(macbuf, scan->mac_addr));
        }
        else
        {
            ++(sss->stats.errors);
            traceError("unicast %lu to [%s] %s FAILED (%d: %s)",
                       pktsize,
                       sock2str(sockbuf, &(scan->sock)),
                       mac2str(macbuf, scan->mac_addr),
                       errno, strerror(errno));
        }
    }
    else
    {
        traceDebug("try_forward unknown MAC");

        /* Not a known MAC so drop. */
    }
    
    return 0;
}


/**
 * Try and broadcast a message to all edges in the community.
 *
 * This will send the exact same datagram to zero or more edges registered to
 * the supernode.
 */
static int try_broadcast(n2n_sn_t *sss,
                         const n2n_common_t *cmn, const n2n_mac_t src_mac,
                         const uint8_t *pktbuf, size_t pktsize)
{
    struct peer_info   *scan;
    macstr_t            macbuf;
    n2n_sock_str_t      sockbuf;

    traceDebug("try_broadcast");

    N2N_LIST_FOR_EACH(&sss->edges, scan)
    {
        if ( community_equal(scan->community_name, cmn->community) &&
             !mac_equal(src_mac, scan->mac_addr) )
        /* REVISIT: exclude if the destination socket is where the packet came from. */
        {
            int data_sent_len;
            data_sent_len = sendto_sock(sss->sock, pktbuf, pktsize, &scan->sock);

            if (data_sent_len != pktsize)
            {
                ++(sss->stats.errors);
                traceWarning("multicast %lu to [%s] %s failed %s",
                             pktsize,
                             sock2str(sockbuf, &(scan->sock)),
                             mac2str(macbuf, scan->mac_addr),
                             strerror(errno));
            }
            else
            {
                ++(sss->stats.broadcast);
                traceDebug("multicast %lu to [%s] %s",
                           pktsize,
                           sock2str(sockbuf, &(scan->sock)),
                           mac2str(macbuf, scan->mac_addr));
            }
        }
    } /* loop */
    
    return 0;
}


static int process_mgmt(n2n_sn_t *sss,
                        const struct sockaddr_in *sender_sock,
                        const uint8_t *mgmt_buf,
                        size_t mgmt_size,
                        time_t now)
{
    char resbuf[N2N_SN_PKTBUF_SIZE];
    size_t ressize = 0;
    ssize_t r;

    traceDebug("process_mgmt");

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "----------------\n");

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "uptime    %lu\n", (now - sss->start_time));

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "edges     %u\n",
                        (unsigned int) list_size(&sss->edges));

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "errors    %u\n",
                        (unsigned int) sss->stats.errors);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "reg_sup   %u\n",
                        (unsigned int) sss->stats.reg_super);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "reg_nak   %u\n",
                        (unsigned int) sss->stats.reg_super_nak);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "fwd       %u\n",
                        (unsigned int) sss->stats.fwd);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "broadcast %u\n",
                        (unsigned int) sss->stats.broadcast);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "last fwd  %lu sec ago\n",
                        (long unsigned int) (now - sss->stats.last_fwd));

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "last reg  %lu sec ago\n",
                        (long unsigned int) (now - sss->stats.last_reg_super));


    r = sendto(sss->mgmt_sock, resbuf, ressize, 0/*flags*/,
               (struct sockaddr *) sender_sock, sizeof(struct sockaddr_in));

    if (r <= 0)
    {
        ++(sss->stats.errors);
        traceError("process_mgmt : sendto failed. %s", strerror(errno));
    }

    return 0;
}


#ifdef N2N_MULTIPLE_SUPERNODES

typedef void (*fed_cb_t) (n2n_sn_t *sss, time_t now);


#define QUERY_INTERVAL          5
#define QUERY_INTERVAL_EXTENDED 10
#define SUBSCRIPTION_INTERVAL   4
#define FEDERATION_UPD_INTERVAL 5

#define FEDERATION_PEERS_NUM    3




static void send_query(n2n_sn_t *sss, const n2n_sock_t *dst)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_common_t cmn;
    n2n_QUERY_SUPER_t query;
    n2n_sock_str_t sockbuf;

    init_cmn(&cmn, n2n_query_super, N2N_FLAGS_FROM_SUPERNODE, cmn.community);//TODO
    memset(&query, 0, sizeof(n2n_QUERY_SUPER_t));

    idx = 0;
    encode_QUERY_SUPER(pktbuf, &idx, &cmn, &query);

    traceInfo("Tx QUERY_SUPER to %s", sock2str(sockbuf, dst));
    sendto_sock(sss->sock, pktbuf, idx, dst);
}

static void federation_discovery(n2n_sn_t *sss, time_t now)
{
    sn_info_t *qi = NULL;
    N2N_LIST_FOR_EACH(&sss->queried_supernodes, qi)
    {
        send_query(sss, &qi->sock);
    }
    sss->snm_state = N2N_SNM_STATE_DISCOVERY;
    sss->stats.last_fed_upd = now;
}

size_t purge_sn_list(n2n_list_head_t *peers, time_t purge_before)
{
    sn_info_t *scan = NULL;
    sn_info_t *next = NULL;
    n2n_list_node_t *prev = &peers->node;
    size_t retval = 0;

    N2N_LIST_FOR_EACH_SAFE(peers, scan, next)
    {
        if (scan->timestamp < purge_before)
        {
            printf("Diff = %d\n", purge_before - scan->timestamp);
            prev->next = &next->list;
            free(scan);
            ++retval;
        }
        else
        {
            prev = &scan->list;
        }
    }

    return retval;
}

static void send_federation(n2n_sn_t *sss, const n2n_sock_t *sn, n2n_flags_t subscr)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_common_t cmn;
    n2n_FEDERATION_t fed;
    n2n_sock_str_t sockbuf;

    init_cmn(&cmn, n2n_federation, N2N_FLAGS_FROM_SUPERNODE | subscr, cmn.community);//TODO

    idx = 0;
    encode_FEDERATION(pktbuf, &idx, &cmn, &fed);

    traceInfo("Tx FEDERATION to %s", sock2str(sockbuf, sn));
    sendto_sock(sss->sock, pktbuf, idx, sn);

    sss->stats.last_fed_upd = time(NULL);
}

static int sn_cmp_vouched_asc(const void *l, const void *r)
{
    return (((const sn_info_t *) l)->vouched -
            ((const sn_info_t *) r)->vouched);
}

/**
 * Picks up the most relevant supernodes from the query results.
 */
static void federation_subscription(n2n_sn_t *sss, time_t now)
{
    sn_info_t *scan = NULL;
    sn_info_t *next = NULL;
    n2n_list_node_t *prev = NULL;
    size_t fed_size = 0;

    if ((now - sss->stats.last_fed_upd) < QUERY_INTERVAL)
        /* Not yet */
        return;

    traceInfo("Federation subscription");

    /* Supernodes with least vouchers will be first */
    list_sort(&sss->queried_supernodes, sn_cmp_vouched_asc);

    /* Current federation peers number */
    fed_size = list_size(&sss->federation);

    prev = &sss->queried_supernodes.node;
    N2N_LIST_FOR_EACH_SAFE(&sss->queried_supernodes, scan, next)
    {
        if (fed_size == FEDERATION_PEERS_NUM)
        {
            /* Enough entries */
            list_clear(&sss->queried_supernodes);
            break;
        }

        if (scan->timestamp == 0)
            /* No response (also no vouchers) */
            break;

        /* Create new federation entry */
        add_supernode_info(&sss->federation, &scan->sock);
        fed_size++;

        /* Send federation subscription */
        send_federation(sss, &scan->sock, N2N_FLAGS_FED_SUBSCRIBE);

        /* Remove the query information */
        prev->next = &next->list;
        free(scan);
    }

    sss->snm_state = N2N_SNM_STATE_READY;
}

static void federation_update(n2n_sn_t *sss, time_t now)
{
    sn_info_t *scan = NULL;
    size_t fed_size = 0;
    size_t purged = 0;

    if ((now - sss->stats.last_fed_upd) < FEDERATION_UPD_INTERVAL)
        /* Not yet */
        return;

    fed_size = list_size(&sss->federation);
    traceInfo("Total federation members: %ld", fed_size);

    purged = purge_sn_list(&sss->federation, now - 2 * FEDERATION_UPD_INTERVAL);//TODO
    traceInfo("Dead federation members: %ld", purged);
    fed_size = list_size(&sss->federation);

    if (fed_size < FEDERATION_PEERS_NUM)
    {
        /* Need more federation peers */

        sss->snm_state = N2N_SNM_STATE_DISCOVERY;
        list_head_init(&sss->queried_supernodes);

        N2N_LIST_FOR_EACH(&sss->federation, scan)
        {
            send_query(sss, &scan->sock);
        }

        sss->stats.last_fed_upd = now;
    }
    else
    {
        //sss->snm_state = N2N_SNM_STATE_READY;

        N2N_LIST_FOR_EACH(&sss->federation, scan)
        {
            send_federation(sss, &scan->sock, 0);
        }
    }
}

static int find_known_supernode_by_sock(n2n_sn_t *sss, const n2n_sock_t *sock,
                                        sn_info_t **snqi, sn_info_t **sni)
{

    *snqi = find_supernode_info(&sss->queried_supernodes, sock);
    if (NULL == *snqi)
    {
        *sni = find_supernode_info(&sss->federation, sock);
    }
    else
    {
        *sni = NULL;
        return 0;
    }

    return -(*sni == NULL);
}

#endif /* #ifdef N2N_MULTIPLE_SUPERNODES */


/**
 * Examine a datagram and determine what to do with it.
 */
static int process_udp(n2n_sn_t *sss,
                       const struct sockaddr_in *sender_sock,
                       const uint8_t *udp_buf,
                       size_t udp_size,
                       time_t now)
{
    n2n_common_t        cmn; /* common fields in the packet header */
    size_t              rem;
    size_t              idx;
    size_t              msg_type;
    uint8_t             from_supernode;
    macstr_t            macbuf;
    macstr_t            macbuf2;
    n2n_sock_str_t      sockbuf;


    traceDebug("process_udp(%lu)", udp_size);

    /* Use decode_common() to determine the kind of packet then process it:
     *
     * REGISTER_SUPER adds an edge and generate a return REGISTER_SUPER_ACK
     *
     * REGISTER, REGISTER_ACK and PACKET messages are forwarded to their
     * destination edge. If the destination is not known then PACKETs are
     * broadcast.
     */

    rem = udp_size; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */
    if (decode_common(&cmn, udp_buf, &rem, &idx) < 0)
    {
        traceError("Failed to decode common section");
        return -1; /* failed to decode packet */
    }

    if (cmn.ttl < 1)
    {
        traceWarning("Expired TTL");
        return 0; /* Don't process further */
    }

    msg_type = cmn.pc; /* packet code */
    from_supernode = ( cmn.flags & N2N_FLAGS_FROM_SUPERNODE );

    --(cmn.ttl); /* The value copied into all forwarded packets. */

    if (msg_type == MSG_TYPE_PACKET)
    {
        /* PACKET from one edge to another edge via supernode. */

        /* pkt will be modified in place and recoded to an output of potentially
         * different size due to addition of the socket.*/
        n2n_PACKET_t                    pkt; 
        n2n_common_t                    cmn2;
        uint8_t                         encbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx=0;
        int                             unicast; /* non-zero if unicast */
        const uint8_t *                 rec_buf; /* either udp_buf or encbuf */


        sss->stats.last_fwd = now;
        decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);

        unicast = (0 == is_multi_broadcast_mac(pkt.dstMac));

        traceDebug("Rx PACKET (%s) %s -> %s %s",
                   (unicast ? "unicast" : "multicast"),
                   mac2str(macbuf, pkt.srcMac),
                   mac2str(macbuf2, pkt.dstMac),
                   (from_supernode ? "from sn" : "local"));

        if (!from_supernode)
        {
            memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

            /* We are going to add socket even if it was not there before */
            cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

            sockaddr2sock(&pkt.sock, (struct sockaddr_storage *) sender_sock);

            rec_buf = encbuf;

            /* Re-encode the header. */
            encode_PACKET(encbuf, &encx, &cmn2, &pkt);

            /* Copy the original payload unchanged */
            encode_buf(encbuf, &encx, (udp_buf + idx), (udp_size - idx));
        }
        else
        {
            /* Already from a supernode. Nothing to modify, just pass to
             * destination. */

            traceDebug("Rx PACKET fwd unmodified");

            rec_buf = udp_buf;
            encx = udp_size;
        }

        /* Common section to forward the final product. */
        if (unicast)
        {
            try_forward(sss, &cmn, pkt.dstMac, rec_buf, encx);
        }
        else
        {
            try_broadcast(sss, &cmn, pkt.srcMac, rec_buf, encx);
        }
    }/* MSG_TYPE_PACKET */
    else if (msg_type == MSG_TYPE_REGISTER)
    {
        /* Forwarding a REGISTER from one edge to the next */

        n2n_REGISTER_t                  reg;
        n2n_common_t                    cmn2;
        uint8_t                         encbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx = 0;
        int                             unicast; /* non-zero if unicast */
        const uint8_t *                 rec_buf; /* either udp_buf or encbuf */

        sss->stats.last_fwd=now;
        decode_REGISTER( &reg, &cmn, udp_buf, &rem, &idx );

        unicast = (0 == is_multi_broadcast_mac(reg.dstMac));

        if (unicast)
        {
            traceDebug("Rx REGISTER %s -> %s %s",
                       mac2str(macbuf, reg.srcMac),
                       mac2str(macbuf2, reg.dstMac),
                       (from_supernode ? "from sn" : "local"));

            if (from_supernode)
            {
                memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

                /* We are going to add socket even if it was not there before */
                cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

                sockaddr2sock(&reg.sock, (struct sockaddr_storage *) sender_sock);

                rec_buf = encbuf;

                /* Re-encode the header. */
                encode_REGISTER(encbuf, &encx, &cmn2, &reg);

                /* Copy the original payload unchanged */
                encode_buf(encbuf, &encx, (udp_buf + idx), (udp_size - idx));
            }
            else
            {
                /* Already from a supernode. Nothing to modify, just pass to
                 * destination. */

                rec_buf = udp_buf;
                encx = udp_size;
            }

            try_forward(sss, &cmn, reg.dstMac, rec_buf, encx); /* unicast only */
        }
        else
        {
            traceError("Rx REGISTER with multicast destination");
        }
    }
    else if (msg_type == MSG_TYPE_REGISTER_ACK)
    {
        traceDebug("Rx REGISTER_ACK (NOT IMPLEMENTED) SHould not be via supernode");
    }
    else if (msg_type == MSG_TYPE_REGISTER_SUPER)
    {
        n2n_REGISTER_SUPER_t            reg;
        n2n_REGISTER_SUPER_ACK_t        ack;
        n2n_common_t                    cmn2;
        uint8_t                         ackbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx = 0;

        /* Edge requesting registration with us.  */
        
        sss->stats.last_reg_super = now;
        ++(sss->stats.reg_super);
        decode_REGISTER_SUPER(&reg, &cmn, udp_buf, &rem, &idx);

        init_cmn(&cmn2, n2n_register_super_ack,
                 N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE,
                 cmn.community);

        memcpy(&(ack.cookie), &(reg.cookie), sizeof(n2n_cookie_t));
        memcpy(ack.edgeMac, reg.edgeMac, sizeof(n2n_mac_t));
        ack.lifetime = reg_lifetime(sss);

        sockaddr2sock(&ack.sock, (struct sockaddr_storage *) sender_sock);

        ack.num_sn = 0; /* No backup */
        memset(&ack.sn_bak, 0, sizeof(n2n_sock_t));

        traceDebug("Rx REGISTER_SUPER for %s [%s]",
                   mac2str(macbuf, reg.edgeMac), sock2str(sockbuf, &ack.sock));

        update_edge(sss, reg.edgeMac, cmn.community, &ack.sock, now);

        encode_REGISTER_SUPER_ACK(ackbuf, &encx, &cmn2, &ack);

        sendto(sss->sock, ackbuf, encx, 0,
               (struct sockaddr *) sender_sock, sizeof(struct sockaddr_in));

        traceDebug("Tx REGISTER_SUPER_ACK for %s [%s]", macbuf, sockbuf);
    }

#ifdef N2N_MULTIPLE_SUPERNODES
    else if (msg_type == MSG_TYPE_FEDERATION)
    {
        //TODO check from supernode
        n2n_FEDERATION_t                fed;
        n2n_common_t                    cmn2;
        uint8_t                         ackbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx = 0;
        n2n_sock_t                      sender;
        sn_info_t *                     sni = NULL;
        sn_info_t *                     scan = NULL;

        decode_FEDERATION(&fed, &cmn, udp_buf, &rem, &idx);

        sockaddr2sock(&sender, (struct sockaddr_storage *) sender_sock);
        traceDebug("Rx FEDERATION from %s", sock2str(sockbuf, &sender));

        N2N_LIST_FOR_EACH(&sss->federation, scan)
        {
            if (0 == sock_equal(&scan->sock, &sender))
            {
                sni = scan;
                break;
            }
        }

        if (cmn.flags & N2N_FLAGS_FED_SUBSCRIBE)
        {
            /* Federation subscription request */
            if (sni)
            {
                traceWarning("Duplicated subscription from %s", sockbuf);
            }
            else
            {
                /* Add new federation member */
                sni = add_supernode_info(&sss->federation, &sender);
            }

            sni->timestamp = now;

            init_cmn(&cmn2, n2n_federation,
                     N2N_FLAGS_FROM_SUPERNODE | N2N_FLAGS_FED_ACK,
                     cmn.community);

            encode_FEDERATION(ackbuf, &encx, &cmn2, &fed);

            sendto(sss->sock, ackbuf, encx, 0,
                   (struct sockaddr *) sender_sock, sizeof(struct sockaddr_in));

            traceDebug("Tx FEDERATION ACK to %s", sockbuf);
        }
        else if (sni != NULL)
        {
            sni->timestamp = now;
        }
        else
        {
            traceError("FEDERATION ACK received from unknown src: %s", sockbuf);
        }
    }
    else if (msg_type == MSG_TYPE_QUERY_SUPER)
    {
        n2n_QUERY_SUPER_t       query;
        n2n_QUERY_SUPER_ACK_t   qack;
        n2n_common_t            cmn2;
        n2n_flags_t             flags = N2N_FLAGS_FROM_SUPERNODE;
        uint8_t                 ackbuf[N2N_SN_PKTBUF_SIZE];
        size_t                  encx = 0;
        sn_info_t *             scan = NULL;
        n2n_sock_t              sender;

        decode_QUERY_SUPER(&query, &cmn, udp_buf, &rem, &idx);
        traceDebug("Rx QUERY_SUPER ");//TODO from %s", sock2str(sockbuf, &(ack.sock)));

        if (from_supernode)
        {
            sockaddr2sock(&sender, (struct sockaddr_storage *) sender_sock);
        }
        else if (cmn.flags & N2N_FLAGS_FED_C)
        {
            /* Query received from edge looking for its community.
             * Search through the edges list to see if one of its
             * peers is registered. */
            peer_info_t *edge = find_peer_by_community(&sss->edges, cmn.community);
            if (edge)
                flags |= N2N_FLAGS_FED_C;
        }

        init_cmn(&cmn2, n2n_query_super_ack, flags, cmn.community);//TODO

        memcpy(&qack.cookie, &query.cookie, sizeof(n2n_cookie_t));

        qack.num_sn = 0;
        N2N_LIST_FOR_EACH(&sss->federation, scan)
        {
            if (from_supernode && (0 == sock_equal(&scan->sock, &sender)))
            {
                scan->timestamp = now;
                continue;
            }

            sock_cpy(&qack.members[ qack.num_sn++ ], &scan->sock);
            traceDebug(">>> Sending %s", sock2str(sockbuf, &qack.members[qack.num_sn-1]));//TODO remove
        }

        encode_QUERY_SUPER_ACK(ackbuf, &encx, &cmn2, &qack);

        sendto(sss->sock, ackbuf, encx, 0,
               (struct sockaddr *) sender_sock, sizeof(struct sockaddr_in));

        traceDebug("Tx QUERY_SUPER_ACK");//TODO to %s", sock2str(sockbuf, &(ack.sock)));
    }
    else if (msg_type == MSG_TYPE_QUERY_SUPER_ACK)
    {
        n2n_QUERY_SUPER_ACK_t       qack;
        sn_info_t *                 sni  = NULL;
        sn_info_t *           snqi = NULL;
        n2n_sock_t                  sender;

        sockaddr2sock(&sender, (struct sockaddr_storage *) sender_sock);
        traceDebug("Rx QUERY_SUPER_ACK from %s", sock2str(sockbuf, &sender));

        if (0 == find_known_supernode_by_sock(sss, &sender, &snqi, &sni))
        {
            /* QUERY_SUPER_ACK from known supernode */

            int i;

            decode_QUERY_SUPER_ACK(&qack, &cmn, udp_buf, &rem, &idx);

            if (snqi != NULL)
            {
                /* Response from a queried supernode */
                if (snqi->timestamp == 0)
                {
                    snqi->timestamp = now;
                    snqi->vouched = qack.num_sn;
                }
                else
                {
                    traceWarning("QUERY_SUPER_ACK already received from %s", sockbuf);
                    return 0;//TODO
                }
            }
            else if (sni != NULL)
            {
                /* Response from a federation supernode */
                sni->timestamp = now;
            }


            for(i = 0; i < qack.num_sn; i++)
            {
                n2n_sock_t *member = &qack.members[i];

                if (0 == find_known_supernode_by_sock(sss, member, &snqi, &sni))
                    continue;

                /* New supernode => save query information */
                add_supernode_info(&sss->queried_supernodes, member);
                traceInfo("Saved supernode address for query: %s", sock2str(sockbuf, member));
                send_query(sss, member);
            }
        }
        else
        {
            traceError("QUERY_SUPER_ACK received from unknown address: %s", sockbuf);
        }
    }
#endif

    else
    {
        /* Not a known message type */
        traceWarning("Unable to handle packet type %d: ignored", (signed int) msg_type);
    }


    return 0;
}


/******************************************************************************/


static int start_sn(n2n_sn_t *sss)
{

#if defined(N2N_HAVE_DAEMON)
    if (sss->daemon)
    {
        useSyslog = 1; /* traceEvent output now goes to syslog. */
        if (-1 == daemon(0, 0))
        {
            traceError("Failed to become daemon.");
            exit(-5);
        }
    }
#endif /* #if defined(N2N_HAVE_DAEMON) */

    traceDebug("traceLevel is %d", traceLevel);

    sss->sock = open_socket(sss->lport, 1 /*bind ANY*/);
    if (-1 == sss->sock)
    {
        traceError("Failed to open main socket. %s", strerror(errno));
        exit(-2);
    }
    traceNormal("supernode is listening on UDP %u (main)", sss->lport);

    sss->mgmt_sock = open_socket(sss->mport, 0 /* bind LOOPBACK */);
    if (-1 == sss->mgmt_sock)
    {
        traceError("Failed to open management socket. %s", strerror(errno));
        exit(-2);
    }
    traceNormal("supernode is listening on UDP %u (management)", sss->mport);

#ifdef N2N_MULTIPLE_SUPERNODES
    if (list_empty(&sss->queried_supernodes))
    {
        sss->snm_state = N2N_SNM_STATE_READY;
    }
    /*
    if (load_snm_info(&sss))
    {
        traceError("Failed to load SNM information. %s", strerror(errno));
        exit(-2);
    }
    */
#endif /* #ifdef N2N_MULTIPLE_SUPERNODES */

    traceNormal("supernode started");
    return 0;
}


/** Long lived processing entry point. Split out from main to simply
 *  daemonisation on some platforms. */
static int run_loop(n2n_sn_t *sss)
{
    uint8_t pktbuf[N2N_SN_PKTBUF_SIZE];
    int keep_running = 1;

#ifdef N2N_MULTIPLE_SUPERNODES
    fed_cb_t fed_callbacks[] = {
            federation_discovery,    /* NONE -> DISCOVERY */
            federation_subscription, /* DISCOVERY -> {READY, DISCOVERY} */
            federation_update        /* READY -> {READY, DISCOVERY} */
    };
#endif

    int      max_sock = 0;
    fd_set   proto_socket_mask;

    /* Setup prototype socket mask */
    FD_ZERO(&proto_socket_mask);
    FD_SET(sss->sock, &proto_socket_mask);
    FD_SET(sss->mgmt_sock, &proto_socket_mask);
    max_sock = MAX(sss->sock, sss->mgmt_sock);

    sss->start_time = time(NULL);

#ifdef N2N_MULTIPLE_SUPERNODES
    fed_callbacks[sss->snm_state](sss, sss->start_time);
#endif

    while (keep_running)
    {
        int              rc;
        ssize_t          bread;
        fd_set           socket_mask;
        struct timeval   wait_time;
        time_t           now = 0;

        socket_mask = proto_socket_mask;

        wait_time.tv_sec = 1;//0 TODO revert value
        wait_time.tv_usec = 0;
        rc = select(max_sock + 1, &socket_mask, NULL, NULL, &wait_time);

        now = time(NULL);

        if (rc > 0)
        {
            if (FD_ISSET(sss->sock, &socket_mask)) 
            {
                struct sockaddr_in  sender_sock;
                socklen_t           i;

                i = sizeof(sender_sock);
                bread = recvfrom(sss->sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0/*flags*/,
                                 (struct sockaddr *) &sender_sock, (socklen_t*) &i);

                if (bread < 0) /* For UDP bread of zero just means no data (unlike TCP). */
                {
                    /* The fd is no good now. Maybe we lost our interface. */
                    traceError("recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
                    keep_running = 0;
                    break;
                }

                /* We have a datagram to process */
                if (bread > 0)
                {
                    /* And the datagram has data (not just a header) */
                    process_udp(sss, &sender_sock, pktbuf, bread, now);
                }
            }

            if (FD_ISSET(sss->mgmt_sock, &socket_mask)) 
            {
                struct sockaddr_in  sender_sock;
                size_t              i;

                i = sizeof(sender_sock);
                bread = recvfrom(sss->mgmt_sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0/*flags*/,
                                 (struct sockaddr *) &sender_sock, (socklen_t*) &i);

                if (bread <= 0)
                {
                    traceError("recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
                    keep_running = 0;
                    break;
                }

                /* We have a datagram to process */
                process_mgmt(sss, &sender_sock, pktbuf, bread, now);
            }
        }
        else
        {
            traceDebug("timeout");
        }

        purge_expired_registrations(&(sss->edges));

#ifdef N2N_MULTIPLE_SUPERNODES
        /* TODO comment */
        fed_callbacks[sss->snm_state](sss, now);
#endif

    } /* while */

    deinit_sn(sss);

    return 0;
}


/******************************************************************************
 *
 * COMMAND LINE ARGUMENTS
 *
 */

static const struct option long_options[] = {
  { "foreground",      no_argument,       NULL, 'f' },
  { "local-port",      required_argument, NULL, 'l' },
  { "management-port", required_argument, NULL, 't' },
#ifdef N2N_MULTIPLE_SUPERNODES
  { "supernode",       required_argument, NULL, 'i' },
#endif
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { NULL,              0,                 NULL,  0  }
};


/**
 * Help message to print if the command line arguments are not valid.
 */
static void help(int argc, char * const argv[])
{
    fprintf(stderr, "%s usage\n", argv[0]);
    fprintf(stderr, "-l <lport>\tSet UDP main listen port to <lport>\n");
    fprintf(stderr, "-t <mport>\tSet UDP management port to <mport>\n");

#ifdef N2N_MULTIPLE_SUPERNODES
    fprintf(stderr, "-i <ip:port>\tSet running SNM supernode to <ip:port>\n");
#endif

#if defined(N2N_HAVE_DAEMON)
    fprintf(stderr, "-f        \tRun in foreground.\n");
#endif /* #if defined(N2N_HAVE_DAEMON) */
    fprintf(stderr, "-v        \tIncrease verbosity. Can be used multiple times.\n");
    fprintf(stderr, "-h        \tThis help message.\n");
    fprintf(stderr, "\n");
    exit(1);
}


static void read_args(int argc, char * const argv[], n2n_sn_t *sss)
{
    int opt;

#ifdef N2N_MULTIPLE_SUPERNODES
    const char *optstring = "fl:t:i:vh";
#else
    const char *optstring = "fl:t:vh";
#endif

    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'l': /* local-port */
        {
            sss->lport = atoi(optarg);
            break;
        }
        case 't': /* management port */
        {
            sss->mport = atoi(optarg);
            break;
        }

#ifdef N2N_MULTIPLE_SUPERNODES
        case 'i':
        {
            n2n_sock_t sock;
            if (0 != str2sock(&sock, optarg))
            {
                traceError("Invalid supernode address: %s", optarg);
                exit(-1);//TODO
            }

            add_supernode_info(&sss->queried_supernodes, &sock);
            traceInfo("Saved supernode address for query: %s", optarg);
            //update_supernodes(&sss->supernodes, &sn);
            break;
        }
#endif

        /* Miscellaneous parameters */

        case 'f': /* foreground */
        {
            sss->daemon = 0;
            break;
        }
        case 'v': /* verbose */
        {
            ++traceLevel;
            break;
        }
        case 'h': /* help */
        {
            help(argc, argv);
            break;
        }
        }
    }
}


/**
 * Main program entry point from kernel.
 */
int main(int argc, char * const argv[])
{
    n2n_sn_t sss;
    init_sn(&sss);

    read_args(argc, argv, &sss);

    if (start_sn(&sss) != 0)
    {
        traceError("Failed in start_sn");
        exit(1);
    }

    return run_loop(&sss);
}


