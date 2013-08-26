/**
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
 *               Richard Andrews <andrews@ntop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 * Code contributions courtesy of:
 * Don Bindner <don.bindner@gmail.com>
 * Sylwester Sosnowski <syso-n2n@no-route.org>
 * Wilfried "Wonka" Klaebe
 * Lukasz Taczuk
 *
 */

#include "n2n.h"
#include "n2n_transforms.h"
#include "n2n_log.h"
#include "n2n_utils.h"
#include "edge.h"
#include "edge_mgmt.h"
#include "tuntap.h"
#include "minilzo.h"
#include <assert.h>

#ifdef N2N_MULTIPLE_SUPERNODES
#include "sn_multiple.h"
#endif


//TODO

#define N2N_DEFAULT_IFACE       "edge0"
#define DEFAULT_NET_MASK        "255.255.255.0"



/* Work-memory needed for compression. Allocate memory in units
 * of `lzo_align_t' (instead of `char') to make sure it is properly aligned.
 */

/* #define HEAP_ALLOC(var,size)						\ */
/*   lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ] */

/* static HEAP_ALLOC(wrkmem,LZO1X_1_MEM_COMPRESS); */

/* ******************************************************* */






/** Return the IP address of the current supernode in the ring. */
static const n2n_sock_t *supernode_ip(const n2n_edge_t *eee)
{
    return &eee->supernodes[eee->sn_idx];
}


static void send_packet2net(n2n_edge_t *eee,
	        uint8_t *decrypted_msg, size_t len);


/******************************************************************************/


/** Initialize an edge to defaults.
 *
 *  This also initializes the NULL transform operation opstruct.
 */
static int edge_init(n2n_edge_t *eee)
{
#ifdef WIN32
    initWin32();
#endif
    memset(eee, 0, sizeof(n2n_edge_t));
    eee->start_time = time(NULL);

    transop_null_init(&(eee->transop[N2N_TRANSOP_NULL_IDX]));
    transop_twofish_init(&(eee->transop[N2N_TRANSOP_TF_IDX]));
    transop_aes_init(&(eee->transop[N2N_TRANSOP_AESCBC_IDX]));

    eee->tx_transop_idx = N2N_TRANSOP_NULL_IDX; /* No guarantee the others have been setup */

    eee->daemon = 1; /* By default run in daemon mode. */
    eee->re_resolve_supernode_ip = 0;
    /* keyschedule set to NULLs by memset */
    /* community_name set to NULLs by memset */
    eee->null_transop        = 0;
    eee->udp_sock            = -1;
    eee->udp_mgmt_sock       = -1;
    eee->ip_mode             = N2N_IPM_STATIC;
    eee->allow_routing       = 0;
    eee->drop_multicast      = 1;
    list_head_init(&eee->known_peers);
    list_head_init(&eee->pending_peers);
    eee->last_register_req   = 0;
    eee->register_lifetime   = REGISTER_SUPER_INTERVAL_DFL;
    eee->last_p2p            = 0;
    eee->last_sup            = 0;
    eee->sup_attempts        = N2N_EDGE_SUP_ATTEMPTS;

    if (lzo_init() != LZO_E_OK)
    {
        traceError("LZO compression error");
        return (-1);
    }

#ifdef N2N_MULTIPLE_SUPERNODES
    eee->snm_sock = -1;
    eee->snm_discovery_state = N2N_SNM_STATE_DISCOVERY;
    memset(&eee->supernodes, 0, sizeof(sn_list_t));
#endif

    //TODO
    memset(&(eee->supernode), 0, sizeof(eee->supernode));
    eee->supernode.family = AF_INET;

    //TODO

#ifndef WIN32
    /* Device name matters on non-Windows environments */
    strcpy(eee->device.dev_name, N2N_DEFAULT_IFACE);
#endif
    eee->device.device_mask = inet_addr("255.255.255.0");//TODO
    eee->device.mtu = DEFAULT_MTU;

    /*
    // TUNTAP: tuntap_dev_name, ip_mode, ip_addr, netmask, device_mac, mtu
    //char    tuntap_dev_name[N2N_IFNAMSIZ] = "edge0";
    char    ip_mode[N2N_IF_MODE_SIZE] = "static";
    char    ip_addr[N2N_NETMASK_STR_SIZE] = "";
    char    netmask[N2N_NETMASK_STR_SIZE] = "255.255.255.0";
    //int     mtu = DEFAULT_MTU;
*/
    return (0);
}



/* Called in main() after options are parsed. */
static int edge_init_twofish(n2n_edge_t *eee, uint8_t *encrypt_pwd, uint32_t encrypt_pwd_len)
{
    return transop_twofish_setup(&(eee->transop[N2N_TRANSOP_TF_IDX]), 0, encrypt_pwd, encrypt_pwd_len);
}


/**
 * Find the transop op-struct for the transform enumeration required.
 * @return - index into the transop array, or -1 on failure.
 */
static int transop_enum_to_index(n2n_transform_t id)
{
    switch (id)
    {
    case N2N_TRANSFORM_ID_TWOFISH:
        return N2N_TRANSOP_TF_IDX;
        break;
    case N2N_TRANSFORM_ID_NULL:
        return N2N_TRANSOP_NULL_IDX;
        break;
    case N2N_TRANSFORM_ID_AESCBC:
        return N2N_TRANSOP_AESCBC_IDX;
        break;
    default:
        return -1;
    }
}


/**
 * Choose the transop for Tx. This should be based on the newest valid
 * cipherspec in the key schedule.
 *
 * Never fall back to NULL transform unless no key sources were specified. It is
 * better to render edge inoperative than to expose user data in the clear. In
 * the case where all SAs are expired an arbitrary transform will be chosen for
 * Tx. It will fail having no valid SAs but one must be selected.
 */
static size_t edge_choose_tx_transop(const n2n_edge_t *eee)//TODO make inline
{
    if (eee->null_transop)
    {
        return N2N_TRANSOP_NULL_IDX;
    }

    return eee->tx_transop_idx;
}


/**
 * Called periodically to roll keys and do any periodic maintenance in the
 * transform operations state machines.
 */
static int n2n_tick_transop(n2n_edge_t *eee, time_t now)
{
    n2n_tostat_t tst;
    size_t trop = eee->tx_transop_idx;

    /* Tests are done in order that most preferred transform is last and causes
     * tx_transop_idx to be left at most preferred valid transform. */
    tst = (eee->transop[N2N_TRANSOP_NULL_IDX].tick)(&(eee->transop[N2N_TRANSOP_NULL_IDX]), now);
    tst = (eee->transop[N2N_TRANSOP_AESCBC_IDX].tick)(&(eee->transop[N2N_TRANSOP_AESCBC_IDX]), now);
    if (tst.can_tx)
    {
        traceDebug("can_tx AESCBC (idx=%u)", (unsigned int) N2N_TRANSOP_AESCBC_IDX);
        trop = N2N_TRANSOP_AESCBC_IDX;
    }

    tst = (eee->transop[N2N_TRANSOP_TF_IDX].tick)(&(eee->transop[N2N_TRANSOP_TF_IDX]), now);
    if (tst.can_tx)
    {
        traceDebug("can_tx TF (idx=%u)", (unsigned int) N2N_TRANSOP_TF_IDX);
        trop = N2N_TRANSOP_TF_IDX;
    }

    if (trop != eee->tx_transop_idx)
    {
        eee->tx_transop_idx = trop;
        traceNormal("Chose new tx_transop_idx=%u", (unsigned int) (eee->tx_transop_idx));
    }

    return 0;
}



/**
 * Read in a key-schedule file, parse the lines and pass each line to the
 * appropriate trans_op for parsing of key-data and adding key-schedule
 * entries. The lookup table of time->trans_op is constructed such that
 * encoding can be passed to the correct trans_op. The trans_op internal table
 * will then determine the best SA for that trans_op from the key schedule to
 * use for encoding.
 */
/* TODO static*/ int edge_init_keyschedule(n2n_edge_t *eee)
{

#define N2N_NUM_CIPHERSPECS 32

    int retval = -1;
    ssize_t numSpecs = 0;
    n2n_cipherspec_t specs[N2N_NUM_CIPHERSPECS];
    size_t i;
    time_t now = time(NULL);

    numSpecs = n2n_read_keyfile(specs, N2N_NUM_CIPHERSPECS, eee->keyschedule);

    if (numSpecs > 0)
    {
        traceNormal("keyfile = %s read -> %d specs.\n", optarg, (signed int) numSpecs);

        for (i = 0; i < (size_t) numSpecs; ++i)
        {
            int idx;

            idx = transop_enum_to_index(specs[i].t);

            switch (idx)
            {
            case N2N_TRANSOP_TF_IDX:
            case N2N_TRANSOP_AESCBC_IDX:
            {
                retval = (eee->transop[idx].addspec)(&(eee->transop[idx]),
                                                     &(specs[i]));
                break;
            }
            default:
                retval = -1;
                break;
            }

            if (0 != retval)
            {
                traceError("keyschedule failed to add spec[%u] to transop[%d].\n",
                           (unsigned int) i, idx);

                return retval;
            }
        }

        n2n_tick_transop(eee, now);
    }
    else
    {
        traceError("Failed to process '%s'", eee->keyschedule);
    }

    return retval;
}


/**
 * Deinitialize the edge and deallocate any owned memory.
 */
static void edge_deinit(n2n_edge_t *eee)
{
    if (eee->udp_sock >= 0)
    {
        closesocket( eee->udp_sock);
    }

    if (eee->udp_mgmt_sock >= 0)
    {
        closesocket(eee->udp_mgmt_sock);
    }

    list_clear(&eee->pending_peers);
    list_clear(&eee->known_peers);

    (eee->transop[N2N_TRANSOP_TF_IDX].deinit)(&eee->transop[N2N_TRANSOP_TF_IDX]);
    (eee->transop[N2N_TRANSOP_NULL_IDX].deinit)(&eee->transop[N2N_TRANSOP_NULL_IDX]);

#ifdef N2N_MULTIPLE_SUPERNODES
    if (eee->snm_sock >= 0)
    {
        closesocket(eee->snm_sock);
    }
    eee->snm_discovery_state = 0;

    list_clear(&eee->supernodes.head);
#endif
}


/******************************************************************************
 *
 * EDGE <-> SUPERNODE COMMUNICATION
 *
 */

/**
 * Send a REGISTER_SUPER packet to the current supernode.
 */
static void send_register_super(n2n_edge_t *eee, const n2n_sock_t *supernode)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    ssize_t sent;
    n2n_common_t cmn;
    n2n_REGISTER_SUPER_t reg;
    n2n_sock_str_t sockbuf;

    init_cmn(&cmn, n2n_register_super, 0, eee->community_name);

    for (idx = 0; idx < N2N_COOKIE_SIZE; ++idx)
    {
        eee->last_cookie[idx] = rand() % 0xff;
    }

    memset(&reg, 0, sizeof(reg));
    memcpy(reg.cookie, eee->last_cookie, N2N_COOKIE_SIZE);
    reg.auth.scheme = 0; /* No auth yet */

    idx = 0;
    encode_mac(reg.edgeMac, &idx, eee->device.mac_addr);

    idx = 0;
    encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

    traceInfo("send REGISTER_SUPER to %s", sock2str(sockbuf, supernode));

    sent = sendto_sock(eee->udp_sock, pktbuf, idx, supernode);

}


/**
 * @brief Check to see if we should re-register with the supernode.
 *
 *  This is frequently called by the main loop.
 */
static void update_supernode_reg(n2n_edge_t *eee, time_t nowTime)
{
    if (eee->sn_wait && (nowTime > (eee->last_register_req + (eee->register_lifetime / 10))))
    {
        /* fall through */
        traceDebug("update_supernode_reg: doing fast retry.");
    }
    else if (nowTime < (eee->last_register_req + eee->register_lifetime))
    {
        return; /* Too early */
    }

    if (0 == eee->sup_attempts)
    {
        /* Give up on that supernode and try the next one. */
        ++(eee->sn_idx);

        if (eee->sn_idx >= eee->sn_num)
        {
            /* Got to end of list, go back to the start. Also works for list of one entry. */
            eee->sn_idx = 0;
        }

#ifdef N2N_MULTIPLE_SUPERNODES
        if (eee->reg_sn.timestamp < eee->last_register_req)      /* supernode didn't respond */
        {
            if (sn_cmp(&eee->supernode, &eee->reg_sn.sn) == 0)   /* supernode is the main one */
            {
                supernode2addr(&(eee->supernode), eee->sn_ip_array[eee->sn_idx]);

                traceWarning("Changed active supernode to %s", eee->sn_ip_array[eee->sn_idx]);
            }
#endif
        traceWarning("Supernode not responding - moving to %u of %u",
                   (unsigned int)eee->sn_idx, (unsigned int)eee->sn_num );

#ifdef N2N_MULTIPLE_SUPERNODES
        }
#endif

        eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
    }
    else
    {
        --(eee->sup_attempts);
    }

#ifdef N2N_MULTIPLE_SUPERNODES
    /* setting next supernode to register to */
    supernode2addr(&(eee->reg_sn.sn), eee->sn_ip_array[eee->sn_idx]);
    eee->reg_sn.timestamp = 0;
    send_register_super(eee, &(eee->reg_sn.sn));

#else
    if (eee->re_resolve_supernode_ip || (eee->sn_num > 1))
    {
        //TODO supernode2addr(&(eee->supernode), eee->sn_ip_array[eee->sn_idx]);
        eee->supernode = eee->supernodes[eee->sn_idx];
    }

    send_register_super(eee, &(eee->supernode));
#endif

    {
        n2n_sock_str_t sockstr;
        traceDebug("Registering with supernode (%s) (attempts left %u)",
                   sock2str(sockstr, supernode_ip(eee)),
                   (unsigned int) eee->sup_attempts);
    }

    eee->sn_wait = 1;

    /* REVISIT: turn-on gratuitous ARP with config option. */
    /* send_grat_arps(sock_fd, is_udp_sock); */

    eee->last_register_req = nowTime;
}


/******************************************************************************
 *
 * EDGE <-> EDGE (P2P) COMMUNICATION
 *
 */

/**
 * Send a REGISTER packet to another edge.
 */
static void send_register(n2n_edge_t *eee, const n2n_sock_t *remote_peer)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    ssize_t sent;
    n2n_common_t cmn;
    n2n_REGISTER_t reg;
    n2n_sock_str_t sockbuf;

    init_cmn(&cmn, n2n_register, 0, eee->community_name);
    memset(&reg, 0, sizeof(reg));

    idx = 0;
    encode_uint32(reg.cookie, &idx, 123456789);
    idx = 0;
    encode_mac(reg.srcMac, &idx, eee->device.mac_addr);

    idx = 0;
    encode_REGISTER(pktbuf, &idx, &cmn, &reg);

    traceInfo("send REGISTER %s", sock2str(sockbuf, remote_peer));
    sent = sendto_sock(eee->udp_sock, pktbuf, idx, remote_peer);
}


/**
 * Send a REGISTER_ACK packet to a peer edge.
 */
static void send_register_ack(n2n_edge_t            *eee,
                              const n2n_sock_t      *remote_peer,
                              const n2n_REGISTER_t  *reg)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    ssize_t sent;
    n2n_common_t cmn;
    n2n_REGISTER_ACK_t ack;
    n2n_sock_str_t sockbuf;

    init_cmn(&cmn, n2n_register_ack, 0, eee->community_name);

    memset(&ack, 0, sizeof(ack));
    memcpy(ack.cookie, reg->cookie, N2N_COOKIE_SIZE);
    memcpy(ack.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
    memcpy(ack.dstMac, reg->srcMac, N2N_MAC_SIZE);

    idx = 0;
    encode_REGISTER_ACK(pktbuf, &idx, &cmn, &ack);

    traceInfo("send REGISTER_ACK %s", sock2str(sockbuf, remote_peer));

    sent = sendto_sock(eee->udp_sock, pktbuf, idx, remote_peer);
}


/** NOT IMPLEMENTED
 *
 *  This would send a DEREGISTER packet to a peer edge or supernode to indicate
 *  the edge is going away.
 */
static void send_deregister(n2n_edge_t *eee, 
                            n2n_sock_t *remote_peer)
{
    /* Marshall and send message */
}


/**
 * Start the registration process.
 *
 * If the peer is already in pending_peers, ignore the request.
 * If not in pending_peers, add it and send a REGISTER.
 *
 * If hdr is for a direct peer-to-peer packet, try to register back to sender
 * even if the MAC is in pending_peers. This is because an incident direct
 * packet indicates that peer-to-peer exchange should work so more aggressive
 * registration can be permitted (once per incoming packet) as this should only
 * last for a small number of packets..
 *
 * Called from the main loop when Rx a packet for our device mac.
 */
static void try_send_register(n2n_edge_t *eee, uint8_t from_supernode,
                              const n2n_mac_t mac, const n2n_sock_t *peer)
{
    /* REVISIT: purge of pending_peers not yet done. */
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    struct peer_info *scan = find_peer_by_mac(&eee->pending_peers, mac);
    if (scan)
        return;

    scan = calloc(1, sizeof(struct peer_info));

    memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
    scan->sock = *peer;
    scan->last_seen = time(NULL); /* Don't change this it marks the pending peer for removal. */

    peer_list_add(&eee->pending_peers, scan);

    traceDebug("=== new pending %s -> %s",
               mac2str(mac_buf, scan->mac_addr),
               sock2str(sockbuf, &(scan->sock)));

    traceInfo("Pending peers list size=%u",
               (unsigned int) list_size(&eee->pending_peers));

    /* trace Sending REGISTER */

    send_register(eee, &(scan->sock));

    /* pending_peers now owns scan. */
}


/**
 * Move the peer from the pending_peers list to the known_peers lists.
 *
 * peer must be a pointer to an element of the pending_peers list.
 *
 * Called by main loop when Rx a REGISTER_ACK.
 */
static void set_peer_operational(n2n_edge_t *eee,
                                 const n2n_mac_t mac, const n2n_sock_t *peer)
{
    struct peer_info *prev = NULL;
    struct peer_info *scan;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    traceInfo("set_peer_operational: %s -> %s",
              mac2str(mac_buf, mac), sock2str(sockbuf, peer));

    scan = find_peer_by_mac_for_removal(&eee->pending_peers, mac, &prev);

    if (scan == NULL)
    {
        traceDebug("Failed to find sender in pending_peers.");
        return;
    }

    /* Remove scan from pending_peers. */
    if (prev)
        prev->list.next = scan->list.next;
    else
        eee->pending_peers.node.next = scan->list.next;

    scan->sock = *peer;
    scan->last_seen = time(NULL);

    /* Add scan to known_peers. */
    list_add(&eee->known_peers, &scan->list);

    traceDebug("=== new peer %s -> %s",
               mac2str(mac_buf, scan->mac_addr), sock2str(sockbuf, peer));
    traceInfo("Pending peers list size=%u",
              (unsigned int) list_size(&eee->pending_peers));
    traceInfo("Operational peers list size=%u",
              (unsigned int) list_size(&eee->known_peers));
}


/**
 * Keep the known_peers list straight.
 *
 *  Ignore broadcast L2 packets, and packets with invalid public_ip.
 *  If the dst_mac is in known_peers make sure the entry is correct:
 *  - if the public_ip socket has changed, erase the entry
 *  - if the same, update its last_seen = when
 */
static void update_peer_address(n2n_edge_t *eee, uint8_t from_supernode,
                                const n2n_mac_t mac, const n2n_sock_t *peer,
                                time_t when)
{
    struct peer_info *scan = NULL;
    struct peer_info *prev = NULL; /* use to remove bad registrations. */
    n2n_sock_str_t sockbuf1;
    n2n_sock_str_t sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t mac_buf;

    if (is_empty_ip_address(peer))
        /* Not to be registered. */
        return;

    if (is_broadcast_mac(mac))
        /* Not to be registered. */
        return;

    scan = find_peer_by_mac_for_removal(&eee->known_peers, mac, &prev);

    if (NULL == scan)
        /* Not in known_peers. */
        return;

    if (0 != sock_equal(&scan->sock, peer))
    {
        if (0 == from_supernode)
        {
            traceNormal("Peer changed %s: %s -> %s",
                        mac2str(mac_buf, scan->mac_addr),
                        sock2str(sockbuf1, &scan->sock),
                        sock2str(sockbuf2, peer));

            /* The peer has changed public socket. It can no longer
             * be assumed to be reachable. Remove the peer. */
            if (NULL == prev)
            {
                /* scan was head of list */
                eee->known_peers.node.next = scan->list.next;
            }
            else
            {
                prev->list.next = scan->list.next;
            }
            free(scan);

            try_send_register(eee, from_supernode, mac, peer);
        }
        else
        {
            /* Don't worry about what the supernode reports,
             * it could be seeing a different socket. */
        }
    }
    else
    {
        /* Found and unchanged. */
        scan->last_seen = when;
    }
}


/**
 * Update the last_seen time for this peer, or get registered.
 */
static void check_peer(n2n_edge_t *eee, uint8_t from_supernode,
                       const n2n_mac_t mac, const n2n_sock_t *peer)
{
    struct peer_info *scan = find_peer_by_mac(&eee->known_peers, mac);

    if (NULL == scan)
    {
        /* Not in known_peers - start the REGISTER process. */
        try_send_register(eee, from_supernode, mac, peer);
    }
    else
    {
        /* Already in known_peers. */
        update_peer_address(eee, from_supernode, mac, peer, time(NULL));
    }
}


/**
 * @return 1 if destination is a peer, 0 if destination is supernode
 */
static int find_peer_destination(n2n_edge_t *eee,
                                 const n2n_mac_t mac, n2n_sock_t *destination)
{
    const struct peer_info *scan = NULL;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    int retval = 0;

    traceDebug("Searching destination peer for MAC %02X:%02X:%02X:%02X:%02X:%02X",
               mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
               mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);

    N2N_LIST_FOR_EACH(&eee->known_peers, scan)
    {
        traceDebug("Evaluating peer [MAC=%02X:%02X:%02X:%02X:%02X:%02X]",
                   scan->mac_addr[0] & 0xFF, scan->mac_addr[1] & 0xFF, scan->mac_addr[2] & 0xFF,
                   scan->mac_addr[3] & 0xFF, scan->mac_addr[4] & 0xFF, scan->mac_addr[5] & 0xFF);

        if (scan->last_seen > 0 && mac_equal(mac, scan->mac_addr))
        {
            memcpy(destination, &scan->sock, sizeof(n2n_sock_t));
            retval = 1;
            break;
        }
    }

    if (0 == retval)
    {
        memcpy(destination, &(eee->supernode), sizeof(struct sockaddr_in));
    }

    traceDebug("find_peer_destination (%s) -> [%s]",
               mac2str(mac_buf, mac), sock2str(sockbuf, destination));

    return retval;
}


#ifdef N2N_MULTIPLE_SUPERNODES

static int load_supernodes(n2n_edge_t *eee)
{
    size_t i;
    n2n_sock_t sn;

    /* read the supernode addresses from file */
    sprintf(eee->supernodes.filename, "EDGE_SN_%s", eee->community_name);

    if (read_supernodes_from_file( eee->supernodes.filename,
                                  &eee->supernodes.head))
    {
        traceError("Failed read supernodes from file. %s", strerror(errno));
        exit(-2);
    }

    if (list_empty(&eee->supernodes.head))
    {
        /* first startup: save the sn addresses given as cmd line params */

        for (i = 0; i < eee->sn_num; ++i)
        {
            /* updating initial supernode list */
            supernode2addr(&sn, eee->sn_ip_array[i]);
            update_supernodes(&eee->supernodes, &sn);
        }

        /* reset sn_ip_array */
        eee->sn_num = 0;
        memset(eee->sn_ip_array, 0, N2N_EDGE_NUM_SUPERNODES * sizeof(n2n_sn_name_t));
    }
    else
    {
        /* fill sn_ip_array */
        struct sn_info *sni = NULL;
        eee->sn_num = 0;

        N2N_LIST_FOR_EACH_ENTRY(sni, &eee->supernodes.head)
        {
            sock2str(eee->sn_ip_array[eee->sn_num++], &sni->sn);
        }

        /* set registering supernode */
        supernode2addr(&eee->reg_sn.sn, eee->sn_ip_array[0]);
        eee->reg_sn.timestamp = 0;

        eee->snm_discovery_state = N2N_SNM_STATE_READY;
    }

    return eee->sn_num;
}

static int add_supernode(n2n_edge_t *eee, n2n_sock_t *sn)
{
    int new_one = 0;

    if (eee->sn_num == N2N_EDGE_NUM_SUPERNODES)
    {
        traceError("Already have MAX supernodes addresses");
        return -1;
    }

    new_one = update_and_save_supernodes(&eee->supernodes, sn, 1);

    if (new_one)
    {
        n2n_sock_str_t sock_str;
        sock2str(sock_str, sn);

        strncpy((eee->sn_ip_array[eee->sn_num]), sock_str, N2N_EDGE_SN_HOST_SIZE);

        traceDebug("Added supernode[%u] = %s\n", eee->sn_num, sock_str);

        ++eee->sn_num;
    }

    return 0;
}

static void edge_send_snm_req(n2n_edge_t *eee, n2n_sock_t *sn);

static int sn_rank(const struct sn_info *sni)
{
    int delta = N2N_MAX_COMM_PER_SN - sni->communities_num;
    delta = MAX(delta, 1);
    return (int) (sni->timestamp * 100 / delta);
}

static int sn_cmp_rank_asc(const void *l, const void *r)
{
    return (sn_rank((const struct sn_info *) l) -
            sn_rank((const struct sn_info *) r));
}

static void supernodes_discovery(n2n_edge_t *eee, time_t nowTime)
{
    int i;
    struct sn_info *crt = NULL, *prev = NULL;

    if (nowTime - eee->start_time < N2N_SUPER_DISCOVERY_INTERVAL)
    {
        return;
    }

    if (eee->snm_discovery_state == N2N_SNM_STATE_DISCOVERY)
    {
        list_sort(&eee->supernodes.head, sn_cmp_rank_asc);

        /* save the best supernodes */
        i   = 0;
        crt = N2N_LIST_FIRST_ENTRY(&eee->supernodes.head, struct sn_info);

        while (i < N2N_MIN_SN_PER_COMM && crt != NULL)
        {
            i++;
            prev = crt;
            crt  = N2N_LIST_NEXT_ENTRY(crt);
        }

        /* if none, give it another try */
        if (i == 0)
            return;

        /* remove the rest */
        list_clear(&prev->list);//TODO

        eee->snm_discovery_state = N2N_SNM_STATE_REQ_ADV;

        /* send requests for ADV */
        N2N_LIST_FOR_EACH_ENTRY(crt, &eee->supernodes.head)
        {
            edge_send_snm_req(eee, &crt->sn);
        }

        /* clear supernodes */
        list_clear(&eee->supernodes.head);
    }
    else if (eee->snm_discovery_state == N2N_SNM_STATE_REQ_ADV)
    {
        //TODO rediscovery
    }
}

static void deregister_supernodes(n2n_edge_t *eee)
{
    struct sn_info *sni = NULL;

    N2N_LIST_FOR_EACH_ENTRY(sni, &eee->supernodes.head)
    {
        send_deregister(eee, &sni->sn);
    }
}

static void edge_send_snm_req(n2n_edge_t *eee, n2n_sock_t *sn)
{
    uint8_t          pktbuf[N2N_PKT_BUF_SIZE];
    size_t           idx;
    snm_hdr_t        hdr;
    n2n_SNM_REQ_t    req;
    snm_comm_name_t  comm;
    n2n_sock_str_t   sockbuf;

    hdr.type    = SNM_TYPE_REQ_LIST_MSG;
    hdr.seq_num = 0;
    SET_E(hdr.flags);   /* request from edge */
    SET_N(hdr.flags);   /* request contains community name*/

    if (eee->snm_discovery_state == N2N_SNM_STATE_DISCOVERY)
        SET_S(hdr.flags);    /* request supernodes */
    else
        SET_A(hdr.flags);    /* request advertise */

    /* fill community name */
    comm.size = strlen((const char *) eee->community_name);
    memcpy(comm.name, eee->community_name, comm.size);

    req.comm_num = 1;
    req.comm_ptr = &comm;

    idx = 0;
    encode_SNM_REQ(pktbuf, &idx, &hdr, &req);

    log_SNM_hdr(&hdr);
    log_SNM_REQ(&req);
    traceInfo("### Tx N2N SNM_REQ to %s", sock2str(sockbuf, sn));

    sendto_sock(eee->snm_sock, pktbuf, idx, sn);
}

static void readFromSNMSocket(n2n_edge_t *eee)
{
    snm_hdr_t           hdr;
    uint8_t             udp_buf[N2N_PKT_BUF_SIZE];
    ssize_t             recvlen;
    size_t              rem;
    size_t              idx;
    size_t              msg_type;
    struct sockaddr_in  sender_sock;
    n2n_sock_t          sender;
    n2n_sock_str_t      sockbuf;

    size_t              i;
    time_t              now = time(NULL);

    i = sizeof(sender_sock);
    recvlen = recvfrom(eee->snm_sock, udp_buf, N2N_PKT_BUF_SIZE, 0/*flags*/,
                       (struct sockaddr *) &sender_sock, (socklen_t*) &i);
    if (recvlen < 0)
    {
        traceError("recvfrom failed with %s", strerror(errno));
        return;
    }

    sender.family = AF_INET; /* udp_sock was opened PF_INET v4 */
    sender.port   = ntohs(sender_sock.sin_port);
    memcpy(&(sender.addr.v4), &(sender_sock.sin_addr.s_addr), IPV4_SIZE);

    traceInfo("### Rx N2N SNM (%u) from %s",
               recvlen, sock2str(sockbuf, &sender));

    rem = recvlen;
    idx = 0;
    if (decode_SNM_hdr(&hdr, udp_buf, &rem, &idx) < 0)
    {
        traceError("Failed to decode header");
        return;
    }
    log_SNM_hdr(&hdr);

    msg_type = hdr.type;

    if (msg_type == SNM_TYPE_RSP_LIST_MSG)
    {
        n2n_SNM_INFO_t info;

        if (eee->snm_discovery_state == N2N_SNM_STATE_READY)
        {
            traceError("Received SNM RSP but edge is READY");
            return;
        }
        
        decode_SNM_INFO(&info, &hdr, udp_buf, &rem, &idx);
        log_SNM_INFO(&info);

        if (GET_A(hdr.flags))
        {
            /* supernode accepted community */

            if (info.comm_num != 1)
            {
                traceError("Invalid ADV response: Community number=%d",
                           info.comm_num);
                return;
            }
            if (memcmp(eee->community_name, info.comm_ptr[0].name, info.comm_ptr[0].size))
            {
                traceError("Invalid ADV community name: %s",
                           info.comm_ptr[0].name);
                return;
            }

            /* clear supernodes list */
            list_clear(&eee->supernodes.head);

            for (i = 0; i < info.sn_num; i++)
            {
                n2n_sock_t *sn = &info.sn_ptr[i];

                if (sn_is_zero_addr(sn))
                    sn_cpy_addr(sn, &sender);

                if (add_supernode(eee, sn))
                    break;
            }

            eee->snm_discovery_state = N2N_SNM_STATE_READY;
        }
        else
        {
            /* still searching for supernodes */

            struct sn_info *sni = sn_find(&eee->supernodes.head, &sender);
            sni->communities_num = info.comm_num;
            sni->timestamp = now - sni->timestamp; /* set response time */

            for (i = 0; i < info.sn_num; i++)
            {
                n2n_sock_t *sn = &info.sn_ptr[i];

                if (!sn_find(&eee->supernodes.head, sn))
                {
                    sni = add_new_supernode(&eee->supernodes.head, sn);
                    sni->timestamp = now;
                    edge_send_snm_req(eee, sn);
                }
            }
        }
    }
    else if (msg_type == SNM_TYPE_ADV_MSG)
    {
        n2n_SNM_ADV_t adv;
        decode_SNM_ADV(&adv, &hdr, udp_buf, &rem, &idx);
        log_SNM_ADV(&adv);

        if (sn_is_zero_addr(&adv.sn))
        {
            sn_cpy_addr(&adv.sn, &sender);
        }

        if (add_supernode(eee, &adv.sn))
            return;

        /* Init main supernode address */
        if (eee->sn_num == 1)
        {
            supernode2addr(&eee->supernode, eee->sn_ip_array[eee->sn_idx]);

            eee->reg_sn.sn = eee->supernode;
            eee->reg_sn.timestamp = 0;
        }

        eee->snm_discovery_state = N2N_SNM_STATE_READY;
    }

}

#endif // N2N_MULTIPLE_SUPERNODES



/******************************************************************************
 *
 * TUNNELING
 *
 */

/**
 * Send an encapsulated Ethernet PACKET to a destination edge or broadcast MAC
 * address.
 */
static ssize_t send_PACKET(n2n_edge_t *eee, n2n_mac_t dst_mac,
                           const uint8_t *pktbuf, size_t pktlen)
{
    int is_p2p_dest;
    ssize_t s;
    n2n_sock_str_t sockbuf;
    n2n_sock_t destination;

    /* hexdump( pktbuf, pktlen ); */

    is_p2p_dest = find_peer_destination(eee, dst_mac, &destination);

    if (is_p2p_dest)
    {
        ++(eee->tx_p2p);
    }
    else
    {
        ++(eee->tx_sup);
    }

    traceInfo("send_PACKET to %s", sock2str(sockbuf, &destination));
    s = sendto_sock(eee->udp_sock, pktbuf, pktlen, &destination);

    return s;
}


/**
 * A layer-2 packet was received at the tunnel and needs to be sent via UDP.
 */
static void send_packet2net(n2n_edge_t *eee, uint8_t *tap_pkt, size_t len)
{
    n2n_PACKET_t pkt;
    n2n_common_t cmn;

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t pktlen = 0;

    size_t tx_transop_idx = 0;
    n2n_trans_op_t *tx_transop = NULL;

    ether_hdr_t eh;
    //TODO n2n_mac_t dest_mac;
    uint8_t *dest_mac;


    /* tap_pkt is not aligned so we have to copy to aligned memory */
    memcpy(&eh, tap_pkt, sizeof(ether_hdr_t));

    /* Discard IP packets that are not originated by this hosts */
    if (!(eee->allow_routing))
    {
        if (ntohs(eh.type) == 0x0800)
        {
            /* This is an IP packet from the local source address - not forwarded. */
#define ETH_FRAMESIZE 14
#define IP4_SRCOFFSET 12
            uint32_t *dst = (uint32_t *) &tap_pkt[ETH_FRAMESIZE + IP4_SRCOFFSET];

            /* Note: all elements of the_ip are in network order */
            if (*dst != eee->device.ip_addr)
            {
                ipstr_t ip_buf;
                /* This is a packet that needs to be routed */
                traceInfo("Discarding routed packet [%s]",
                          intoa(ntohl(*dst), ip_buf, sizeof(ip_buf)));//TODO
                return;
            }
            else
            {
                /* This packet is originated by us */
                /* traceInfo("Sending non-routed packet"); */
            }
        }
    }

    /* Optionally compress then apply transforms, e.g. encryption. */

    /* Once processed, send to destination in PACKET */

    //TODO memcpy(dest_mac, tap_pkt, N2N_MAC_SIZE); /* dest MAC is first in ethernet header */
    dest_mac = eh.dhost;

    tx_transop_idx = edge_choose_tx_transop(eee);
    //TODO
    tx_transop = &eee->transop[tx_transop_idx];

    /* no options, not from supernode, no socket */
    init_cmn(&cmn, n2n_packet, 0, eee->community_name);

    memset(&pkt, 0, sizeof(pkt));
    memcpy(pkt.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
    memcpy(pkt.dstMac, dest_mac, N2N_MAC_SIZE);
    //pkt.sock.family = 0; /* do not encode sock */
    pkt.transform = tx_transop->transform_id;


    pktlen = 0;
    encode_PACKET(pktbuf, &pktlen, &cmn, &pkt);
    traceDebug("encoded PACKET header of size=%u transform %u (idx=%u)",
               (unsigned int) pktlen, (unsigned int) pkt.transform, (unsigned int) tx_transop_idx);

    /* Transform */
    pktlen += tx_transop->fwd(tx_transop,
                              pktbuf + pktlen, N2N_PKT_BUF_SIZE - pktlen, /* out */
                              tap_pkt, len); /* in */

    /* Update statistics (TODO: what if sending error?) */
    ++tx_transop->tx_cnt;

    send_PACKET(eee, dest_mac, pktbuf, pktlen); /* to peer or supernode */
}


/**
 * A PACKET has arrived containing an encapsulated Ethernet datagram - usually
 * encrypted.
 */
static int handle_PACKET(n2n_edge_t *eee,
                         const n2n_common_t *cmn,
                         const n2n_PACKET_t *pkt,
                         const n2n_sock_t *orig_sender,
                         uint8_t *payload,
                         size_t psize)
{
    ssize_t     data_sent_len;
    uint8_t     from_supernode;
    size_t      rx_transop_idx;
    //TODO uint8_t    *eth_payload = NULL;
    time_t      now;
    int         retval = -1;

    now = time(NULL);

    traceDebug("handle_PACKET size %u transform %u",
               (unsigned int) psize, (unsigned int) pkt->transform);
    /* hexdump( payload, psize ); */

    from_supernode = ( cmn->flags & N2N_FLAGS_FROM_SUPERNODE );

    if (from_supernode)
    {
        ++(eee->rx_sup);
        eee->last_sup = now;
    }
    else
    {
        ++(eee->rx_p2p);
        eee->last_p2p = now;
    }

    /* Update the sender in peer table entry */
    check_peer(eee, from_supernode, pkt->srcMac, orig_sender);

    rx_transop_idx = transop_enum_to_index(pkt->transform);

    if (rx_transop_idx < 0)
    {
        traceError("handle_PACKET dropped unknown transform enum %u",
                   (unsigned int) pkt->transform);
        return -1;
    }

    /* Handle transform. */
    {
        uint8_t eth_payload[N2N_PKT_BUF_SIZE];
        size_t  eth_size;

        n2n_trans_op_t *rx_transop = &eee->transop[rx_transop_idx];

        //TODO eth_payload = decodebuf;
        eth_size = rx_transop->rev(rx_transop,
                                   eth_payload, N2N_PKT_BUF_SIZE, /* out */
                                   payload, psize); /* in */

        /* Update statistics */
        ++rx_transop->rx_cnt;

        /* Write Ethernet packet to tap device. */
        traceInfo("sending to TAP %u", (unsigned int) eth_size);
        data_sent_len = tuntap_write(&eee->device, eth_payload, eth_size);

        retval = -(data_sent_len != eth_size);
    }

    return retval;
}


/**
 * Read a single packet from the TAP interface, process it and write out the
 * corresponding packet to the cooked socket.
 */
static void readFromTAPSocket(n2n_edge_t *eee)
{
    /* tun -> remote */
    uint8_t    eth_pkt[N2N_PKT_BUF_SIZE];
    ssize_t    eth_len;

    const uint8_t *dst_mac = eth_pkt;
    macstr_t mac_buf;

    eth_len = tuntap_read(&eee->device, eth_pkt, N2N_PKT_BUF_SIZE);

    if ((eth_len <= 0) || (eth_len > N2N_PKT_BUF_SIZE))
    {
        traceWarning("tuntap_read()=%d [%d/%s]",
                     (signed int) eth_len, errno, strerror(errno));
        return;
    }

    traceInfo("### Rx TAP packet (%4d) for %s",
              (signed int) eth_len, mac2str(mac_buf, dst_mac));

    if (eee->drop_multicast &&
        (is_ipv6_multicast_mac(dst_mac) ||
         is_broadcast_mac(dst_mac)/* ||
         is_ethMulticast(eth_pkt, len)*/))
    {
        traceDebug("Dropping multicast");
    }
    else
    {
        send_packet2net(eee, eth_pkt, eth_len);
    }
}


#if defined(DUMMY_ID_00001) /* Disabled waiting for config option to enable it */



static char gratuitous_arp[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Dest MAC */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src MAC */
  0x08, 0x06, /* ARP */
  0x00, 0x01, /* Ethernet */
  0x08, 0x00, /* IP */
  0x06, /* Hw Size */
  0x04, /* Protocol Size */
  0x00, 0x01, /* ARP Request */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src MAC */
  0x00, 0x00, 0x00, 0x00, /* Src IP */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Target MAC */
  0x00, 0x00, 0x00, 0x00  /* Target IP */
};


/** Build a gratuitous ARP packet for a /24 layer 3 (IP) network. */
static int build_gratuitous_arp(char *buffer, uint16_t buffer_len)
{
    if (buffer_len < sizeof(gratuitous_arp))
        return (-1);

    memcpy(buffer, gratuitous_arp, sizeof(gratuitous_arp));
    memcpy(&buffer[6], device.mac_addr, 6);
    memcpy(&buffer[22], device.mac_addr, 6);
    memcpy(&buffer[28], &device.ip_addr, 4);

    /* REVISIT: BbMaj7 - use a real netmask here. This is valid only by accident
     * for /24 IPv4 networks. */
    buffer[31] = 0xFF; /* Use a faked broadcast address */
    memcpy(&buffer[38], &device.ip_addr, 4);
    return (sizeof(gratuitous_arp));
}

/** Called from update_supernode_reg to periodically send gratuitous ARP
 *  broadcasts. */
static void send_grat_arps(n2n_edge_t *eee,)
{
    char buffer[48];
    size_t len;

    traceNormal("Sending gratuitous ARP...");
    len = build_gratuitous_arp(buffer, sizeof(buffer));
    send_packet2net(eee, buffer, len);
    send_packet2net(eee, buffer, len); /* Two is better than one :-) */
}
#endif /* #if defined(DUMMY_ID_00001) */


/******************************************************************************
 *
 * UDP
 *
 */

/**
 * Read a datagram from the main UDP socket to the Internet.
 */
static void readFromIPSocket(n2n_edge_t *eee)
{
    n2n_common_t        cmn; /* common fields in the packet header */

    n2n_sock_str_t      sockbuf1;
    n2n_sock_str_t      sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t            mac_buf1;
    macstr_t            mac_buf2;

    uint8_t             udp_buf[N2N_PKT_BUF_SIZE];      /* Compete UDP packet */
    ssize_t             recvlen;
    size_t              rem;
    size_t              idx;
    size_t              msg_type;
    uint8_t             from_supernode;
    struct sockaddr_in  sender_sock;
    n2n_sock_t          sender;
    n2n_sock_t         *orig_sender = NULL;
    time_t              now = 0;

    size_t              i;

    i = sizeof(sender_sock);
    recvlen = recvfrom(eee->udp_sock, udp_buf, N2N_PKT_BUF_SIZE, 0/*flags*/,
                       (struct sockaddr *) &sender_sock, (socklen_t*) &i);

    if (recvlen < 0)
    {
        traceError("recvfrom failed with %s", strerror(errno));
        return; /* failed to receive data from UDP */
    }

    /* REVISIT: when UDP/IPv6 is supported we will need a flag to indicate which
     * IP transport version the packet arrived on. May need to UDP sockets. */
    sender.family = AF_INET; /* udp_sock was opened PF_INET v4 */
    sender.port = ntohs(sender_sock.sin_port);
    memcpy(&(sender.addr.v4), &(sender_sock.sin_addr.s_addr), IPV4_SIZE);

    /* The packet may not have an orig_sender socket spec. So default to last
     * hop as sender. */
    orig_sender = &sender;

    traceInfo("### Rx N2N UDP (%d) from %s",
              (signed int) recvlen, sock2str(sockbuf1, &sender));

    /* hexdump( udp_buf, recvlen ); */

    rem = recvlen; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */
    if (decode_common(&cmn, udp_buf, &rem, &idx) < 0)
    {
        traceError("Failed to decode common section in N2N_UDP");
        return; /* failed to decode packet */
    }

    if (0 != memcmp(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE))
    {
        traceWarning("Received packet with invalid community: %s\n", cmn.community);
        return;
    }

    now = time(NULL);

    msg_type = cmn.pc; /* packet code */
    from_supernode = ( cmn.flags & N2N_FLAGS_FROM_SUPERNODE );


    if (msg_type == MSG_TYPE_PACKET)
    {
        /* process PACKET - most frequent so first in list. */
        n2n_PACKET_t pkt;
        decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);

        if (pkt.sock.family)
        {
            orig_sender = &pkt.sock;
        }

        traceInfo("Rx PACKET from %s (%s)", sock2str(sockbuf1, &sender),
                  sock2str(sockbuf2, orig_sender));

        handle_PACKET(eee, &cmn, &pkt, orig_sender, udp_buf + idx, recvlen - idx);
    }
    else if (msg_type == MSG_TYPE_REGISTER)
    {
        /* Another edge is registering with us */
        n2n_REGISTER_t reg;
        decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx);

        if (reg.sock.family)
        {
            orig_sender = &reg.sock;
        }

        traceInfo("Rx REGISTER src=%s dst=%s from peer %s (%s)",
                  mac2str(mac_buf1, reg.srcMac), mac2str(mac_buf2, reg.dstMac),
                  sock2str(sockbuf1, &sender), sock2str(sockbuf2, orig_sender));

        if (mac_equal(reg.dstMac, eee->device.mac_addr))
        {
            check_peer(eee, from_supernode, reg.srcMac, orig_sender);
        }

        send_register_ack(eee, orig_sender, &reg);
    }
    else if (msg_type == MSG_TYPE_REGISTER_ACK)
    {
        /* Peer edge is acknowledging our register request */
        n2n_REGISTER_ACK_t ra;
        decode_REGISTER_ACK(&ra, &cmn, udp_buf, &rem, &idx);

        if (ra.sock.family)
        {
            orig_sender = &ra.sock;
        }

        traceInfo("Rx REGISTER_ACK src=%s dst=%s from peer %s (%s)",
                  mac2str(mac_buf1, ra.srcMac), mac2str(mac_buf2, ra.dstMac),
                  sock2str(sockbuf1, &sender), sock2str(sockbuf2, orig_sender));

        /* Move from pending_peers to known_peers; ignore if not in pending. */
        set_peer_operational(eee, ra.srcMac, &sender);
    }
    else if (msg_type == MSG_TYPE_REGISTER_SUPER_ACK)
    {
        n2n_REGISTER_SUPER_ACK_t ra;

        if (eee->sn_wait == 0)
        {
            traceWarning("Rx REGISTER_SUPER_ACK with no outstanding REGISTER_SUPER.");
            return;
        }

        decode_REGISTER_SUPER_ACK(&ra, &cmn, udp_buf, &rem, &idx);

        if (ra.sock.family)
        {
            orig_sender = &(ra.sock);
        }

        traceNormal("Rx REGISTER_SUPER_ACK myMAC=%s [%s] (external %s). Attempts %u",
                    mac2str(mac_buf1, ra.edgeMac), sock2str(sockbuf1, &sender),
                    sock2str(sockbuf2, orig_sender), (unsigned int) eee->sup_attempts);

        if (0 != memcmp(ra.cookie, eee->last_cookie, N2N_COOKIE_SIZE))
        {
            traceWarning("Rx REGISTER_SUPER_ACK with wrong or old cookie.");
            return;
        }


        if (ra.num_sn > 0)
        {
#ifdef N2N_MULTIPLE_SUPERNODES
            for (i = 0; i < ra.num_sn; i++)
            {
                if (add_supernode(eee, &ra.sn_bak[i]))
                    break;

                traceNormal("Rx REGISTER_SUPER_ACK backup supernode at %s",
                           sock2str(sockbuf1, &(ra.sn_bak[i])));
            }
#else
            traceNormal("Rx REGISTER_SUPER_ACK backup supernode at %s",
                        sock2str(sockbuf1, &(ra.sn_bak)));
#endif
        }

        eee->last_sup = now;
        eee->sn_wait = 0;

#ifdef N2N_MULTIPLE_SUPERNODES
        eee->reg_sn.timestamp = now; //TODO check if sending sn is reg_sn
        eee->sup_attempts = 0; /* we got a response, so no more attempts */
#else
        eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS; /* refresh because we got a response */
#endif

        /* REVISIT: store sn_back */
        eee->register_lifetime = ra.lifetime;
        eee->register_lifetime = MAX( eee->register_lifetime, REGISTER_SUPER_INTERVAL_MIN );
        eee->register_lifetime = MIN( eee->register_lifetime, REGISTER_SUPER_INTERVAL_MAX );
    }
    else
    {
        /* Not a known message type */
        traceWarning("Unable to handle packet type %d: ignored", (signed int) msg_type);
        return;
    }
}


/******************************************************************************
 *
 * EDGE MANAGEMENT
 *
 */

/**
 * Read a datagram from the management UDP socket and take appropriate action.
 */
static void readFromMgmtSocket(n2n_edge_t *eee, int *keep_running)
{
    uint8_t             udp_buf[N2N_PKT_BUF_SIZE]; /* Complete UDP packet */
    ssize_t             recvlen;
    ssize_t             sendlen;
    struct sockaddr_in  sender_sock;
    socklen_t           i;
    size_t              msg_len;
    edge_cmd_t          cmd_type;

    i = sizeof(sender_sock);
    recvlen = recvfrom(eee->udp_mgmt_sock, udp_buf, N2N_PKT_BUF_SIZE, 0 /* flags */,
                       (struct sockaddr *) &sender_sock, (socklen_t *) &i);

    if (recvlen < 0)
    {
        traceError("mgmt recvfrom failed with %s", strerror(errno));
        return; /* failed to receive data from UDP */
    }

    cmd_type = process_edge_mgmt(eee, udp_buf, recvlen, udp_buf, &msg_len);

    switch (cmd_type)
    {
    case EDGE_CMD_STOP:
        traceError("stop command received.");
        *keep_running = 0;
        return;
    case EDGE_CMD_STATS:
        traceDebug("mgmt status sending: %s", udp_buf);
        break;
    default:
        break;
    }

    sendlen = sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0/* flags */,
                     (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));

    if (sendlen < 0)
    {
        traceError("mgmt sendto failed with %s", strerror(errno));
    }
}

/* ***************************************************** */


/* ***************************************************** */


//TODO

#define N2N_NETMASK_STR_SIZE    16 /* dotted decimal 12 numbers + 3 dots */
#define N2N_MACNAMSIZ           18 /* AA:BB:CC:DD:EE:FF + NULL*/
#define N2N_IF_MODE_SIZE        16 /* static | dhcp */





/******************************************************************************/


struct boot_helper
{
    int     local_port;
    int     mgmt_port;
#ifdef N2N_MULTIPLE_SUPERNODES
    int     snm_port;
#endif
#ifndef WIN32
    int     user_id;
    int     group_id;
#endif
    char   *encrypt_key;
};

typedef struct boot_helper boot_helper_t;


static void initBootHelper(boot_helper_t *boot_helper)
{
    char *env_key = getenv("N2N_KEY");
    boot_helper->local_port = 0 /* any port */;
    boot_helper->mgmt_port = N2N_EDGE_MGMT_PORT; /* 5644 by default */
#ifdef N2N_MULTIPLE_SUPERNODES
    boot_helper->snm_port = 0 //TODO
#endif
#ifndef WIN32
    boot_helper->user_id = 0;  /* root is the only guaranteed ID */
    boot_helper->group_id = 0; /* root is the only guaranteed ID */
#endif
    boot_helper->encrypt_key = (env_key ? strdup(env_key) : NULL);
}


static void destroyBootHelper(boot_helper_t *boot_helper)
{
    if (boot_helper->encrypt_key)
    {
        free(boot_helper->encrypt_key);
        boot_helper->encrypt_key = NULL;
    }
}


static int edge_start(n2n_edge_t *edge, boot_helper_t *boot_helper)
{
    int i;

#ifdef N2N_HAVE_DAEMON
    if (edge->daemon)
    {
        /* traceEvent output now goes to syslog. */
        useSyslog = 1;
        if (-1 == daemon(0, 0))
        {
            traceError("Failed to become daemon.");
            exit(-5);
        }
    }
#endif /* N2N_HAVE_DAEMON */


    traceNormal("Starting n2n edge %s %s", n2n_sw_version, n2n_sw_buildDate);


    for (i = 0; i < N2N_EDGE_NUM_SUPERNODES; ++i)
    {
        n2n_sock_str_t sockstr;
        traceNormal("supernode %u => %s\n", i, sock2str(sockstr, &edge->supernodes[i]));
    }

#ifdef N2N_MULTIPLE_SUPERNODES
    if (load_supernodes(&eee) > 0)
#endif
    //TODO supernode2addr(&(edge->supernode), edge->sn_ip_array[edge->sn_idx]);
    edge->supernode = edge->supernodes[edge->sn_idx];

    /* Open TAP device */

#ifndef WIN32
    /* If running suid root then we need to setuid before using the force. */
    if (-1 == setuid(0))
    {
        traceError("setuid(0) [%s]\n", strerror(errno));
        return -1;
    }
    /* setgid( 0 ); */
#endif

    if (tuntap_open(&edge->device, edge->ip_mode) < 0)
        return (-1);

#ifndef WIN32
    if ((boot_helper->user_id != 0) || (boot_helper->group_id != 0))
    {
        traceNormal("Interface up. Dropping privileges to uid=%d, gid=%d",
                    (signed int) boot_helper->user_id, (signed int) boot_helper->group_id);

        /* Finished with the need for root privileges. Drop to unprivileged user. */
        setreuid(boot_helper->user_id, boot_helper->user_id);
        setregid(boot_helper->group_id, boot_helper->group_id);
    }
#endif

    /* Init encryption */

    if (boot_helper->encrypt_key)
    {
        if (edge_init_twofish(edge, (uint8_t *) boot_helper->encrypt_key, strlen(boot_helper->encrypt_key)) < 0)
        {
            fprintf(stderr, "Error: twofish setup failed.\n");
            return (-1);
        }
    }
    else if (strlen(edge->keyschedule) > 0)
    {
        if (edge_init_keyschedule(edge) != 0)
        {
            fprintf(stderr, "Error: keyschedule setup failed.\n");
            return (-1);
        }
    }
    else
    {
        /* run in NULL mode */
        traceWarning("Encryption is disabled in edge.");
        edge->null_transop = 1;
    }


    /* Open connections */

    if (boot_helper->local_port > 0)
        traceNormal("Binding to local port %d", (unsigned int) boot_helper->local_port);

    edge->udp_sock = open_socket(boot_helper->local_port, 1 /*bind ANY*/);
    if (edge->udp_sock < 0)
    {
        traceError("Failed to bind main UDP port %u", (unsigned int) boot_helper->local_port);
        return (-1);
    }

    edge->udp_mgmt_sock = open_socket(boot_helper->mgmt_port, 0 /* bind LOOPBACK*/);
    if (edge->udp_mgmt_sock < 0)
    {
        traceError("Failed to bind management UDP port %u", (unsigned int) N2N_EDGE_MGMT_PORT);
        return (-1);
    }

#ifdef N2N_MULTIPLE_SUPERNODES

    edge->snm_sock = open_socket(snm_port, 1 /*bind ANY*/);
    if (edge->snm_sock < 0)
    {
        traceError("Failed to bind SNM UDP port %d", snm_port);
        return(-1);
    }

    if (edge->snm_discovery_state == N2N_SNM_STATE_DISCOVERY)
    {
        /* send requests to all supernodes */
        struct sn_info *sni = NULL;

        N2N_LIST_FOR_EACH_ENTRY(sni, &edge->supernodes.head)
        {
            edge_send_snm_req(edge, &sni->sn);
        }
    }

#else

    update_supernode_reg(edge, time(NULL));

#endif

    traceNormal("edge started");

    return 0;
}


#ifdef WIN32

static DWORD tunReadThread(LPVOID lpArg)
{
    n2n_edge_t *eee = (n2n_edge_t *) lpArg;
    while (1)
    {
        readFromTAPSocket(eee);
    }
    return ((DWORD) NULL);
}


/** Start a second thread in Windows because TUNTAP interfaces do not expose
 *  file descriptors. */
static void startTunReadThread(n2n_edge_t *eee)
{
    HANDLE hThread;
    DWORD dwThreadId;

    hThread = CreateThread(NULL,         /* security attributes */
                           0,            /* use default stack size */
                           (LPTHREAD_START_ROUTINE) tunReadThread, /* thread function */
                           (void*) eee,  /* argument to thread function */
                           0,            /* thread creation flags */
                           &dwThreadId); /* thread id out */
}
#endif


static int run_loop(n2n_edge_t *eee)
{
    int      keep_running = 1;
    size_t   num_purged;
    time_t   last_iface_check = 0;
    time_t   last_transop = 0;
    time_t   now;
    int      rc;

    int      max_sock = 0;
    fd_set   proto_socket_mask;


    /* Setup prototype socket mask */
    FD_ZERO(&proto_socket_mask);
    FD_SET(eee->udp_sock, &proto_socket_mask);
    FD_SET(eee->udp_mgmt_sock, &proto_socket_mask);
    max_sock = max( eee->udp_sock, eee->udp_mgmt_sock );
#ifndef WIN32
    FD_SET(eee->device.fd, &proto_socket_mask);
    max_sock = max( max_sock, eee->device.fd );
#endif
#ifdef N2N_MULTIPLE_SUPERNODES
    FD_SET(eee->snm_sock, &proto_socket_mask);
    max_sock = max(max_sock, eee->snm_sock);
#endif


#ifdef WIN32
    startTunReadThread(eee);
#endif

    /* Main loop
     *
     * select() is used to wait for input on either the TAP fd or the UDP/TCP
     * socket. When input is present the data is read and processed by either
     * readFromIPSocket() or readFromTAPSocket()
     */

    while (keep_running)
    {
        fd_set          socket_mask;
        struct timeval  wait_time;

        socket_mask = proto_socket_mask;

        wait_time.tv_sec  = SOCKET_TIMEOUT_INTERVAL_SECS;
        wait_time.tv_usec = 0;

        rc = select(max_sock + 1, &socket_mask, NULL, NULL, &wait_time);
        now = time(NULL);

        /* Make sure ciphers are updated before the packet is treated. */
        if ((now - last_transop) > TRANSOP_TICK_INTERVAL)
        {
            last_transop = now;
            n2n_tick_transop(eee, now);
        }

        if (rc > 0)
        {
            /* Any or all of the FDs could have input; check them all. */

            if (FD_ISSET(eee->udp_sock, &socket_mask))
            {
                /* Read a cooked socket from the Internet socket.
                 * Writes on the TAP socket. */
                readFromIPSocket(eee);
            }

#ifndef WIN32
            if (FD_ISSET(eee->device.fd, &socket_mask))
            {
                /* Read an Ethernet frame from the TAP socket.
                 * Write on the IP socket. */
                readFromTAPSocket(eee);
            }
#endif

#ifdef N2N_MULTIPLE_SUPERNODES
            if (FD_ISSET(eee->snm_sock, &socket_mask))
            {
                readFromSNMSocket(eee);
            }
#endif

            if (FD_ISSET(eee->udp_mgmt_sock, &socket_mask))
            {
                /* Read from the management Internet socket.
                 * Writes on the management IP socket. */
                readFromMgmtSocket(eee, &keep_running);
            }
        }

        /* Finished processing select data. */

#ifdef N2N_MULTIPLE_SUPERNODES
        if (eee->snm_discovery_state != N2N_SNM_STATE_READY)
        {
            supernodes_discovery(eee, now);
        }
        else
#endif
        update_supernode_reg(eee, now);

        /* Purge expired peer information */
        num_purged  = purge_expired_registrations(&eee->known_peers);
        num_purged += purge_expired_registrations(&eee->pending_peers);
        if (num_purged > 0)
        {
            traceNormal("Peer removed: pending=%u, operational=%u",
                        (unsigned int) list_size(&eee->pending_peers),
                        (unsigned int) list_size(&eee->known_peers));
        }

        /* Re-check the IP if dynamic mode enabled */
        if (eee->ip_mode == N2N_IPM_DHCP &&
            (now - last_iface_check) > IFACE_UPDATE_INTERVAL)
        {
            traceNormal("Re-checking dynamic IP address.");
            tuntap_get_address(&eee->device);
            last_iface_check = now;
        }

    } /* while */

    /* End of loop */

#ifdef N2N_MULTIPLE_SUPERNODES
    deregister_supernodes(eee);
#else
    send_deregister(eee, &(eee->supernode));
#endif

    closesocket(eee->udp_sock);//TODO move to deinit
    tuntap_close(&(eee->device));

    edge_deinit(eee);

    return (0);
}


/******************************************************************************
 *
 * COMMAND LINE ARGUMENTS
 *
 */

static const struct option long_options[] = {
  { "community",       required_argument, NULL, 'c' },
  { "supernode-list",  required_argument, NULL, 'l' },
  { "tun-device",      required_argument, NULL, 'd' },
  { "euid",            required_argument, NULL, 'u' },
  { "egid",            required_argument, NULL, 'g' },
  { "verbose",         no_argument,       NULL, 'v' },
  { "help"   ,         no_argument,       NULL, 'h' },
  { NULL,              0,                 NULL,  0  }
};


static void help()
{
    print_n2n_version();

    printf("edge "
#if defined(N2N_CAN_NAME_IFACE)
     "-d <tun device> "
#endif /* #if defined(N2N_CAN_NAME_IFACE) */
     "-a [static:|dhcp:]<tun IP address> "
     "-c <community> "
     "[-k <encrypt key> | -K <key file>] "
     "[-s <netmask>] "
#if defined(N2N_HAVE_SETUID)
     "[-u <uid> -g <gid>]"
#endif /* #ifndef N2N_HAVE_SETUID */

#if defined(N2N_HAVE_DAEMON)
     "[-f]"
#endif /* #if defined(N2N_HAVE_DAEMON) */
     "[-m <MAC address>]"
     "\n"
     "-l <supernode host:port> "
     "[-p <local port>] [-M <mtu>] "
     "[-r] [-E] [-v] [-t <mgmt port>] [-b] [-h]\n\n");

#ifdef __linux__
    printf("-d <tun device>          | tun device name\n");
#endif

    printf("-a <mode:address>        | Set interface address. For DHCP use '-r -a dhcp:0.0.0.0'\n");
    printf("-c <community>           | n2n community name the edge belongs to.\n");
    printf("-k <encrypt key>         | Encryption key (ASCII) - also N2N_KEY=<encrypt key>. Not with -K.\n");
    printf("-K <key file>            | Specify a key schedule file to load. Not with -k.\n");
    printf("-s <netmask>             | Edge interface netmask in dotted decimal notation (255.255.255.0).\n");
    printf("-l <supernode host:port> | Supernode IP:port\n");
    printf("-b                       | Periodically resolve supernode IP\n");
    printf("                         : (when supernodes are running on dynamic IPs)\n");
    printf("-p <local port>          | Fixed local UDP port.\n");
#ifndef WIN32
    printf("-u <UID>                 | User ID (numeric) to use when privileges are dropped.\n");
    printf("-g <GID>                 | Group ID (numeric) to use when privileges are dropped.\n");
#endif /* ifndef WIN32 */
#ifdef N2N_HAVE_DAEMON
    printf("-f                       | Do not fork and run as a daemon; rather run in foreground.\n");
#endif /* #ifdef N2N_HAVE_DAEMON */
    printf("-m <MAC address>         | Fix MAC address for the TAP interface (otherwise it may be random)\n"
           "                         : eg. -m 01:02:03:04:05:06\n");
    printf("-M <mtu>                 | Specify n2n MTU of edge interface (default %d).\n",
           DEFAULT_MTU);
    printf("-r                       | Enable packet forwarding through n2n community.\n");
    printf("-E                       | Accept multicast MAC addresses (default=drop).\n");
    printf("-v                       | Make more verbose. Repeat as required.\n");
    printf("-t                       | Management UDP Port (for multiple edges on a machine).\n");

    printf("\nEnvironment variables:\n");
    printf("  N2N_KEY                | Encryption key (ASCII). Not with -K or -k.\n" );

    exit(0);
}


static void read_args(int argc, char *argv[], n2n_edge_t *eee, boot_helper_t *boot_helper)
{
    // TUNTAP: tuntap_dev_name, ip_mode, ip_addr, netmask, device_mac, mtu
    int     opt;
    //char    tuntap_dev_name[N2N_IFNAMSIZ] = "edge0";
    int     got_s = 0;

    char    device_mac[N2N_MACNAMSIZ] = "";

#ifdef N2N_MULTIPLE_SUPERNODES
    const char *optstring = "K:k:a:bc:Eu:g:m:M:s:S:d:l:p:fvhrt:";
#else
    const char *optstring = "K:k:a:bc:Eu:g:m:M:s:d:l:p:fvhrt:";
#endif

    effective_args_t effective_args = { 0, NULL };
    build_effective_args(argc, argv, &effective_args);


    optarg = NULL;
    while ((opt = getopt_long(effective_args.argc, effective_args.argv,
                              optstring, long_options, NULL)) != EOF)
    {
        switch (opt)
        {

        /* N2N protocols parameters */

        case 'c': /* community as a string */
        {
            memset(eee->community_name, 0, N2N_COMMUNITY_SIZE);
            strncpy((char *) eee->community_name, optarg, N2N_COMMUNITY_SIZE);
            break;
        }
        case 'l': /* supernode-list */
        {
            if (eee->sn_num == N2N_EDGE_NUM_SUPERNODES)
            {
                fprintf(stderr, "Too many supernodes!\n");
                exit(1);
            }

            if (0 != str2sock(&eee->supernodes[eee->sn_num], optarg))
            {
                fprintf(stderr, "Wrong supernode parameter: %s (Hint: -l <host:port>)", optarg);
                exit(1);
            }

            traceDebug("Adding supernode[%u] = %s\n", (unsigned int) eee->sn_num, optarg);
            ++eee->sn_num;
            break;
        }
        case 'b':
        {
            eee->re_resolve_supernode_ip = 1;
            break;
        }

        /* Network parameters */

        case 'a': /* IP address and mode of TUNTAP interface */
        {
            if (0 != scan_address(&eee->device.ip_addr, &eee->ip_mode, optarg))
            {
                fprintf(stderr, "Error: wrong address: \"%s\".\n", optarg);
                exit(1);
            }
            if (eee->ip_mode == N2N_IPM_DHCP)
            {
                traceNormal("Dynamic IP address assignment enabled.");
            }
            break;
        }
        case 's': /* Subnet Mask */
        {
            if (0 != got_s)
            {
                traceWarning("Multiple subnet masks supplied.");
            }
            if (0 != scan_address(&eee->device.device_mask, NULL, optarg))
            {
                fprintf(stderr, "Error: wrong mask address: %s.\n", optarg);
                exit(1);
            }
            //strncpy(netmask, optarg, N2N_NETMASK_STR_SIZE);
            got_s = 1;
            break;
        }
        case 'p':
        {
            boot_helper->local_port = atoi(optarg);
            break;
        }
        case 't':
        {
            boot_helper->mgmt_port = atoi(optarg);
            break;
        }
#ifdef N2N_MULTIPLE_SUPERNODES
        case 'S':
        {
            snm_port = atoi(optarg);
            break;
        }
#endif
        case 'r': /* enable packet routing across n2n endpoints */
        {
            eee->allow_routing = 1;
            break;
        }
        case 'E': /* multicast ethernet addresses accepted. */
        {
            eee->drop_multicast = 0;
            traceDebug("Enabling ethernet multicast traffic\n");
            break;
        }

        /* TUNTAP parameters */

#if defined(N2N_CAN_NAME_IFACE)
        case 'd': /* TUNTAP name */
        {
            //strncpy(tuntap_dev_name, optarg, N2N_IFNAMSIZ);
            strncpy(eee->device.dev_name, optarg, N2N_IFNAMSIZ);
            break;
        }
#endif
        case 'm': /* TUNTAP MAC address */
        {
            //TODO strncpy(eee->device.mac_addr, optarg, N2N_MACNAMSIZ);
            str2mac(eee->device.mac_addr, optarg);
            break;
        }
        case 'M': /* TUNTAP MTU */
        {
            eee->device.mtu = atoi(optarg);
            break;
        }

        /* Encryption parameters */

        case 'k': /* encrypt key */
        {
            if (strlen(eee->keyschedule) > 0)
            {
                fprintf(stderr, "Error: -K and -k options are mutually exclusive.\n");
                exit(1);
            }

            boot_helper->encrypt_key = strdup(optarg);
            traceDebug("encrypt_key = '%s'\n", boot_helper->encrypt_key);
            break;
        }
        case 'K':
        {
            if (boot_helper->encrypt_key)
            {
                fprintf(stderr, "Error: -K and -k options are mutually exclusive.\n");
                exit(1);
            }

            strncpy(eee->keyschedule, optarg, N2N_PATHNAME_MAXLEN - 1);
            eee->keyschedule[N2N_PATHNAME_MAXLEN - 1] = 0; /* strncpy does not add NULL if the source has no NULL. */

            traceDebug("keyfile = '%s'\n", eee->keyschedule);
            fprintf(stderr, "keyfile = '%s'\n", eee->keyschedule);
            break;
        }

        /* Miscellaneous parameters */

#ifdef N2N_HAVE_DAEMON
        case 'f': /* do not fork as daemon */
        {
            eee->daemon = 0;
            break;
        }
#endif /* #ifdef N2N_HAVE_DAEMON */

#ifndef WIN32
        case 'u': /* unprivileged uid */
        {
            boot_helper->user_id = atoi(optarg);
            break;
        }
        case 'g': /* unprivileged gid */
        {
            boot_helper->group_id = atoi(optarg);
            break;
        }
#endif /* #ifdef WIN32 */

        case 'v': /* verbose */
        {
            /* do 2 -v flags to increase verbosity to DEBUG level*/
            ++traceLevel;
            break;
        }
        case 'h': /* help */
        {
            help();
            break;
        }
        } /* end switch */
    }

    destroy_effective_args(&effective_args);


    if (!(
#ifdef __linux__
          (eee->device.dev_name[0] != 0) &&
#endif
          (eee->community_name[0] != 0) &&
          (eee->device.ip_addr != 0)))
    {
        help();
    }
}


/**
 * Entry point to program from kernel.
 */
int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);//TODO debug
    setvbuf(stderr, NULL, _IONBF, 0);
    //char    device_mac[N2N_MACNAMSIZ] = "";

    n2n_edge_t eee; /* single instance for this program */

    boot_helper_t boot_helper;

    if (edge_init(&eee) != 0)
    {
        traceError("Failed in edge_init");
        exit(1);
    }

    initBootHelper(&boot_helper);
    read_args(argc, argv, &eee, &boot_helper);//TODO check

    if (edge_start(&eee, &boot_helper) != 0)
    {
        traceError("Failed in edge_start");
        exit(1);
    }

    destroyBootHelper(&boot_helper);

    return run_loop(&eee);
}


