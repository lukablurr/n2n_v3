/*
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 * Code contributions courtesy of:
 * Massimo Torquati <torquati@ntop.org>
 * Matt Gilg
 *
 */

#include "n2n.h"
#include "n2n_log.h"
#include "minilzo.h"
#include <assert.h>


#if defined(DEBUG)
#   define PURGE_REGISTRATION_FREQUENCY   60
#   define REGISTRATION_TIMEOUT          120
#else /* #if defined(DEBUG) */
#   define PURGE_REGISTRATION_FREQUENCY   60
#   define REGISTRATION_TIMEOUT           (60*20)
#endif /* #if defined(DEBUG) */



/******************************************************************************
 *
 * MESSAGES
 *
 */

char *msg_type2str(uint16_t msg_type)
{
    switch (msg_type)
    {
    case MSG_TYPE_REGISTER:             return ("MSG_TYPE_REGISTER");
    case MSG_TYPE_DEREGISTER:           return ("MSG_TYPE_DEREGISTER");
    case MSG_TYPE_PACKET:               return ("MSG_TYPE_PACKET");
    case MSG_TYPE_REGISTER_ACK:         return ("MSG_TYPE_REGISTER_ACK");
    case MSG_TYPE_REGISTER_SUPER:       return ("MSG_TYPE_REGISTER_SUPER");
    case MSG_TYPE_REGISTER_SUPER_ACK:   return ("MSG_TYPE_REGISTER_SUPER_ACK");
    case MSG_TYPE_REGISTER_SUPER_NAK:   return ("MSG_TYPE_REGISTER_SUPER_NAK");
    case MSG_TYPE_FEDERATION:           return ("MSG_TYPE_FEDERATION");
    default:                            return ("???");
    }
    return ("???");
}


/******************************************************************************
 *
 * PEER INFORMATION
 *
 */


/**
 * Add info to the head of list. If list is NULL; create it.
 *
 * The item new is added to the head of the list. New is modified during
 * insertion. list takes ownership of new.
 */
void peer_list_add(n2n_list_head_t *peers, peer_info_t *info)
{
    list_add(peers, &info->list);
    info->last_seen = time(NULL);
}


size_t purge_expired_registrations(n2n_list_head_t *peers)
{
    static time_t last_purge = 0;
    time_t now = time(NULL);
    size_t num_reg = 0;

    if ((now - last_purge) < PURGE_REGISTRATION_FREQUENCY)
        return 0;

    traceInfo("Purging old registrations");

    num_reg = purge_peer_list(peers, now - REGISTRATION_TIMEOUT);

    last_purge = now;
    traceInfo("Remove %ld registrations", num_reg);

    return num_reg;
}


/**
 * Purge old items from the peer_list and return the number of items that
 * were removed.
 */
size_t purge_peer_list(n2n_list_head_t *peers, time_t purge_before)
{
    peer_info_t *scan = NULL;
    peer_info_t *prev = NULL;
    peer_info_t *next = NULL;
    size_t retval = 0;

    N2N_LIST_FOR_EACH_SAFE(peers, scan, next)
    {
        if (scan->last_seen < purge_before)
        {
            if (prev == NULL)
            {
                peers->node.next = &next->list;
            }
            else
            {
                prev->list.next = &next->list;
            }

            ++retval;
            free(scan);
        }
        else
        {
            prev = scan;
        }
    }

    return retval;
}


/** Find the peer entry in list with mac_addr equal to mac.
 *
 *  Does not modify the list.
 *
 *  @return NULL if not found; otherwise pointer to peer entry.
 */
peer_info_t *find_peer_by_mac(n2n_list_head_t *peers, const n2n_mac_t mac)
{
    peer_info_t *peer = NULL;

    N2N_LIST_FOR_EACH(peers, peer)
    {
        if (mac_equal(mac, peer->mac_addr))//TODO
            return peer;
    }

    return NULL;
}


peer_info_t *find_peer_by_mac_for_removal(n2n_list_head_t *peers, const n2n_mac_t mac,
                                          peer_info_t **prev)
{
    peer_info_t *peer = NULL;

    N2N_LIST_FOR_EACH(peers, peer)
    {
        if (mac_equal(mac, peer->mac_addr))//TODO
            return peer;

        *prev = peer;
    }

    *prev = NULL;
    return NULL;
}


/******************************************************************************
 *
 * N2N VERSION
 *
 */

void print_n2n_version()
{
    printf("Welcome to n2n v.%s for %s\n"
           "Built on %s\n"
           "Copyright 2007-09 - http://www.ntop.org\n\n",
           n2n_sw_version, n2n_sw_osName, n2n_sw_buildDate);
}


