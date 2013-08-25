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
 *    Babak Farrokhi <babak@farrokhi.net> [FreeBSD port]
 *    Lukasz Taczuk
 *
 */

#ifndef _N2N_H_
#define _N2N_H_

/*
   tunctl -t tun0
   tunctl -t tun1
   ifconfig tun0 1.2.3.4 up
   ifconfig tun1 1.2.3.5 up
   ./edge -d tun0 -l 2000 -r 127.0.0.1:3000 -c hello
   ./edge -d tun1 -l 3000 -r 127.0.0.1:2000 -c hello


   tunctl -u UID -t tunX
*/

#if defined(__APPLE__) && defined(__MACH__)
#define _DARWIN_
#endif


/* Some capability defaults which can be reset for particular platforms. */
#define N2N_HAVE_DAEMON 1
#define N2N_HAVE_SETUID 1
/* #define N2N_CAN_NAME_IFACE */

/* Moved here to define _CRT_SECURE_NO_WARNINGS before all the including takes place */
#ifdef WIN32
#include "win32/n2n_win32.h"
#undef N2N_HAVE_DAEMON
#undef N2N_HAVE_SETUID
#endif

#include <time.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef WIN32
#include <netdb.h>
#endif

#ifndef _MSC_VER
#include <getopt.h>
#endif /* #ifndef _MSC_VER */


#ifndef WIN32
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <pthread.h>

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#define N2N_CAN_NAME_IFACE 1
#endif /* #ifdef __linux__ */

#ifdef __FreeBSD__
#include <netinet/in_systm.h>
#endif /* #ifdef __FreeBSD__ */

//TODO #include <syslog.h>
#include <sys/wait.h>

/*#define ETH_ADDR_LEN 6
struct ether_hdr
{
    uint8_t  dhost[ETH_ADDR_LEN];
    uint8_t  shost[ETH_ADDR_LEN];
    uint16_t type;                 higher layer protocol encapsulated
} __attribute__ ((__packed__));*/

//typedef struct ether_hdr ether_hdr_t;

#ifdef __sun__
#include <sys/sysmacros.h> /* MIN() and MAX() declared here */
#undef N2N_HAVE_DAEMON
#endif /* #ifdef __sun__ */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>

#endif /* #ifndef WIN32 */



#ifdef WIN32
#include "win32/wintap.h"
#endif /* #ifdef WIN32 */

#include "n2n_list.h"
#include "n2n_wire.h"


/******************************************************************************
 *
 * MESSAGES
 *
 */

/* N2N packet header indicators. */
#define MSG_TYPE_REGISTER               1
#define MSG_TYPE_DEREGISTER             2
#define MSG_TYPE_PACKET                 3
#define MSG_TYPE_REGISTER_ACK           4
#define MSG_TYPE_REGISTER_SUPER         5
#define MSG_TYPE_REGISTER_SUPER_ACK     6
#define MSG_TYPE_REGISTER_SUPER_NAK     7
#define MSG_TYPE_FEDERATION             8

/* Functions */
extern char *msg_type2str(uint16_t msg_type);


/******************************************************************************
 *
 * COMPRESSION
 *
 */

#define QUICKLZ                     1

/* Set N2N_COMPRESSION_ENABLED to 0 to disable lzo1x compression of Ethernet
 * frames. Doing this will break compatibility with the standard n2n packet
 * format so do it only for experimentation. All edges must be built with the
 * same value if they are to understand each other. */
#define N2N_COMPRESSION_ENABLED     1


/******************************************************************************
 *
 * SUPERNODE INFORMATION
 *
 */

#define SUPERNODE_IP                "127.0.0.1"
#define SUPERNODE_PORT              1234


/******************************************************************************
 *
 * PEER INFORMATION
 *
 */

struct peer_info
{
    n2n_list_node_t     list;
    n2n_community_t     community_name;
    n2n_mac_t           mac_addr;
    n2n_sock_t          sock;
    time_t              last_seen;
};

typedef struct peer_info peer_info_t;


/* Operations on peer_info lists. */
void   peer_list_add(n2n_list_head_t *peers, peer_info_t *info);
size_t purge_peer_list(n2n_list_head_t *peers, time_t purge_before);
size_t purge_expired_registrations(n2n_list_head_t *peers);

/* Search functions */
peer_info_t *find_peer_by_mac(n2n_list_head_t *peers, const n2n_mac_t mac);
peer_info_t *find_peer_by_mac_for_removal(n2n_list_head_t *peers, const n2n_mac_t mac,
                                          peer_info_t **prev);


/******************************************************************************
 *
 * N2N VERSION
 *
 */

/* version.c */
extern char *n2n_sw_version, *n2n_sw_osName, *n2n_sw_buildDate;


void print_n2n_version();


#endif /* _N2N_H_ */
