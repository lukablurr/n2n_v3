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

#ifndef N2N_NET_H_
#define N2N_NET_H_

#ifdef WIN32
# include "win32/n2n_win32.h"
#else /* #ifdef WIN32 */
//#include <netdb.h>//TODO ???
# include <sys/socket.h>

# ifdef __linux__
#  include <linux/if.h>
# endif /* #ifdef __linux__ */

# ifdef __FreeBSD__
#  include <netinet/in_systm.h>
# endif /* #ifdef __FreeBSD__ */

# include <arpa/inet.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/udp.h>
#endif /* #ifdef WIN32 */

#include <string.h>



/******************************************************************************
 *
 * LAYER 2
 *
 */

#define ETH_ADDR_LEN            6

#define N2N_MAC_SIZE            ETH_ADDR_LEN
#define N2N_MACSTR_SIZE         32


typedef uint8_t     n2n_mac_t[ETH_ADDR_LEN];

/** Common type used to hold stringified MAC addresses. */
typedef char        macstr_t[N2N_MACSTR_SIZE];

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct ether_hdr
{
    n2n_mac_t  dhost;
    n2n_mac_t  shost;
    uint16_t   type;                /* higher layer protocol encapsulated */
} PACKED;

typedef struct ether_hdr ether_hdr_t;


/* functions */
int is_empty_mac(const uint8_t *mac);
int is_broadcast_mac(const uint8_t *mac);
int is_multicast_mac(const uint8_t *mac);
int is_ipv6_multicast_mac(const uint8_t *mac);

uint8_t is_multi_broadcast_mac(const uint8_t *dest_mac);

static inline int mac_equal(const n2n_mac_t a, const n2n_mac_t b)
{
    return (0 == memcmp(a, b, ETH_ADDR_LEN));
}

char *mac2str(macstr_t buf, const n2n_mac_t mac);
int   str2mac(uint8_t *outmac /* 6 bytes */, const char *s);


/******************************************************************************
 *
 * LAYER 3
 *
 */

#define IPV4_SIZE           4
#define IPV6_SIZE           16


/** Common type used to hold stringified IP addresses. */
typedef char ipstr_t[32];


extern char *intoa(uint32_t addr, char *buf, uint16_t buf_len);


/******************************************************************************
 *
 * LAYER 4
 *
 */

#define DEFAULT_MTU         1400
#define N2N_SOCKBUF_SIZE    64   /* string representation of INET or INET6 sockets */


#ifndef WIN32
#define closesocket(a)      close(a)
#define SOCKET              int
#endif /* #ifndef WIN32 */


struct n2n_sock
{
    uint8_t     family;         /* AF_INET or AF_INET6; or 0 if invalid */
    uint16_t    port;           /* host order TODO */
    union
    {
        uint8_t v6[IPV6_SIZE];  /* byte sequence */
        uint8_t v4[IPV4_SIZE];  /* byte sequence */
    } addr;
};

typedef struct n2n_sock n2n_sock_t;


/* tracing string buffer */
typedef char n2n_sock_str_t[N2N_SOCKBUF_SIZE];


/* functions */
SOCKET open_socket(int local_port, int bind_any);

ssize_t sendto_sock(int sock_fd, const void *pktbuf, size_t pktsize, const n2n_sock_t *dest);

int is_empty_ip_address(const n2n_sock_t *sock);

int sock_equal(const n2n_sock_t *a, const n2n_sock_t *b);

char*       sock2str(n2n_sock_str_t out, const n2n_sock_t *sock);
n2n_sock_t* sock_from_cstr(n2n_sock_t *out,  const n2n_sock_str_t str);

int str2sock(n2n_sock_t *out, const n2n_sock_str_t str);


/******************************************************************************
 *
 * TUNNELING
 *
 */

enum ip_mode
{
    N2N_IPM_NONE = 0,
    N2N_IPM_STATIC,
    N2N_IPM_DHCP
};

typedef enum ip_mode ip_mode_t;


/* functions */
int scan_address(uint32_t *ip_addr, ip_mode_t *ip_mode, const char *s);


#endif /* N2N_NET_H_ */
