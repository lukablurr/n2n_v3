/*
 * n2n_net.c
 *
 *  Created on: Dec 1, 2012
 *      Author: wolf
 */

#include <string.h>
#include <errno.h>

#include "n2n.h"//TODO
#include "n2n_net.h"



/* *********************************************** */
/* Layer 2 */

static const n2n_mac_t broadcast_addr =
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const n2n_mac_t multicast_addr =
        { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x00 }; /* First 3 bytes are meaningful */

static const n2n_mac_t ipv6_multicast_addr =
        { 0x33, 0x33, 0x00, 0x00, 0x00, 0x00 }; /* First 2 bytes are meaningful */


int is_broadcast_mac(const uint8_t *mac)
{
    return (0 == memcmp(mac, broadcast_addr, ETH_ADDR_LEN));
}

/** Destination 01:00:5E:00:00:00 - 01:00:5E:7F:FF:FF is
 *  multicast ethernet [RFC1112].
 */
int is_multicast_mac(const uint8_t *mac)
{
    return (0 == memcmp(mac, multicast_addr, 3) &&
            (0 == (0x80 & mac[3])));
}


/** Destination MAC 33:33:0:00:00:00 - 33:33:FF:FF:FF:FF is
 *  reserved for IPv6 neighbour discovery [RFC2464].
 */
int is_ipv6_multicast_mac(const uint8_t *mac)
{
    return (0 == memcmp(mac, ipv6_multicast_addr, 2));
}


uint8_t is_multi_broadcast_mac(const uint8_t *mac)
{
    return (is_broadcast_mac(mac) ||
            is_multicast_mac(mac) ||
            is_ipv6_multicast_mac(mac));
}
/* http://www.faqs.org/rfcs/rfc908.html */



char *macaddr_str(macstr_t buf, const n2n_mac_t mac)
{
    snprintf(buf, N2N_MACSTR_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
             mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);
    return buf;
}


static uint8_t hex2byte(const char *s) //TODO move to utils
{
    char tmp[3];
    tmp[0] = s[0];
    tmp[1] = s[1];
    tmp[2] = 0; /* NULL term */

    return ((uint8_t) strtol(s, NULL, 16));
}

extern int str2mac(uint8_t *outmac /* 6 bytes */, const char *s)
{
    size_t i;

    /* break it down as one case for the first "HH", the 5 x through loop for
     * each ":HH" where HH is a two hex nibbles in ASCII. */

    *outmac = hex2byte(s);
    ++outmac;
    s += 2; /* don't skip colon yet - helps generalise loop. */

    for (i = 1; i < 6; ++i)
    {
        s += 1;
        *outmac = hex2byte(s);
        ++outmac;
        s += 2;
    }

    return 0; /* ok */
}



/* *********************************************** */
/* Layer 3 */

int is_empty_ip_address(const n2n_sock_t *sock)
{
    const uint8_t *ptr = NULL;
    size_t len = 0;
    size_t i;

    if (AF_INET6 == sock->family)
    {
        ptr = sock->addr.v6;
        len = 16;
    }
    else
    {
        ptr = sock->addr.v4;
        len = 4;
    }

    for (i = 0; i < len; ++i)
    {
        if (0 != ptr[i])
        {
            /* found a non-zero byte in address */
            return 0;
        }
    }

    return 1;
}


/* addr should be in network order. Things are so much simpler that way. */
char* intoa(uint32_t /* host order */addr, char *buf, uint16_t buf_len)
{
    char *cp, *retStr;
    uint8_t byteval;
    int n;

    cp = &buf[buf_len];
    *--cp = '\0';

    n = 4;
    do
    {
        byteval = addr & 0xff;
        *--cp = byteval % 10 + '0';
        byteval /= 10;
        if (byteval > 0)
        {
            *--cp = byteval % 10 + '0';
            byteval /= 10;
            if (byteval > 0)
                *--cp = byteval + '0';
        }
        *--cp = '.';
        addr >>= 8;
    } while (--n > 0);

    /* Convert the string to lowercase */
    retStr = (char*) (cp + 1);

    return (retStr);
}



/* ************************************** */
/* Layer 4 */

SOCKET open_socket(int local_port, int bind_any)
{
    SOCKET sock_fd;
    struct sockaddr_in local_address;
    int sockopt = 1;

    if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        traceError("Unable to create socket [%s][%d]\n",
            strerror(errno), sock_fd);
        return (-1);
    }

#ifndef WIN32
    /* fcntl(sock_fd, F_SETFL, O_NONBLOCK); */
#endif

    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &sockopt, sizeof(sockopt));

    memset(&local_address, 0, sizeof(local_address));
    local_address.sin_family = AF_INET;
    local_address.sin_port = htons(local_port);
    local_address.sin_addr.s_addr = htonl(bind_any ? INADDR_ANY : INADDR_LOOPBACK);
    if (bind(sock_fd, (struct sockaddr*) &local_address, sizeof(local_address)) == -1)
    {
        traceError("Bind error [%s]\n", strerror(errno));
        return (-1);
    }

    return (sock_fd);
}


static int fill_sockaddr(struct sockaddr *out_addr, const n2n_sock_t *sock)
{
    struct sockaddr_in *si = NULL;

    if (AF_INET != sock->family)
    {
        /* AF_INET6 not implemented */
        errno = EAFNOSUPPORT;
        return -1;
    }

    si = (struct sockaddr_in *) out_addr;
    si->sin_family = sock->family;
    si->sin_port   = htons(sock->port);
    memcpy(&si->sin_addr.s_addr, sock->addr.v4, IPV4_SIZE);
    return 0;
}

/** Send a datagram to a socket defined by a n2n_sock_t.
 *
 *  @return -1 on error otherwise number of bytes sent
 */
ssize_t sendto_sock(int         sock_fd,
                    const void *pktbuf,
                    size_t      pktsize,
                    const n2n_sock_t *dest)
{
    n2n_sock_str_t sockbuf;
    struct sockaddr_in dst_addr;
    ssize_t sent;

    fill_sockaddr((struct sockaddr *) &dst_addr, dest);

    traceDebug("sendto_sock %lu to [%s]", pktsize, sock_to_cstr(sockbuf, dest));//TODO to be removed

    sent = sendto(sock_fd,
                  pktbuf, pktsize,
                  0/*flags*/,
                  (const struct sockaddr *) &dst_addr,
                  sizeof(struct sockaddr_in));

    if (sent < 0)
    {
        char *c = strerror(errno);
        traceError("sendto failed (%d) %s", errno, c);
    }
    else
    {
        traceDebug("sendto sent=%d", (signed int) sent);
    }

    return sent;
}



/* @return zero if the two sockets are equivalent. */
int sock_equal(const n2n_sock_t *a,
               const n2n_sock_t *b)
{
    if (a->port != b->port)
        return 1;

    if (a->family != b->family)
        return 1;

    switch (a->family) /* they are the same */
    {
    case AF_INET:
        if (0 != memcmp(a->addr.v4, b->addr.v4, IPV4_SIZE))
            return 1;
        break;
    default:
        if (0 != memcmp(a->addr.v6, b->addr.v6, IPV6_SIZE))
            return 1;
        break;
    }

    return 0;
}



extern char *sock_to_cstr(n2n_sock_str_t out,
                          const n2n_sock_t *sock)
{
    int r;

    if (NULL == out)
        return NULL;

    memset(out, 0, N2N_SOCKBUF_SIZE);

    if (AF_INET6 == sock->family)
    {
        /* INET6 not written yet */
        r = snprintf(out, N2N_SOCKBUF_SIZE, "XXXX:%hu", sock->port);
        return out;
    }
    else
    {
        const uint8_t *a = sock->addr.v4;
        r = snprintf(out, N2N_SOCKBUF_SIZE, "%hu.%hu.%hu.%hu:%hu",
                     (a[0] & 0xff), (a[1] & 0xff), (a[2] & 0xff), (a[3] & 0xff), sock->port);
        return out;
    }
}

extern n2n_sock_t *sock_from_cstr(n2n_sock_t *out, const n2n_sock_str_t str)
{
    if (NULL == out)
        return NULL;

    memset(out, 0, sizeof(n2n_sock_t));

    if (strchr(str, '.'))
    {
        /* IPv4 */
        unsigned int ipv4[IPV4_SIZE];
        unsigned int port;
        out->family = AF_INET;
        sscanf(str, "%d.%d.%d.%d:%d", &ipv4[0], &ipv4[1], &ipv4[2], &ipv4[3], &port);
        out->addr.v4[0] = ipv4[0];
        out->addr.v4[1] = ipv4[1];
        out->addr.v4[2] = ipv4[2];
        out->addr.v4[3] = ipv4[3];
        out->port = port;
        return out;
    }
    else if (strchr(str, ':'))
    {
        /* INET6 not written yet */
        out->family = AF_INET6;
        sscanf(str, "XXXX:%hu", &out->port);
        return out;
    }

    return NULL;
}







