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
#include "n2n_log.h"



/******************************************************************************
 *
 * LAYER 2
 *
 */

static const n2n_mac_t broadcast_addr =
        { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const n2n_mac_t multicast_addr =
        { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x00 }; /* First 3 bytes are meaningful */

static const n2n_mac_t ipv6_multicast_addr =
        { 0x33, 0x33, 0x00, 0x00, 0x00, 0x00 }; /* First 2 bytes are meaningful */


int is_empty_mac(const uint8_t *mac)
{
    const n2n_mac_t empty_addr =
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    return (0 == memcmp(mac, empty_addr, ETH_ADDR_LEN));
}


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


char *mac2str(macstr_t buf, const n2n_mac_t mac)
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


/******************************************************************************
 *
 * LAYER 3
 *
 */

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


static int extract_ipv4(n2n_sock_t *out, const char* str_orig)
{
    int retval = ( 1 != inet_pton(AF_INET, str_orig, out->addr.v4) );
    if (retval)
    {
        traceError("Error extracting IPv4 address: %s", str_orig);
    }
    return retval;
}


static int extract_ipv6(n2n_sock_t *out, const char* str_orig)
{
    int retval = ( 1 != inet_pton(AF_INET6, str_orig, out->addr.v6) );
    if (retval)
    {
        traceError("Error extracting IPv6 address: %s", str_orig);
    }
    return retval;
}


/******************************************************************************
 *
 * LAYER 4
 *
 */

SOCKET open_socket(int local_port, int bind_any)
{
    SOCKET sock_fd;
    struct sockaddr_in local_address;
    int sockopt = 1;

    if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        traceError("Unable to create socket [%s][%d]\n", strerror(errno), sock_fd);
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


static int fill_sockaddr(struct sockaddr_storage *out_addr, const n2n_sock_t *sock)
{
    if (AF_INET == sock->family)
    {
        struct sockaddr_in *si = (struct sockaddr_in *) out_addr;
        si->sin_family = AF_INET;
        si->sin_port = htons(sock->port);//TODO
        memcpy(&si->sin_addr.s_addr, sock->addr.v4, IPV4_SIZE);
        return 0;
    }
    else if (AF_INET6 == sock->family)
    {
        struct sockaddr_in6 *si6 = (struct sockaddr_in6 *) out_addr;
        si6->sin6_family = AF_INET6;
        si6->sin6_port = htons(sock->port);//TODO
        si6->sin6_flowinfo = 0;
        memcpy(&si6->sin6_addr, sock->addr.v6, IPV6_SIZE);
        si6->sin6_scope_id = 0;
        return 0;
    }

    errno = EAFNOSUPPORT;
    return -1;
}

/**
 * Send a datagram to a socket defined by a n2n_sock_t.
 *
 * @return -1 on error otherwise number of bytes sent
 */
ssize_t sendto_sock(int sock_fd,
                    const void *pktbuf, size_t pktsize,
                    const n2n_sock_t *dest)
{
    n2n_sock_str_t sockbuf;
    struct sockaddr_storage dst_addr;
    ssize_t sent;

    fill_sockaddr(&dst_addr, dest);

    traceDebug("sendto_sock %lu to [%s]", pktsize, sock2str(sockbuf, dest));//TODO to be removed

    sent = sendto(sock_fd,
                  pktbuf, pktsize,
                  0 /* flags */,
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
int sock_equal(const n2n_sock_t *a, const n2n_sock_t *b)
{
    if (a->port != b->port)
        return 1;

    if (a->family != b->family)
        return 1;

    if (a->family == AF_INET)
    {
        return (0 != memcmp(a->addr.v4, b->addr.v4, IPV4_SIZE));
    }

    return (0 != memcmp(a->addr.v6, b->addr.v6, IPV6_SIZE));
}


extern char *sock2str(n2n_sock_str_t out, const n2n_sock_t *sock)
{
    int r;
    ipstr_t ipstr;

    if (NULL == out)
        return NULL;

    if (NULL == inet_ntop(sock->family, &sock->addr, ipstr, 32/* TODO */))
    {
        //TODO log
        return NULL;
    }

    if (AF_INET6 == sock->family)
        r = snprintf(out, N2N_SOCKBUF_SIZE, "[%s]:%hu", ipstr, sock->port);//TODO ntoh
    else
        r = snprintf(out, N2N_SOCKBUF_SIZE, "%s:%hu", ipstr, sock->port);

    return out;
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


extern int str2sock(n2n_sock_t *out, const n2n_sock_str_t str_orig)
{
    int retval;

    n2n_sock_str_t str;
    memcpy(str, str_orig, sizeof(n2n_sock_str_t));


    char *last_colon_pos = strrchr(str, ':');

    if (strchr(str, ':') == last_colon_pos)
    {
        out->family = AF_INET;

        if (last_colon_pos) //TODO
        {
            *last_colon_pos = '\0';
            out->port = atoi(last_colon_pos + 1);
        }

        retval = extract_ipv4(out, str);
    }
    else
    {
        out->family = AF_INET6;

        char *l_brack_pos = strchr(str, '[');
        if (l_brack_pos)
        {
            char *r_brack_pos = strchr(str, ']');
            if (!r_brack_pos)
                return -1;//TODO

            if (r_brack_pos < last_colon_pos) //TODO
            {
                //*last_colon_pos = '\0';
                out->port = atoi(last_colon_pos + 1);
            }

            *r_brack_pos = 0;
            retval = extract_ipv6(out, l_brack_pos + 1);
        }
        else
            retval = extract_ipv6(out, str);
    }

    return retval;
}


/******************************************************************************
 *
 * TUNNELING
 *
 */

/**
 * Find the address and IP mode for the tuntap device.
 *
 *  s is one of these forms:
 *
 *  <host> := <hostname> | A.B.C.D
 *
 *  <host> | static:<host> | dhcp:<host>
 *
 *  If the mode is present (colon required) then fill ip_mode with that value
 *  otherwise do not change ip_mode. Fill ip_mode with everything after the
 *  colon if it is present; or s if colon is not present.(TODO - update)
 *
 *  return 0 on success and -1 on error
 */
int scan_address(uint32_t *ip_addr, ip_mode_t *ip_mode, const char *s)
{
    int retval = -1;//TODO use it?
    char *p;

    if ((NULL == s) || (NULL == ip_addr))
    {
        return -1;
    }

    p = strchr(s, ':');

    if (p)
    {
        /* colon is present */
        size_t host_off = p - s;

        if (ip_mode)
        {
            if (0 == strncmp(s, "static", host_off))
                *ip_mode = N2N_IPM_STATIC;

            else if (0 == strncmp(s, "dhcp", host_off))
                *ip_mode = N2N_IPM_DHCP;

            else
            {
                *ip_mode = N2N_IPM_NONE;
                traceError("Unknown IP mode: %.*s\n", host_off, s);
                return -1;
            }
        }

        /* move to IP position */
        s = p + 1;
    }

    *ip_addr = inet_addr(s);//TODO use a wrapping function

    return 0;
}



/******************************************************************************
 *
 * TESTING - TODO to be moved
 *
 */
/*
int main()
{
#define ENTRIES_NUM 14
    const char *entries[ENTRIES_NUM] = {
            "1.2.3.4",
            "1.2.3.4:4000",
            "226.000.000.037",
            "0x7f.1",
            "0:0:0:0:0:0:0:0",
            "1:0:0:0:0:0:0:8",
            "0:0:0:0:0:FFFF:204.152.189.116",
            "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443",
            "[2001:db8:85a3:8d3:1319:8a2e:370:7348]",
            "2001:db8:85a3:8d3:1319:8a2e:370:7348:443",
            "::",
            "::/128",
            "fc00::",
            "fc00::/7"
    };
    int i;
    n2n_sock_str_t sockstr;

    for (i = 0; i < ENTRIES_NUM; i++)
    {
        n2n_sock_t sock;
        memset(&sock, 0, sizeof(n2n_sock_t));

        int r = my_sock_from_cstr(&sock, entries[i]);

        printf("[%2d] = %s --> %s %s\n", i, entries[i],
               (r == 0 ? "PASSED" : "FAILED"),
               (r == 0 ? sock_to_cstr(sockstr, &sock) : ""));
    }



    return 0;
}*/



