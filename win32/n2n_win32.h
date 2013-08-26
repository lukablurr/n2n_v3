/*

	(C) 2007-09 - Luca Deri <deri@ntop.org>

*/

#ifndef _N2N_WIN32_H_
#define _N2N_WIN32_H_

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#if defined(__MINGW32__) || defined(__CYGWIN__)
/* should be defined here and before winsock gets included */
#define _WIN32_WINNT 0x501 //Otherwise the linker doesnt find getaddrinfo
#include <inttypes.h>
#endif /* #if defined(__MINGW32__) */

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>


#include "wintap.h"

#ifdef _MSC_VER
#include "getopt.h"

/* Other Win environments are expected to support stdint.h */

/* stdint.h typedefs (C99) (not present in Visual Studio) */
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

/* sys/types.h typedefs (not present in Visual Studio) */
typedef unsigned int u_int32_t;
typedef unsigned short u_int16_t;
typedef unsigned char u_int8_t;

typedef int ssize_t;

#define snprintf _snprintf
#define strdup   _strdup

#else

#define _snprintf snprintf
#define _strdup   strdup

#endif /* #ifdef _MSC_VER */

typedef unsigned long in_addr_t;


#define EAFNOSUPPORT   WSAEAFNOSUPPORT 
#define MAX(a,b) (a > b ? a : b)
#define MIN(a,b) (a < b ? a : b)

#define socklen_t int

/* ************************************* */

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
        u_char  ip_hl:4,                /* header length */
                ip_v:4;                 /* version */
#else
        u_char  ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
#endif
        u_char  ip_tos;                 /* type of service */
        short   ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        short   ip_off;                 /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


/* ************************************* */

#define index(a, b) strchr(a, b)


#endif
