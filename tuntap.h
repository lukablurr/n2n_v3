/*
 * tuntap.h
 *
 *  Created on: Aug 21, 2013
 *      Author: wolf
 */

#ifndef TUNTAP_H_
#define TUNTAP_H_

/*
   tunctl -t tun0
   tunctl -t tun1
   ifconfig tun0 1.2.3.4 up
   ifconfig tun1 1.2.3.5 up
   ./edge -d tun0 -l 2000 -r 127.0.0.1:3000 -c hello
   ./edge -d tun1 -l 3000 -r 127.0.0.1:2000 -c hello


   tunctl -u UID -t tunX
*/

#include "n2n_net.h"

#ifdef __linux__
# include <linux/if_tun.h>
# define N2N_CAN_NAME_IFACE 1
#endif /* #ifdef __linux__ */


/* N2N_IFNAMSIZ is needed on win32 even if dev_name is not used after declaration */
#define N2N_IFNAMSIZ            16 /* 15 chars * NULL */


#ifndef WIN32

typedef struct tuntap_dev
{
    int             fd;
    uint8_t         mac_addr[6];
    uint32_t        ip_addr;
    uint32_t        device_mask;
    uint16_t        mtu;
    char            dev_name[N2N_IFNAMSIZ];
} tuntap_dev_t;

#else
typedef struct tuntap_dev
{
    HANDLE          device_handle;
    char           *device_name;
    char           *ifName;
    OVERLAPPED      overlap_read;
    OVERLAPPED      overlap_write;
    uint8_t         mac_addr[6];
    uint32_t        ip_addr;
    uint32_t        device_mask;
    unsigned int    mtu;
} tuntap_dev_t;

#endif /* #ifndef WIN32 */



/*extern int  tuntap_open(tuntap_dev *device, char *dev, const char *address_mode, char *device_ip,
                        char *device_mask, const char *device_mac, int mtu);*/
extern int  tuntap_open(tuntap_dev_t *device, ip_mode_t ip_mode);

extern int  tuntap_read(tuntap_dev_t *device, unsigned char *buf, int len);

extern int  tuntap_write(tuntap_dev_t *device, unsigned char *buf, int len);

extern void tuntap_close(tuntap_dev_t *device);

extern void tuntap_get_address(tuntap_dev_t *device);



#endif /* TUNTAP_H_ */
