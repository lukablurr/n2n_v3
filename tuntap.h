/*
 * tuntap.h
 *
 *  Created on: Aug 21, 2013
 *      Author: wolf
 */

#ifndef TUNTAP_H_
#define TUNTAP_H_

#include "n2n_net.h"


/* N2N_IFNAMSIZ is needed on win32 even if dev_name is not used after declaration */
#define N2N_IFNAMSIZ            16 /* 15 chars * NULL */


#ifndef WIN32

#include <stdint.h>

typedef struct tuntap_dev
{
    int             fd;
    uint8_t         mac_addr[6];
    uint32_t        ip_addr;
    uint32_t        device_mask;
    uint16_t        mtu;
    char            dev_name[N2N_IFNAMSIZ];
} tuntap_dev;

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
} tuntap_dev;

#endif /* #ifndef WIN32 */



/*extern int  tuntap_open(tuntap_dev *device, char *dev, const char *address_mode, char *device_ip,
                        char *device_mask, const char *device_mac, int mtu);*/
extern int  tuntap_open(tuntap_dev *device, ip_mode_t ip_mode);

extern int  tuntap_read(tuntap_dev *device, unsigned char *buf, int len);

extern int  tuntap_write(tuntap_dev *device, unsigned char *buf, int len);

extern void tuntap_close(tuntap_dev *device);

extern void tuntap_get_address(tuntap_dev *device);



#endif /* TUNTAP_H_ */
