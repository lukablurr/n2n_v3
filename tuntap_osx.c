/*
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
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
 */

#include "n2n.h"
#include "n2n_log.h"
#include "tuntap.h"

#ifdef _DARWIN_

/* ********************************** */

#define N2N_OSX_TAPDEVICE_SIZE 32
int tuntap_open(tuntap_dev_t *device , ip_mode_t ip_mode)
                /*char *dev,
                const char *address_mode, // static or dhcp
                char *device_ip, 
                char *device_mask,
                const char *device_mac,
                int mtu)*/
{
    int i;
    char tap_device[N2N_OSX_TAPDEVICE_SIZE];

    for (i = 0; i < 255; i++)
    {
        snprintf(tap_device, sizeof(tap_device), "/dev/tap%d", i);

        device->fd = open(tap_device, O_RDWR);
        if (device->fd > 0)
        {
            traceNormal("Succesfully open %s", tap_device);
            break;
        }
    }

    if (device->fd < 0)
    {
        traceError("Unable to open tap device");
        return (-1);
    }
    else
    {
        char buf[256];
        ipstr_t ipstr, maskstr;
        FILE *fd;

        //TODO remove device->ip_addr = inet_addr(device_ip);

        if ( !is_empty_mac(device->mac_addr) )
        {
            /* FIXME - This is not tested. Might be wrong syntax for OS X */

            /* Set the hw address before bringing the if up. */
            macstr_t macstr;
            snprintf(buf, sizeof(buf), "ifconfig tap%d ether %s",
                     i, mac2str(macstr, device->mac_addr));
            system(buf);
        }

        ipv4_to_str(ipstr, sizeof(ipstr_t), (const uint8_t *) &device->ip_addr);
        ipv4_to_str(maskstr, sizeof(ipstr_t), (const uint8_t *) &device->device_mask);

        snprintf(buf, sizeof(buf), "ifconfig tap%d %s netmask %s mtu %d up",
                 i, ipstr, maskstr, device->mtu);
        system(buf);

        traceNormal("Interface tap%d up and running (%s/%s)",
                    i, ipstr, maskstr);

        /* Read MAC address */

        snprintf(buf, sizeof(buf), "ifconfig tap%d |grep ether|cut -c 8-24", i);
        /* traceInfo("%s", buf); */

        fd = popen(buf, "r");
        if (fd < 0)
        {
            tuntap_close(device);
            return (-1);
        }
        else
        {
            int a, b, c, d, e, f;

            buf[0] = 0;
            fgets(buf, sizeof(buf), fd);
            pclose(fd);

            if (buf[0] == '\0')
            {
                traceError("Unable to read tap%d interface MAC address");
                exit(0);
            }

            traceNormal("Interface tap%d [MTU %d] mac %s", i, device->mtu, buf);
            if (sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", &a, &b, &c, &d, &e, &f) == 6)
            {
                device->mac_addr[0] = a, device->mac_addr[1] = b;
                device->mac_addr[2] = c, device->mac_addr[3] = d;
                device->mac_addr[4] = e, device->mac_addr[5] = f;
            }
        }
    }

    /* read_mac(dev, device->mac_addr); */
    return (device->fd);
}

/* ********************************** */

int tuntap_read(tuntap_dev_t *device, unsigned char *buf, int len)
{
    return (read(device->fd, buf, len));
}

/* ********************************** */

int tuntap_write(tuntap_dev_t *device, unsigned char *buf, int len)
{
    return (write(device->fd, buf, len));
}

/* ********************************** */

void tuntap_close(tuntap_dev_t *device)
{
    close(device->fd);
}

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(tuntap_dev_t *device)
{
}

#endif /* _DARWIN_ */
