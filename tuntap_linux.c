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
 * along with this program; if not, see <http://www.gnu.org/licenses/>
*/

#include "n2n.h"
#include "n2n_log.h"
#include "tuntap.h"



#ifdef __linux__

static void read_mac(char *ifname, n2n_mac_t mac_addr)
{
    int _sock, res;
    struct ifreq ifr;
    macstr_t mac_addr_buf;

    memset(&ifr, 0, sizeof(struct ifreq));

    /* Dummy socket, just to make ioctls with */
    _sock = socket(PF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, ifname);
    res = ioctl(_sock, SIOCGIFHWADDR, &ifr);
    if (res < 0)
    {
        perror("Get hw addr");
    }
    else
        memcpy(mac_addr, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

    traceNormal("Interface %s has MAC %s",
               ifname,
               mac2str(mac_addr_buf, mac_addr));
    close(_sock);
}

/* ********************************** */

/** @brief  Open and configure the TAP device for packet read/write.
 *
 *  This routine creates the interface via the tuntap driver then uses ifconfig
 *  to configure address/mask and MTU.
 *
 *  @param device      - [inout] a device info holder object
 *  @param dev         - user-defined name for the new iface, 
 *                       if NULL system will assign a name
 *  @param device_ip   - address of iface
 *  @param device_mask - netmask for device_ip
 *  @param mtu         - MTU for device_ip
 *
 *  @return - negative value on error
 *          - non-negative file-descriptor on success
 */
int tuntap_open(tuntap_dev_t *device, ip_mode_t ip_mode)
                //char *dev, /* user-definable interface name, eg. edge0 */
                //const char *address_mode, /* static or dhcp */
                //char *device_ip,
                //char *device_mask,
                //const char *device_mac,
                //int mtu)
{
    char *tuntap_device = "/dev/net/tun";
#define N2N_LINUX_SYSTEMCMD_SIZE 128
    char buf[N2N_LINUX_SYSTEMCMD_SIZE];
    struct ifreq ifr;
    int rc;

    //TODO
    ipstr_t ipstr;

    device->fd = open(tuntap_device, O_RDWR);
    if (device->fd < 0)
    {
        traceEvent(TRACE_ERROR, "Unable to open TUN/TAP device: ioctl() [%s][%d]\n", strerror(errno), errno);
        return -1;
    }

    traceEvent(TRACE_NORMAL, "Succesfully open %s\n", tuntap_device);
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI; /* Want a TAP device for layer 2 frames. */
    strncpy(ifr.ifr_name, device->dev_name, IFNAMSIZ);
    rc = ioctl(device->fd, TUNSETIFF, (void *) &ifr);

    if (rc < 0)
    {
        traceError("ioctl() [%s][%d]\n", strerror(errno), rc);
        close(device->fd);
        return -1;
    }

    /* Store the device name for later reuse */
    strncpy(device->dev_name, ifr.ifr_name, MIN(IFNAMSIZ, N2N_IFNAMSIZ));

    if ( !is_empty_mac(device->mac_addr) )
    {
        /* Set the hw address before bringing the if up. */
        macstr_t macstr;
        snprintf(buf, sizeof(buf), "/sbin/ifconfig %s hw ether %s",
                 ifr.ifr_name, mac2str(macstr, device->mac_addr));
        system(buf);
        traceInfo("Setting MAC: %s", buf);
    }


    ipv4_to_str(ipstr, sizeof(ipstr_t), (const uint8_t *) &device->ip_addr);//TODO make array

    if (ip_mode == N2N_IPM_DHCP)
    {
        snprintf(buf, sizeof(buf), "/sbin/ifconfig %s %s mtu %d up",
                 ifr.ifr_name, ipstr, device->mtu);
    }
    else
    {
        ipstr_t maskstr;
        strcpy((char *) maskstr, inet_ntoa( *(  (struct in_addr *) &device->device_mask)  ));//TODO
        //intoa(device->device_mask, maskstr, sizeof(maskstr));

        snprintf(buf, sizeof(buf), "/sbin/ifconfig %s %s netmask %s mtu %d up",
                 ifr.ifr_name, ipstr, maskstr, device->mtu);
    }

    traceInfo("Bringing up: %s", buf);
    system(buf);

    //device->ip_addr = inet_addr(device_ip);
    //device->device_mask = inet_addr(device_mask);
    read_mac(device->dev_name, device->mac_addr);
    return (device->fd);
}

int tuntap_read(tuntap_dev_t *device, unsigned char *buf, int len)
{
    return (read(device->fd, buf, len));
}

int tuntap_write(tuntap_dev_t *device, unsigned char *buf, int len)
{
    return (write(device->fd, buf, len));
}

void tuntap_close(tuntap_dev_t *device)
{
    close(device->fd);
}

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(tuntap_dev_t *device)
{
    FILE *fp = NULL;
    ssize_t nread = 0;
    char buf[N2N_LINUX_SYSTEMCMD_SIZE];

    /* Would rather have a more direct way to get the inet address but a netlink
     * socket is overkill and probably less portable than ifconfig and sed. */

    /* If the interface has no address (0.0.0.0) there will be no inet addr
     * line and the returned string will be empty. */
    snprintf(buf, sizeof(buf),
             "/sbin/ifconfig %s | /bin/sed -e '/inet addr:/!d' -e 's/^.*inet addr://' -e 's/ .*$//'",
             device->dev_name);
    fp = popen(buf, "r");
    if (fp)
    {
        memset(buf, 0, N2N_LINUX_SYSTEMCMD_SIZE); /* make sure buf is NULL terminated. */
        nread = fread(buf, 1, 15, fp);
        fclose(fp);
        fp = NULL;

        traceInfo("ifconfig address = %s", buf);

        device->ip_addr = inet_addr(buf);
    }
}


#endif /* #ifdef __linux__ */
