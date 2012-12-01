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

#include "minilzo.h"

#include <assert.h>

#if defined(DEBUG)
#   define PURGE_REGISTRATION_FREQUENCY   60
#   define REGISTRATION_TIMEOUT          120
#else /* #if defined(DEBUG) */
#   define PURGE_REGISTRATION_FREQUENCY   60
#   define REGISTRATION_TIMEOUT           (60*20)
#endif /* #if defined(DEBUG) */


int traceLevel = 2 /* NORMAL */;
int useSyslog = 0, syslog_opened = 0;

#define N2N_TRACE_DATESIZE 32
void traceEvent(int eventTraceLevel, char *file, int line, char *format, ...)
{
    va_list va_ap;

    if (eventTraceLevel <= traceLevel)
    {
        char buf[2048];
        char out_buf[640];
        char theDate[N2N_TRACE_DATESIZE];
        char *extra_msg = "";
        time_t theTime = time(NULL);
#ifdef WIN32
        int i;
#endif

        /* We have two paths - one if we're logging, one if we aren't
         *   Note that the no-log case is those systems which don't support it (WIN32),
         *                                those without the headers !defined(USE_SYSLOG)
         *                                those where it's parametrically off...
         */

        memset(buf, 0, sizeof(buf));
        strftime(theDate, N2N_TRACE_DATESIZE, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

        va_start(va_ap, format);
        vsnprintf(buf, sizeof(buf) - 1, format, va_ap);
        va_end(va_ap);

        if (eventTraceLevel == 0 /* TRACE_ERROR */)
            extra_msg = "ERROR: ";
        else if (eventTraceLevel == 1 /* TRACE_WARNING */)
            extra_msg = "WARNING: ";

        while (buf[strlen(buf) - 1] == '\n')
            buf[strlen(buf) - 1] = '\0';

#ifndef WIN32
        if (useSyslog)
        {
            if (!syslog_opened)
            {
                openlog("n2n", LOG_PID, LOG_DAEMON);
                syslog_opened = 1;
            }

            snprintf(out_buf, sizeof(out_buf), "%s%s", extra_msg, buf);
            syslog(LOG_INFO, "%s", out_buf);
        }
        else
        {
            snprintf(out_buf, sizeof(out_buf), "%s [%11s:%4d] %s%s", theDate, file, line, extra_msg, buf);
            printf("%s\n", out_buf);
            fflush(stdout);
        }
#else
        /* this is the WIN32 code */
        for (i = strlen(file) - 1; i > 0; i--)
        {
            if (file[i] == '\\')
            {
                i++;
                break;
            }
        }
        snprintf(out_buf, sizeof(out_buf), "%s [%11s:%4d] %s%s", theDate, &file[i], line, extra_msg, buf);
        printf("%s\n", out_buf);
        fflush(stdout);
#endif
  }

}


/* *********************************************** */

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

/* *********************************************** */

void hexdump(const uint8_t *buf, size_t len)
{
    size_t i;

    if (0 == len)
        return;

    for (i = 0; i < len; i++)
    {
        if ((i > 0) && ((i % 16) == 0))
            printf("\n");
        
        printf("%02X ", buf[i] & 0xFF);
    }

    printf("\n");
}

/* *********************************************** */

void print_n2n_version()
{
    printf("Welcome to n2n v.%s for %s\n"
           "Built on %s\n"
           "Copyright 2007-09 - http://www.ntop.org\n\n",
           n2n_sw_version, n2n_sw_osName, n2n_sw_buildDate);
}




/** Find the peer entry in list with mac_addr equal to mac.
 *
 *  Does not modify the list.
 *
 *  @return NULL if not found; otherwise pointer to peer entry.
 */
struct peer_info * find_peer_by_mac(struct n2n_list *list, const n2n_mac_t mac)
{
    struct peer_info *peer = NULL;

    N2N_LIST_FOR_EACH_ENTRY(peer, list)
    {
        if (0 == memcmp(mac, peer->mac_addr, 6))
            return peer;
    }

    return NULL;
}

/** Add new to the head of list. If list is NULL; create it.
 *
 *  The item new is added to the head of the list. New is modified during
 *  insertion. list takes ownership of new.
 */
void peer_list_add(struct n2n_list *list, struct peer_info *new)
{
    list_add(list, &new->list);
    new->last_seen = time(NULL);
}


size_t purge_expired_registrations(struct n2n_list *peer_list)
{
    static time_t last_purge = 0;
    time_t now = time(NULL);
    size_t num_reg = 0;

    if ((now - last_purge) < PURGE_REGISTRATION_FREQUENCY)
        return 0;

    traceInfo("Purging old registrations");

    num_reg = purge_peer_list(peer_list, now - REGISTRATION_TIMEOUT);

    last_purge = now;
    traceInfo("Remove %ld registrations", num_reg);

    return num_reg;
}

/** Purge old items from the peer_list and return the number of items that were removed. */
size_t purge_peer_list(struct n2n_list *peer_list, time_t purge_before)
{
    struct peer_info *scan = NULL;
    struct peer_info *prev = NULL;
    struct peer_info *next = NULL;
    size_t retval = 0;

    N2N_LIST_FOR_EACH_ENTRY_SAFE(scan, next, peer_list)
    {
        if (scan->last_seen < purge_before)
        {
            if (prev == NULL)
            {
                peer_list->next = &next->list;
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



