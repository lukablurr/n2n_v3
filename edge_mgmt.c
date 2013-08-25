/*
 * edge_mgmt.c
 *
 *  Created on: Aug 22, 2013
 *      Author: wolf
 */

#include "edge_mgmt.h"
#include "n2n_log.h"
#include <string.h>


#define CMD_STOP        "stop"
#define CMD_HELP        "help"
#define CMD_VERB_INC    "+verb"
#define CMD_VERB_DEC    "-verb"
#define CMD_RELOAD      "reload"



static size_t build_stats_response(n2n_edge_t *eee, uint8_t rsp_buf[])
{
    size_t msg_len = 0;
    time_t now = time(NULL);

    traceDebug("mgmt status rq");

    msg_len += snprintf((char *) (rsp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "Statistics for edge\n");

    msg_len += snprintf((char *) (rsp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "uptime %lu\n",
                        time(NULL) - eee->start_time);

    msg_len += snprintf((char *) (rsp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "paths  super:%u,%u p2p:%u,%u\n",
                        (unsigned int) eee->tx_sup,
                        (unsigned int) eee->rx_sup,
                        (unsigned int) eee->tx_p2p,
                        (unsigned int) eee->rx_p2p);

    msg_len += snprintf((char *) (rsp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "trans:null |%6u|%6u|\n"
                        "trans:tf   |%6u|%6u|\n"
                        "trans:aes  |%6u|%6u|\n",
                        (unsigned int) eee->transop[N2N_TRANSOP_NULL_IDX].tx_cnt,
                        (unsigned int) eee->transop[N2N_TRANSOP_NULL_IDX].rx_cnt,
                        (unsigned int) eee->transop[N2N_TRANSOP_TF_IDX].tx_cnt,
                        (unsigned int) eee->transop[N2N_TRANSOP_TF_IDX].rx_cnt,
                        (unsigned int) eee->transop[N2N_TRANSOP_AESCBC_IDX].tx_cnt,
                        (unsigned int) eee->transop[N2N_TRANSOP_AESCBC_IDX].rx_cnt);

    msg_len += snprintf((char *) (rsp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "peers  pend:%u full:%u\n",
                        (unsigned int) list_size(&eee->pending_peers),
                        (unsigned int) list_size(&eee->known_peers));

    msg_len += snprintf((char *) (rsp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "last   super:%lu(%ld sec ago) p2p:%lu(%ld sec ago)\n",
                        eee->last_sup, (now - eee->last_sup), eee->last_p2p, (now - eee->last_p2p));

    return msg_len;
}


static size_t build_help_response(uint8_t rsp_buf[])
{
    size_t msg_len = 0;
    msg_len = snprintf((char *) rsp_buf, N2N_PKT_BUF_SIZE,
                       "Help for edge management console:\n"
                       "  %7s Gracefully exit edge\n"
                       "  %7s This help message\n"
                       "  %7s Increase verbosity of logging\n"
                       "  %7s Decrease verbosity of logging\n"
                       "  %7s Re-read the keyschedule\n"
                       "  <enter> Display statistics\n\n",
                       CMD_STOP, CMD_HELP, CMD_VERB_INC, CMD_VERB_DEC, CMD_RELOAD);
    return msg_len;
}


static size_t process_verb_inc_cmd(uint8_t rsp_buf[])
{
    size_t msg_len = 0;

    ++traceLevel;
    traceError("+verb traceLevel=%u", (unsigned int) traceLevel);

    msg_len += snprintf((char *) rsp_buf, N2N_PKT_BUF_SIZE,
                        "> +OK traceLevel=%u\n", (unsigned int) traceLevel);
    return msg_len;
}


static size_t process_verb_dec_cmd(uint8_t rsp_buf[])
{
    size_t msg_len = 0;

    if (traceLevel > 0)
    {
        --traceLevel;
        msg_len += snprintf((char *) rsp_buf, N2N_PKT_BUF_SIZE,
                            "> -OK traceLevel=%u\n", traceLevel);
    }
    else
    {
        msg_len += snprintf((char *) rsp_buf, N2N_PKT_BUF_SIZE,
                            "> -NOK traceLevel=%u\n", traceLevel);
    }

    traceError("-verb traceLevel=%u", (unsigned int) traceLevel);
    return msg_len;
}


static size_t process_reload_cmd(n2n_edge_t *eee, uint8_t buf[])
{
    size_t msg_len = 0;

    if (strlen(eee->keyschedule) > 0)
    {
        if (edge_init_keyschedule(eee) == 0)
        {
            msg_len += snprintf((char *) buf, N2N_PKT_BUF_SIZE, "> OK\n");
        }
    }

    return msg_len;
}


edge_cmd_t process_edge_mgmt(n2n_edge_t *eee,
                             uint8_t req_buf[], ssize_t req_len,
                             uint8_t rsp_buf[], size_t *rsp_len)
{
    if (req_len >= 4)
    {
        if (0 == memcmp(req_buf, CMD_STOP, strlen(CMD_STOP)))
        {
            return EDGE_CMD_STOP;
        }

        if (0 == memcmp(req_buf, "help", 4))
        {
            *rsp_len = build_help_response(rsp_buf);
            return EDGE_CMD_HELP;
        }

    }

    if (req_len >= 5)
    {
        if (0 == memcmp(req_buf, CMD_VERB_INC, strlen(CMD_VERB_INC)))
        {
            *rsp_len = process_verb_inc_cmd(rsp_buf);
            return EDGE_CMD_VERB_INC;
        }

        if (0 == memcmp(req_buf, CMD_VERB_DEC, strlen(CMD_VERB_DEC)))
        {
            *rsp_len = process_verb_dec_cmd(rsp_buf);
            return EDGE_CMD_VERB_DEC;
        }
    }

    if (req_len >= 6)
    {
        if (0 == memcmp(req_buf, CMD_RELOAD, strlen(CMD_RELOAD)))
        {
            *rsp_len = process_reload_cmd(eee, rsp_buf);
            return EDGE_CMD_RELOAD;
        }
    }

    *rsp_len = build_stats_response(eee, rsp_buf);
    return EDGE_CMD_STATS;
}


