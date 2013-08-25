/*
 * edge_mgmt.h
 *
 *  Created on: Aug 22, 2013
 *      Author: wolf
 */

#ifndef EDGE_MGMT_H_
#define EDGE_MGMT_H_

#include "edge.h"
#include <stdint.h>



typedef enum edge_cmd
{
    EDGE_CMD_NONE = 0,
    EDGE_CMD_STATS,
    EDGE_CMD_STOP,
    EDGE_CMD_HELP,
    EDGE_CMD_VERB_INC,
    EDGE_CMD_VERB_DEC,
    EDGE_CMD_RELOAD

} edge_cmd_t;


edge_cmd_t process_edge_mgmt(n2n_edge_t *eee,
                             uint8_t req_buf[], ssize_t req_len,
                             uint8_t rsp_buf[], size_t *rsp_len);

#endif /* EDGE_MGMT_H_ */
