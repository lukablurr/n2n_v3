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
 */

#ifndef N2N_UTILS_H_
#define N2N_UTILS_H_

#ifdef WIN32
# include "win32/n2n_win32.h"
#else
# include <stdint.h>
# include <sys/types.h>
#endif



/** maximum length of command line arguments */
#define MAX_CMDLINE_BUFFER_LENGTH    4096

/** maximum length of a line in the configuration file */
#define MAX_CONFFILE_LINE_LENGTH     1024



/* ************************************** */

struct effective_args
{
    int     argc;
    char  **argv;
};

typedef struct effective_args effective_args_t;


void build_effective_args(int argc, char *argv[], effective_args_t *effective_args);
void destroy_effective_args(effective_args_t *effective_args);



/* ************************************** */


void hexdump(const uint8_t *buf, size_t len);

/* ************************************** */

#ifndef max
#define max(a, b) ((a < b) ? b : a)
#endif

#ifndef min
#define min(a, b) ((a > b) ? b : a)
#endif


#endif /* N2N_UTILS_H_ */
