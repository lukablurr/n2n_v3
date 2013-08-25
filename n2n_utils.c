/**
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
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#include "n2n_utils.h"
#include "n2n_log.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>


/* parse the configuration file */
static int readConfFile(const char *filename, char * const linebuffer)
{
    struct stat stats;
    FILE *fd;
    char *buffer = NULL;

    buffer = (char *) malloc(MAX_CONFFILE_LINE_LENGTH);
    if (!buffer)
    {
        traceError("Unable to allocate memory");
        return -1;
    }

    if (stat(filename, &stats))
    {
        if (errno == ENOENT)
            traceError("parameter file %s not found/unable to access\n", filename);
        else
            traceError("cannot stat file %s, errno=%d\n", filename, errno);
        free(buffer);
        return -1;
    }

    fd = fopen(filename, "rb");
    if (!fd)
    {
        traceError("Unable to open parameter file '%s' (%d)...\n", filename, errno);
        free(buffer);
        return -1;
    }
    while (fgets(buffer, MAX_CONFFILE_LINE_LENGTH, fd))
    {
        char *p = NULL;

        /* strip out comments */
        p = strchr(buffer, '#');
        if (p)
            *p = '\0';

        /* remove \n */
        p = strchr(buffer, '\n');
        if (p)
            *p = '\0';

        /* strip out heading spaces */
        p = buffer;
        while (*p == ' ' && *p != '\0')
            ++p;
        if (p != buffer)
            strncpy(buffer, p, strlen(p) + 1);

        /* strip out trailing spaces */
        while (strlen(buffer) && buffer[strlen(buffer) - 1] == ' ')
            buffer[strlen(buffer) - 1] = '\0';

        /* check for nested @file option */
        if (strchr(buffer, '@'))
        {
            traceError("@file in file nesting is not supported\n");
            free(buffer);
            return -1;
        }
        if ((strlen(linebuffer) + strlen(buffer) + 2) < MAX_CMDLINE_BUFFER_LENGTH)
        {
            strncat(linebuffer, " ", 1);
            strncat(linebuffer, buffer, strlen(buffer));
        }
        else
        {
            traceError("too many argument");
            free(buffer);
            return -1;
        }
    }

    free(buffer);
    fclose(fd);

    return 0;
}

/* Create the argv vector */
static void buildargv(const char * const linebuffer, effective_args_t *effective_args)
{
    const int INITIAL_MAXARGC = 16; /* Number of args + NULL in initial argv */
    int maxargc;
    int argc = 0;
    char **argv;
    char *buffer, *buff;

    buffer = (char *) calloc(1, strlen(linebuffer) + 2);
    if (!buffer)
    {
        traceError("Unable to allocate memory");
        exit(1);
    }
    strncpy(buffer, linebuffer, strlen(linebuffer));

    maxargc = INITIAL_MAXARGC;
    argv = (char **) malloc(maxargc * sizeof(char*));
    if (argv == NULL)
    {
        traceError("Unable to allocate memory");
        exit(1);
    }
    buff = buffer;
    while (buff)
    {
        char *p = strchr(buff, ' ');
        if (p)
        {
            *p = '\0';
            argv[argc++] = strdup(buff);
            while (*++p == ' ' && *p != '\0')
                ;
            buff = p;
            if (argc >= maxargc)
            {
                maxargc *= 2;
                argv = (char **) realloc(argv, maxargc * sizeof(char*));
                if (argv == NULL)
                {
                    traceError("Unable to re-allocate memory");
                    free(buffer);
                    exit(1);
                }
            }
        }
        else
        {
            argv[argc++] = strdup(buff);
            break;
        }
    }
    free(buffer);

    effective_args->argc = argc;
    effective_args->argv = argv;
}

void build_effective_args(int argc, char *argv[], effective_args_t *effective_args)
{
    int i;

    char *linebuffer = (char *) malloc(MAX_CMDLINE_BUFFER_LENGTH);
    if (!linebuffer)
    {
        traceError("Unable to allocate memory");
        exit(1);
    }

    snprintf(linebuffer, MAX_CMDLINE_BUFFER_LENGTH, "%s", argv[0]);

#ifdef WIN32
    for (i = 0; i < (int) strlen(linebuffer); i++)
        if (linebuffer[i] == '\\')
            linebuffer[i] = '/';
#endif

    for (i = 1; i < argc; ++i)
    {
        if (argv[i][0] == '@')
        {
            if (readConfFile(&argv[i][1], linebuffer) < 0)
                exit(1); /* <<<<----- check */
        }
        else if ((strlen(linebuffer) + strlen(argv[i]) + 2) < MAX_CMDLINE_BUFFER_LENGTH)
        {
            strncat(linebuffer, " ", 1);
            strncat(linebuffer, argv[i], strlen(argv[i]));
        }
        else
        {
            traceError("too many argument");
            exit(1);
        }
    }
    /* strip trailing spaces */
    while (strlen(linebuffer) && linebuffer[ strlen(linebuffer) - 1 ] == ' ')
        linebuffer[ strlen(linebuffer) - 1 ] = '\0';

    /* build the new argv from the linebuffer */
    buildargv(linebuffer, effective_args);

    if (linebuffer)
    {
        free(linebuffer);
        linebuffer = NULL;
    }

    /* {int k;for(k=0;k<effectiveargc;++k)  printf("%s\n",effectiveargv[k]);} */
}

void destroy_effective_args(effective_args_t *effective_args)
{
    int i;
    for (i = 0; i < effective_args->argc; ++i)
    {
        free(effective_args->argv[i]);
    }
    free(effective_args->argv);
    effective_args->argv = NULL;
    effective_args->argc = 0;
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


