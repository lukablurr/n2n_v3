/*
 * n2n_log.c
 *
 *  Created on: Aug 21, 2013
 *      Author: wolf
 */

#include "n2n.h"
#include "n2n_log.h"
#include <stdarg.h>
#ifndef WIN32
# include <syslog.h>

int useSyslog = 0;
int syslog_opened = 0;

#endif /* #ifndef WIN32 */


#define N2N_TRACE_DATESIZE 32


int traceLevel = N2N_LOG_NORMAL;



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

        if (eventTraceLevel == N2N_LOG_ERROR)
            extra_msg = "ERROR: ";
        else if (eventTraceLevel == N2N_LOG_WARNING)
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


