/*
 * n2n_log.h
 *
 *  Created on: Aug 21, 2013
 *      Author: wolf
 */

#ifndef N2N_LOG_H_
#define N2N_LOG_H_



/* Logging levels */

#define N2N_LOG_ERROR     0
#define N2N_LOG_WARNING   1
#define N2N_LOG_NORMAL    2
#define N2N_LOG_INFO      3
#define N2N_LOG_DEBUG     4

#define TRACE(LOG_LVL)  LOG_LVL, __FILE__, __LINE__

#define TRACE_ERROR     TRACE(N2N_LOG_ERROR)
#define TRACE_WARNING   TRACE(N2N_LOG_WARNING)
#define TRACE_NORMAL    TRACE(N2N_LOG_NORMAL)
#define TRACE_INFO      TRACE(N2N_LOG_INFO)
#define TRACE_DEBUG     TRACE(N2N_LOG_DEBUG)

/* ************************************** */

extern int traceLevel;
extern int useSyslog;

extern void traceEvent(int eventTraceLevel, char *file, int line, char *format, ...);

/* ************************************** */

#define traceError(...)    traceEvent(TRACE_ERROR,   __VA_ARGS__)
#define traceWarning(...)  traceEvent(TRACE_WARNING, __VA_ARGS__)
#define traceNormal(...)   traceEvent(TRACE_NORMAL,  __VA_ARGS__)
#define traceInfo(...)     traceEvent(TRACE_INFO,    __VA_ARGS__)
#define traceDebug(...)    traceEvent(TRACE_DEBUG,   __VA_ARGS__)



#endif /* N2N_LOG_H_ */
