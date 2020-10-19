/*
 * log.h
 *
 *  Created on: 2013-02-25
 *      Author: lizhitao
 */
#include <sys/types.h>
#include <sys/time.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifndef LOG_H_
#define LOG_H_
#include "ngx_string.h"

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_ERROR 3

void log_init();
void log_print(int level, const char *fmt, ...);
void stderr_print(const char *fmt, ...);
#endif
