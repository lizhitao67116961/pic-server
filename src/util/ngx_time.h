/*
 * Copyright (C) Igor Sysoev
 */
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#ifndef _NGX_TIME_H_INCLUDED_
#define _NGX_TIME_H_INCLUDED_


//typedef struct tm ngx_tm_t;

//#define ngx_tm_sec            tm_sec
//#define ngx_tm_min            tm_min
//#define ngx_tm_hour           tm_hour
//#define ngx_tm_mday           tm_mday
//#define ngx_tm_mon            tm_mon
//#define ngx_tm_year           tm_year
//#define ngx_tm_wday           tm_wday
//#define ngx_tm_isdst          tm_isdst

#define ngx_tm_sec_t          int
#define ngx_tm_min_t          int
#define ngx_tm_hour_t         int
#define ngx_tm_mday_t         int
#define ngx_tm_mon_t          int
#define ngx_tm_year_t         int
#define ngx_tm_wday_t         int

#define ngx_tm_gmtoff         tm_gmtoff
#define ngx_tm_zone           tm_zone

#define ngx_timezone(isdst) (- (isdst ? timezone + 3600 : timezone) / 60)

void ngx_timezone_update(void);
void ngx_localtime(time_t s, struct tm *tm);
void ngx_libc_localtime(time_t s, struct tm *tm);
void ngx_libc_gmtime(time_t s, struct tm *tm);

#define ngx_gettimeofday(tp)  (void) gettimeofday(tp, NULL);
#define ngx_msleep(ms)        (void) usleep(ms * 1000)
#define ngx_sleep(s)          (void) sleep(s)

#endif /* _NGX_TIME_H_INCLUDED_ */
