/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_times.h"
#include "ngx_time.h"
/*
 * The time may be updated by signal handler or by several threads.
 * The time update operations are rare and require to hold the ngx_time_lock.
 * The time read operations are frequent, so they are lock-free and get time
 * values and strings from the current slot.  Thus thread may get the corrupted
 * values only if it is preempted while copying and then it is not scheduled
 * to run more than NGX_TIME_SLOTS seconds.
 */

#define NGX_TIME_SLOTS   64

static ngx_uint_t slot;
static ngx_atomic_t ngx_time_lock;

volatile uintptr_t ngx_current_msec;
volatile ngx_time_t *ngx_cached_time;
volatile ngx_str_t ngx_cached_err_log_time;
volatile ngx_str_t ngx_cached_http_time;
volatile ngx_str_t ngx_cached_http_log_time;
volatile ngx_str_t ngx_cached_http_log_iso8601;

/*
 * locatime() and localtime_r() are not Async-Signal-Safe functions, therefore,
 * they must not be called by a signal handler, so we use the cached
 * GMT offset value. Fortunately the value is changed only two times a year.
 */

static ngx_int_t cached_gmtoff;
#define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))
#define ngx_unlock(lock)    *(lock) = 0
static ngx_time_t cached_time[NGX_TIME_SLOTS];
static u_char cached_err_log_time[NGX_TIME_SLOTS][sizeof("1970/09/28 12:00:00")];
static u_char cached_http_time[NGX_TIME_SLOTS][sizeof("Mon, 28 Sep 1970 06:00:00 GMT")];
static u_char cached_http_log_time[NGX_TIME_SLOTS][sizeof("28/Sep/1970:12:00:00 +0600")];
static u_char cached_http_log_iso8601[NGX_TIME_SLOTS][sizeof("1970-09-28T12:00:00+06:00")];

static char *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

void ngx_time_init(void) {
	ngx_cached_err_log_time.len = sizeof("1970/09/28 12:00:00") - 1;
	ngx_cached_http_time.len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;
	ngx_cached_http_log_time.len = sizeof("28/Sep/1970:12:00:00 +0600") - 1;
	ngx_cached_http_log_iso8601.len = sizeof("1970-09-28T12:00:00+06:00") - 1;

	ngx_cached_time = &cached_time[0];

	ngx_time_update();
}

void ngx_time_update(void) {
	u_char *p0, *p1, *p2, *p3;
	struct tm tm1, gmt;
	time_t sec;
	ngx_uint_t msec;
	ngx_time_t *tp;
	struct timeval tv;

	if (!ngx_trylock(&ngx_time_lock)) {
		return;
	}

	ngx_gettimeofday(&tv);

	sec = tv.tv_sec;
	msec = tv.tv_usec / 1000;

	ngx_current_msec = (uintptr_t) sec * 1000 + msec;

	tp = &cached_time[slot];

	if (tp->sec == sec) {
		tp->msec = msec;
		ngx_unlock(&ngx_time_lock);
		return;
	}

	if (slot == NGX_TIME_SLOTS - 1) {
		slot = 0;
	} else {
		slot++;
	}

	tp = &cached_time[slot];

	tp->sec = sec;
	tp->msec = msec;

	ngx_gmtime(sec, &gmt);

	p0 = &cached_http_time[slot][0];

	(void) ngx_sprintf(p0, "%s, %02d %s %4d %02d:%02d:%02d GMT", week[gmt.tm_wday], gmt.tm_mday, months[gmt.tm_mon - 1], gmt.tm_year, gmt.tm_hour, gmt.tm_min, gmt.tm_sec);

	ngx_localtime(sec, &tm1);
	cached_gmtoff = (ngx_int_t) (tm1.tm_gmtoff / 60);
	tp->gmtoff = cached_gmtoff;

	p1 = &cached_err_log_time[slot][0];

	(void) ngx_sprintf(p1, "%4d/%02d/%02d %02d:%02d:%02d", tm1.tm_year, tm1.tm_mon, tm1.tm_mday, tm1.tm_hour, tm1.tm_min, tm1.tm_sec);

	p2 = &cached_http_log_time[slot][0];

	(void) ngx_sprintf(p2, "%02d/%s/%d:%02d:%02d:%02d %c%02d%02d", tm1.tm_mday, months[tm1.tm_mon - 1], tm1.tm_year, tm1.tm_hour, tm1.tm_min, tm1.tm_sec,
			tp->gmtoff < 0 ? '-' : '+', ngx_abs(tp->gmtoff / 60), ngx_abs(tp->gmtoff % 60));

	p3 = &cached_http_log_iso8601[slot][0];

	(void) ngx_sprintf(p3, "%4d-%02d-%02dT%02d:%02d:%02d%c%02d:%02d", tm1.tm_year, tm1.tm_mon, tm1.tm_mday, tm1.tm_hour, tm1.tm_min, tm1.tm_sec, tp->gmtoff < 0 ? '-' : '+',
			ngx_abs(tp->gmtoff / 60), ngx_abs(tp->gmtoff % 60));

	__sync_synchronize();

	ngx_cached_time = tp;
	ngx_cached_http_time.data = p0;
	ngx_cached_err_log_time.data = p1;
	ngx_cached_http_log_time.data = p2;
	ngx_cached_http_log_iso8601.data = p3;

	ngx_unlock(&ngx_time_lock);
}

void ngx_time_sigsafe_update(void) {
	u_char *p;
	struct tm tm1;
	time_t sec;
	ngx_time_t *tp;
	struct timeval tv;

	if (!ngx_trylock(&ngx_time_lock)) {
		return;
	}

	ngx_gettimeofday(&tv);

	sec = tv.tv_sec;

	tp = &cached_time[slot];

	if (tp->sec == sec) {
		ngx_unlock(&ngx_time_lock);
		return;
	}

	if (slot == NGX_TIME_SLOTS - 1) {
		slot = 0;
	} else {
		slot++;
	}

	ngx_gmtime(sec + cached_gmtoff * 60, &tm1);

	p = &cached_err_log_time[slot][0];

	(void) ngx_sprintf(p, "%4d/%02d/%02d %02d:%02d:%02d", tm1.tm_year, tm1.tm_mon, tm1.tm_mday, tm1.tm_hour, tm1.tm_min, tm1.tm_sec);

	__sync_synchronize();

	ngx_cached_err_log_time.data = p;

	ngx_unlock(&ngx_time_lock);
}

u_char *
ngx_http_time(u_char *buf, time_t t) {
	struct tm tm1;

	ngx_gmtime(t, &tm1);

	return ngx_sprintf(buf, "%s, %02d %s %4d %02d:%02d:%02d GMT", week[tm1.tm_wday], tm1.tm_mday, months[tm1.tm_mon - 1], tm1.tm_year, tm1.tm_hour, tm1.tm_min, tm1.tm_sec);
}

u_char *
ngx_http_cookie_time(u_char *buf, time_t t) {
	struct tm tm1;

	ngx_gmtime(t, &tm1);

	/*
	 * Netscape 3.x does not understand 4-digit years at all and
	 * 2-digit years more than "37"
	 */

	return ngx_sprintf(buf, (tm1.tm_year > 2037) ?
	"%s, %02d-%s-%d %02d:%02d:%02d GMT":
	"%s, %02d-%s-%02d %02d:%02d:%02d GMT",
	week[tm1.tm_wday],
	tm1.tm_mday,
	months[tm1.tm_mon - 1],
	(tm1.tm_year > 2037) ? tm1.tm_year:
	tm1.tm_year % 100,
	tm1.tm_hour,
	tm1.tm_min,
	tm1.tm_sec);
}

void ngx_gmtime(time_t t, struct tm *tp) {
	ngx_int_t yday;
	ngx_uint_t n, sec, min, hour, mday, mon, year, wday, days, leap;

	/* the calculation is valid for positive time_t only */

	n = (ngx_uint_t) t;

	days = n / 86400;

	/* Jaunary 1, 1970 was Thursday */

	wday = (4 + days) % 7;

	n %= 86400;
	hour = n / 3600;
	n %= 3600;
	min = n / 60;
	sec = n % 60;

	/*
	 * the algorithm based on Gauss' formula,
	 * see src/http/ngx_http_parse_time.c
	 */

	/* days since March 1, 1 BC */
	days = days - (31 + 28) + 719527;

	/*
	 * The "days" should be adjusted to 1 only, however, some March 1st's go
	 * to previous year, so we adjust them to 2.  This causes also shift of the
	 * last Feburary days to next year, but we catch the case when "yday"
	 * becomes negative.
	 */

	year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1);

	yday = days - (365 * year + year / 4 - year / 100 + year / 400);

	if (yday < 0) {
		leap = (year % 4 == 0) && (year % 100 || (year % 400 == 0));
		yday = 365 + leap + yday;
		year--;
	}

	/*
	 * The empirical formula that maps "yday" to month.
	 * There are at least 10 variants, some of them are:
	 *     mon = (yday + 31) * 15 / 459
	 *     mon = (yday + 31) * 17 / 520
	 *     mon = (yday + 31) * 20 / 612
	 */

	mon = (yday + 31) * 10 / 306;

	/* the Gauss' formula that evaluates days before the month */

	mday = yday - (367 * mon / 12 - 30) + 1;

	if (yday >= 306) {

		year++;
		mon -= 10;

		/*
		 * there is no "yday" in Win32 SYSTEMTIME
		 *
		 * yday -= 306;
		 */

	} else {

		mon += 2;

		/*
		 * there is no "yday" in Win32 SYSTEMTIME
		 *
		 * yday += 31 + 28 + leap;
		 */
	}

	tp->tm_sec = (ngx_tm_sec_t) sec;
	tp->tm_min = (ngx_tm_min_t) min;
	tp->tm_hour = (ngx_tm_hour_t) hour;
	tp->tm_mday = (ngx_tm_mday_t) mday;
	tp->tm_mon = (ngx_tm_mon_t) mon;
	tp->tm_year = (ngx_tm_year_t) year;
	tp->tm_wday = (ngx_tm_wday_t) wday;
}

time_t ngx_next_time(time_t when) {
	time_t now, next;
	struct tm tm1;

	now = ngx_time();

	ngx_libc_localtime(now, &tm1);

	tm1.tm_hour = (int) (when / 3600);
	when %= 3600;
	tm1.tm_min = (int) (when / 60);
	tm1.tm_sec = (int) (when % 60);

	next = mktime(&tm1);

	if (next == -1) {
		return -1;
	}

	if (next - now > 0) {
		return next;
	}

	tm1.tm_mday++;

	/* mktime() should normalize a date (Jan 32, etc) */

	next = mktime(&tm1);

	if (next != -1) {
		return next;
	}

	return -1;
}
