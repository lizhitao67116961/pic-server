/*
 * Copyright (C) Igor Sysoev
 */
#include "../imgzip_config.h"

#ifndef _NGX_STRING_H_INCLUDED_
#define _NGX_STRING_H_INCLUDED_
#define NGX_ESCAPE_URI            0
#define NGX_ESCAPE_ARGS           1
#define NGX_ESCAPE_URI_COMPONENT  2
#define NGX_ESCAPE_HTML           3
#define NGX_ESCAPE_REFRESH        4
#define NGX_ESCAPE_MEMCACHED      5
#define NGX_ESCAPE_MAIL_AUTH      6
typedef struct {
	size_t len;
	u_char *data;
} ngx_str_t;

typedef struct {
	ngx_str_t key;
	ngx_str_t value;
} ngx_keyval_t;

typedef struct {
	unsigned len :28;

	unsigned valid :1;
	unsigned no_cacheable :1;
	unsigned not_found :1;
	unsigned escape :1;

	u_char *data;
} ngx_variable_value_t;

#define ngx_string(str)     { sizeof(str) - 1, (u_char *) str }
#define ngx_null_string     { 0, NULL }
#define ngx_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#define ngx_str_null(str)   (str)->len = 0; (str)->data = NULL
#define ngx_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))
#define ngx_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define ngx_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)
static inline u_char *ngx_strlchr(u_char *p, u_char *last, u_char c) {
	while (p < last) {

		if (*p == c) {
			return p;
		}

		p++;
	}

	return NULL;
}
u_char *ngx_snprintf(u_char *buf, size_t max, const char *fmt, ...);
u_char * ngx_sprintf(u_char *buf, const char *fmt, ...);
u_char *ngx_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args);
void ngx_strlow(u_char *dst, u_char *src, size_t n);
u_char *ngx_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n);
u_char *ngx_cpystrn(u_char *dst, u_char *src, size_t n);
ngx_int_t ngx_strncasecmp(u_char *s1, u_char *s2, size_t n);
u_char *ngx_strstrn(u_char *s1, char *s2, size_t n);
u_char *ngx_strcasestrn(u_char *s1, char *s2, size_t n);
off_t ngx_atoof(u_char *line, size_t n);
ngx_int_t ngx_atoi(u_char *line, size_t n) ;
time_t ngx_atotm(u_char *line, size_t n);
#endif /* _NGX_STRING_H_INCLUDED_ */
