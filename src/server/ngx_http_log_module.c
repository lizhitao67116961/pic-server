/*
 *
 *  Created on: 2013-03-22
 *      Author: lizhitao
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_http.h"
#include "ngx_connection.h"
#include <stdio.h>
#include <fcntl.h>
typedef u_char *(*ngx_http_log_op_run_pt)(ngx_http_request_t *r, u_char *buf);

typedef size_t (*ngx_http_log_op_getlen_pt)(ngx_http_request_t *r);
typedef struct ngx_open_file_s ngx_open_file_t;
struct ngx_open_file_s {
	int fd;
	ngx_str_t name;

	u_char *buffer;
	u_char *pos;
	u_char *last;
};

typedef struct {
	ngx_open_file_t *file;
	time_t disk_full_time;
	time_t error_log_time;
} ngx_http_log_t;

typedef struct {
	ngx_str_t name;
	size_t len;
	ngx_http_log_op_run_pt run;
	ngx_http_log_op_getlen_pt getlen;
} ngx_http_log_var_t;

static void ngx_http_log_write(ngx_http_request_t *r, ngx_http_log_t *log, u_char *buf, size_t len);

static u_char *ngx_http_log_request_time(ngx_http_request_t *r, u_char *buf);
static u_char *ngx_http_log_status(ngx_http_request_t *r, u_char *buf);
static u_char *ngx_http_log_body_bytes_sent(ngx_http_request_t *r, u_char *buf);
static u_char *ngx_http_log_request_length(ngx_http_request_t *r, u_char *buf);
static u_char *ngx_http_log_time(ngx_http_request_t *r, u_char *buf);
static u_char *ngx_http_log_remote_addr(ngx_http_request_t *r, u_char *buf);
static u_char *ngx_http_log_request(ngx_http_request_t *r, u_char *buf);
static u_char *ngx_http_log_http_referer(ngx_http_request_t *r, u_char *buf);
static u_char *ngx_http_log_http_user_agent(ngx_http_request_t *r, u_char *buf);
static size_t ngx_http_log_remote_addr_getlen(ngx_http_request_t *r);
static size_t ngx_http_log_request_getlen(ngx_http_request_t *r);
static size_t ngx_http_log_http_referer_getlen(ngx_http_request_t *r);
static size_t ngx_http_log_http_user_agent_getlen(ngx_http_request_t *r);

#define NGX_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
#define NGX_SIZE_T_LEN NGX_ATOMIC_T_LEN
#define NGX_ACCESS_LOG_ERROR       (void *) -1

static ngx_http_log_var_t ngx_http_log_vars[] = { { ngx_string("remote_addr"), 0, ngx_http_log_remote_addr, ngx_http_log_remote_addr_getlen }, { ngx_string("time_local"),
		sizeof("28/Sep/1970:12:00:00 +0600") + 1, ngx_http_log_time, NULL }, { ngx_string("request"), 0, ngx_http_log_request, ngx_http_log_request_getlen }, {
		ngx_string("request_time"), NGX_SIZE_T_LEN, ngx_http_log_request_time, NULL }, { ngx_string("status"), 3, ngx_http_log_status, NULL }, { ngx_string("body_bytes_sent"),
		NGX_SIZE_T_LEN, ngx_http_log_body_bytes_sent, NULL }, { ngx_string("request_length"), NGX_SIZE_T_LEN, ngx_http_log_request_length, NULL }, { ngx_string("http_referer"), 0,
		ngx_http_log_http_referer, ngx_http_log_http_referer_getlen }, { ngx_string("http_user_agent"), 0, ngx_http_log_http_user_agent, ngx_http_log_http_user_agent_getlen }, {
		ngx_null_string, 0, NULL } };

static ngx_http_log_t access_log = { 0, 0, 0 };
ngx_int_t ngx_http_log_handler(ngx_http_request_t *r) {
	u_char *p;
	size_t len;
	ngx_uint_t i;
	ngx_open_file_t *file;

	len = 0;
	for (i = 0; ngx_http_log_vars[i].name.len > 0; i++) {
		if (ngx_http_log_vars[i].len == 0) {
			len += ngx_http_log_vars[i].getlen(r);

		} else {
			len += ngx_http_log_vars[i].len;
		}
	}

	len += 1;

	file = access_log.file;

	if (len > (size_t) (file->last - file->pos)) {

		ngx_http_log_write(r, &access_log, file->buffer, file->pos - file->buffer);

		file->pos = file->buffer;
	}

	if (len <= (size_t) (file->last - file->pos)) {

		p = file->pos;

		for (i = 0; ngx_http_log_vars[i].name.len > 0; i++) {
			p = ngx_http_log_vars[i].run(r, p);
			*p = ' ';
			++p;
		}

		*p++ = LF;

		file->pos = p;

	}

	return IMGZIP_OK;
}

static void ngx_http_log_write(ngx_http_request_t *r, ngx_http_log_t *log, u_char *buf, size_t len) {
	u_char *name;
	time_t now;
	ssize_t n;
	ngx_err_t err;

	name = log->file->name.data;
	n = write(log->file->fd, buf, len);

	if (n == (ssize_t) len) {
		return;
	}

	now = ngx_time();

	if (n == -1) {
		err = ngx_errno;

		if (err == ENOSPC) {
			log->disk_full_time = now;
		}

		if (now - log->error_log_time > 59) {
			log_print(LOG_LEVEL_ERROR, "write() to \"%s\" failed", name);
			log->error_log_time = now;
		}

		return;
	}

	if (now - log->error_log_time > 59) {
		log_print(LOG_LEVEL_ERROR, "write() to \"%s\" was incomplete: %z of %uz", name, n, len);
		log->error_log_time = now;
	}
}

static u_char *ngx_http_log_remote_addr(ngx_http_request_t *r, u_char *buf) {
	return ngx_cpymem(buf, r->connection->addr_text.data,
			r->connection->addr_text.len);
}
static u_char *ngx_http_log_request(ngx_http_request_t *r, u_char *buf) {
	*buf = '\"';
	++buf;
	buf = ngx_cpymem(buf, r->request_line.data, r->request_line.len);
	*buf = '\"';
	++buf;
	return buf;
}
static u_char *ngx_http_log_http_referer(ngx_http_request_t *r, u_char *buf) {
	if (r->headers_in.referer) {
		*buf = '\"';
		++buf;
		buf = ngx_cpymem(buf, r->headers_in.referer->value.data,
				r->headers_in.referer->value.len);
		*buf = '\"';
		++buf;
	} else {
		*buf = '-';
		++buf;
	}
	return buf;
}
static u_char *ngx_http_log_http_user_agent(ngx_http_request_t *r, u_char *buf) {
	if (r->headers_in.user_agent) {
		*buf = '\"';
		++buf;
		buf = ngx_cpymem(buf, r->headers_in.user_agent->value.data,
				r->headers_in.user_agent->value.len);
		*buf = '\"';
		++buf;
	} else {
		*buf = '-';
		++buf;
	}
	return buf;
}
static size_t ngx_http_log_remote_addr_getlen(ngx_http_request_t *r) {
	return r->connection->addr_text.len;
}
static size_t ngx_http_log_request_getlen(ngx_http_request_t *r) {
	return r->request_line.len + 2;
}
static size_t ngx_http_log_http_referer_getlen(ngx_http_request_t *r) {
	if (r->headers_in.referer) {
		return r->headers_in.referer->value.len + 2;
	}
	return 1;
}
static size_t ngx_http_log_http_user_agent_getlen(ngx_http_request_t *r) {
	if (r->headers_in.user_agent) {
		return r->headers_in.user_agent->value.len + 2;
	}
	return 1;
}

static u_char *
ngx_http_log_time(ngx_http_request_t *r, u_char *buf) {
	*buf = '[';
	++buf;
	buf = ngx_cpymem(buf, ngx_cached_http_log_time.data, ngx_cached_http_log_time.len);
	*buf = ']';
	++buf;
	return buf;
}

static u_char *
ngx_http_log_request_time(ngx_http_request_t *r, u_char *buf) {
	ngx_time_t *tp;
	ngx_int_t ms;

	tp = ngx_timeofday();

	ms = (ngx_int_t) ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
	ms = ngx_max(ms, 0);

	return ngx_sprintf(buf, "%T.%03M", ms / 1000, ms % 1000);
}

static u_char *
ngx_http_log_status(ngx_http_request_t *r, u_char *buf) {
	ngx_uint_t status;

	if (r->err_status) {
		status = r->err_status;

	} else if (r->headers_out.status) {
		status = r->headers_out.status;

	} else if (r->http_version == NGX_HTTP_VERSION_9) {
		*buf++ = '0';
		*buf++ = '0';
		*buf++ = '9';
		return buf;

	} else {
		status = 0;
	}

	return ngx_sprintf(buf, "%ui", status);
}

/*
 * although there is a real $body_bytes_sent variable,
 * this log operation code function is more optimized for logging
 */

static u_char *
ngx_http_log_body_bytes_sent(ngx_http_request_t *r, u_char *buf) {
	off_t length;

	length = r->headers_out.content_length_n;

	if (length > 0) {
		return ngx_sprintf(buf, "%O", length);
	}

	*buf = '0';

	return buf + 1;
}

static u_char *
ngx_http_log_request_length(ngx_http_request_t *r, u_char *buf) {
	return ngx_sprintf(buf, "%O", r->request_length);
}

ngx_uint_t ngx_http_access_log_init() {
	ngx_open_file_t *file;
	file = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_open_file_t));
	file->fd = open((char*) imgzip_server_conf.access_log_path.data, O_WRONLY | O_APPEND | O_CREAT, 0);
	if (file->fd == -1) {
		return IMGZIP_ERR;
	}
	file->buffer = ngx_pcalloc(ngx_cycle->pool, sizeof(char) * 8 * 1024);
	if (file->buffer == NULL) {
		return IMGZIP_ERR;
	}
	file->pos = file->buffer;
	file->last = file->buffer + sizeof(char) * 8 * 1024;
	access_log.file = file;
	return IMGZIP_OK;
}

