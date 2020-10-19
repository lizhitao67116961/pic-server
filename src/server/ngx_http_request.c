/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_http.h"
#include "ngx_connection.h"
#include "ngx_event_posted.h"
#include <arpa/inet.h>
static void ngx_http_init_request(ngx_event_t *ev);
static void ngx_http_process_request_line(ngx_event_t *rev);
static void ngx_http_process_request_headers(ngx_event_t *rev);
static ssize_t ngx_http_read_request_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_alloc_large_header_buffer(ngx_http_request_t *r, ngx_uint_t request_line);

static ngx_int_t ngx_http_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_unique_header_line(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_host(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_connection(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_user_agent(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_cookie(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_process_request_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_process_request(ngx_http_request_t *r);
static ssize_t ngx_http_validate_host(ngx_http_request_t *r, u_char **host, size_t len, ngx_uint_t alloc);

static void ngx_http_request_handler(ngx_event_t *ev);
static void ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc);
static void ngx_http_finalize_connection(ngx_http_request_t *r);

static void ngx_http_set_keepalive(ngx_http_request_t *r);
static void ngx_http_keepalive_handler(ngx_event_t *ev);
static void ngx_http_close_request(ngx_http_request_t *r, ngx_int_t error);
static void ngx_http_free_request(ngx_http_request_t *r, ngx_int_t error);
static void ngx_http_close_connection(ngx_connection_t *c);
static ngx_int_t ngx_http_set_write_handler(ngx_http_request_t *r);
static void ngx_http_writer(ngx_http_request_t *r);
static char *ngx_http_client_errors[] = {

/* NGX_HTTP_PARSE_INVALID_METHOD */
"client sent invalid method",

/* NGX_HTTP_PARSE_INVALID_REQUEST */
"client sent invalid request",

/* NGX_HTTP_PARSE_INVALID_09_METHOD */
"client sent invalid method in HTTP/0.9 request" };

ngx_http_header_t ngx_http_headers_in[] = { { ngx_string("Host"), offsetof(ngx_http_headers_in_t, host), ngx_http_process_host },

{ ngx_string("Connection"), offsetof(ngx_http_headers_in_t, connection), ngx_http_process_connection },

{ ngx_string("If-Modified-Since"), offsetof(ngx_http_headers_in_t, if_modified_since), ngx_http_process_unique_header_line },

{ ngx_string("If-Unmodified-Since"), offsetof(ngx_http_headers_in_t, if_unmodified_since), ngx_http_process_unique_header_line },

{ ngx_string("User-Agent"), offsetof(ngx_http_headers_in_t, user_agent), ngx_http_process_user_agent },

{ ngx_string("Referer"), offsetof(ngx_http_headers_in_t, referer), ngx_http_process_header_line },

{ ngx_string("Content-Length"), offsetof(ngx_http_headers_in_t, content_length), ngx_http_process_unique_header_line },

{ ngx_string("Content-Type"), offsetof(ngx_http_headers_in_t, content_type), ngx_http_process_header_line },

{ ngx_string("Range"), offsetof(ngx_http_headers_in_t, range), ngx_http_process_header_line },

{ ngx_string("If-Range"), offsetof(ngx_http_headers_in_t, if_range), ngx_http_process_unique_header_line },

{ ngx_string("Transfer-Encoding"), offsetof(ngx_http_headers_in_t, transfer_encoding), ngx_http_process_header_line },

{ ngx_string("Expect"), offsetof(ngx_http_headers_in_t, expect), ngx_http_process_unique_header_line },

{ ngx_string("Authorization"), offsetof(ngx_http_headers_in_t, authorization), ngx_http_process_unique_header_line },

{ ngx_string("Keep-Alive"), offsetof(ngx_http_headers_in_t, keep_alive), ngx_http_process_header_line },

{ ngx_string("X-Forwarded-For"), offsetof(ngx_http_headers_in_t, x_forwarded_for), ngx_http_process_header_line },

{ ngx_string("X-Real-IP"), offsetof(ngx_http_headers_in_t, x_real_ip), ngx_http_process_header_line },

{ ngx_string("Accept"), offsetof(ngx_http_headers_in_t, accept), ngx_http_process_header_line },

{ ngx_string("Accept-Language"), offsetof(ngx_http_headers_in_t, accept_language), ngx_http_process_header_line },

{ ngx_string("Depth"), offsetof(ngx_http_headers_in_t, depth), ngx_http_process_header_line },

{ ngx_string("Destination"), offsetof(ngx_http_headers_in_t, destination), ngx_http_process_header_line },

{ ngx_string("Overwrite"), offsetof(ngx_http_headers_in_t, overwrite), ngx_http_process_header_line },

{ ngx_string("File-Name"), offsetof(ngx_http_headers_in_t, file_name), ngx_http_process_header_line },
{ ngx_string("Pic-Path"), offsetof(ngx_http_headers_in_t, pic_path), ngx_http_process_header_line },
{ ngx_string("File-Extensions"), offsetof(ngx_http_headers_in_t, file_extensions), ngx_http_process_header_line },
{ ngx_string("IsMerge"), offsetof(ngx_http_headers_in_t, ismerge), ngx_http_process_header_line },
{ ngx_string("Pic-Size"), offsetof(ngx_http_headers_in_t, pic_size), ngx_http_process_header_line },
{ ngx_string("Pic-Bulk"), offsetof(ngx_http_headers_in_t, pic_bulk), ngx_http_process_header_line },
{ ngx_string("Pic-dpi"), offsetof(ngx_http_headers_in_t, pic_dpi), ngx_http_process_header_line },
{ ngx_string("Pic-IsAddWaterPic"), offsetof(ngx_http_headers_in_t, pic_isaddwaterpic), ngx_http_process_header_line },
{ ngx_string("Pic-Cut"), offsetof(ngx_http_headers_in_t, pic_cut), ngx_http_process_header_line },
{ ngx_string("Domain"), offsetof(ngx_http_headers_in_t, domain), ngx_http_process_header_line },

{ ngx_string("Cookie"), 0, ngx_http_process_cookie },

{ ngx_null_string, 0, NULL } };

void ngx_http_init_connection(ngx_connection_t *c) {
	ngx_event_t *rev;

	rev = c->read;
	rev->handler = ngx_http_init_request;
	c->write->handler = ngx_http_empty_handler;

	if (rev->ready) {

		ngx_http_init_request(rev);
		return;

	}

	ngx_event_add_timer(rev, c->listening->post_accept_timeout);

	if (ngx_handle_read_event(rev) != IMGZIP_OK) {

		ngx_http_close_connection(c);
		return;
	}
}

static void ngx_http_init_request(ngx_event_t *rev) {
	ngx_time_t *tp;
	ngx_connection_t *c;
	ngx_http_request_t *r;
	ngx_http_connection_t *hc;

	c = rev->data;

	if (rev->timedout) {
		log_print(LOG_LEVEL_ERROR, "client timed out");

		ngx_http_close_connection(c);
		return;
	}

	hc = c->data;

	if (hc == NULL) {
		hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t));
		if (hc == NULL) {
			ngx_http_close_connection(c);
			return;
		}
	}

	r = hc->request;

	if (r) {
		ngx_memzero(r, sizeof(ngx_http_request_t));

		r->pipeline = hc->pipeline;

		if (hc->nbusy) {
			r->header_in = hc->busy[0];
		}

	} else {
		r = ngx_pcalloc(c->pool, sizeof(ngx_http_request_t));
		if (r == NULL) {
			ngx_http_close_connection(c);
			return;
		}

		hc->request = r;
	}

	c->data = r;
	r->http_connection = hc;

	c->sent = 0;

	/* find the server configuration for the address:port */

	r->connection = c;

	/* the default server configuration for the address:port */

	rev->handler = ngx_http_process_request_line;
	r->read_event_handler = ngx_http_block_reading;

	if (c->buffer == NULL) {
		c->buffer = ngx_create_temp_buf(c->pool, CLIENT_HEADER_BUFFER_SIZE);
		if (c->buffer == NULL) {
			ngx_http_close_connection(c);
			return;
		}
	}

	if (r->header_in == NULL) {
		r->header_in = c->buffer;
	}

	r->pool = ngx_create_pool(REQUEST_POOL_SIZE);
	if (r->pool == NULL) {
		ngx_http_close_connection(c);
		return;
	}

	if (ngx_list_init(&r->headers_out.headers, r->pool, 20, sizeof(ngx_table_elt_t)) != IMGZIP_OK)
	{
		ngx_destroy_pool(r->pool);
		ngx_http_close_connection(c);
		return;
	}

	r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
	if (r->ctx == NULL) {
		ngx_destroy_pool(r->pool);
		ngx_http_close_connection(c);
		return;
	}

	c->single_connection = 1;
	c->destroyed = 0;

	r->count = 1;

	tp = ngx_timeofday();
	r->start_sec = tp->sec;
	r->start_msec = tp->msec;

	r->method = NGX_HTTP_UNKNOWN;

	r->headers_in.content_length_n = -1;
	r->headers_in.keep_alive_n = -1;
	r->headers_out.content_length_n = -1;
	r->headers_out.last_modified_time = -1;

	r->http_state = NGX_HTTP_READING_REQUEST_STATE;

	rev->handler(rev);
}

static void ngx_http_process_request_line(ngx_event_t *rev) {
	u_char *host;
	ssize_t n;
	ngx_int_t rc, rv;
	ngx_connection_t *c;
	ngx_http_request_t *r;

	c = rev->data;
	r = c->data;

	log_print(LOG_LEVEL_DEBUG, "http process request line");

	if (rev->timedout) {
		log_print(LOG_LEVEL_ERROR, "client timed out");
		c->timedout = 1;
		ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
		return;
	}

	rc = IMGZIP_AGAIN;

	for (;;) {

		if (rc == IMGZIP_AGAIN) {
			n = ngx_http_read_request_header(r);

			if (n == IMGZIP_AGAIN || n == IMGZIP_ERR) {
				return;
			}
		}

		rc = ngx_http_parse_request_line(r, r->header_in);

		if (rc == IMGZIP_OK) {

			/* the request line has been parsed successfully */

			r->request_line.len = r->request_end - r->request_start;
			r->request_line.data = r->request_start;

			if (r->args_start) {
				r->uri.len = r->args_start - 1 - r->uri_start;
			} else {
				r->uri.len = r->uri_end - r->uri_start;
			}

			if (r->complex_uri || r->quoted_uri) {

				r->uri.data = ngx_pnalloc(r->pool, r->uri.len + 1);
				if (r->uri.data == NULL) {
					ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}

				rc = ngx_http_parse_complex_uri(r, 1);

				if (rc == NGX_HTTP_PARSE_INVALID_REQUEST) {
					log_print(LOG_LEVEL_ERROR, "client sent invalid request");
					ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
					return;
				}

			} else {
				r->uri.data = r->uri_start;
			}

			r->unparsed_uri.len = r->uri_end - r->uri_start;
			r->unparsed_uri.data = r->uri_start;

			r->method_name.len = r->method_end - r->request_start + 1;
			r->method_name.data = r->request_line.data;

			if (r->http_protocol.data) {
				r->http_protocol.len = r->request_end - r->http_protocol.data;
			}

			if (r->uri_ext) {
				if (r->args_start) {
					r->exten.len = r->args_start - 1 - r->uri_ext;
				} else {
					r->exten.len = r->uri_end - r->uri_ext;
				}

				r->exten.data = r->uri_ext;
			}

			if (r->args_start && r->uri_end > r->args_start) {
				r->args.len = r->uri_end - r->args_start;
				r->args.data = r->args_start;
			}

			if (r->host_start && r->host_end) {

				host = r->host_start;
				n = ngx_http_validate_host(r, &host, r->host_end - r->host_start, 0);

				if (n == 0) {
					log_print(LOG_LEVEL_ERROR, "client sent invalid host in request line");
					ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
					return;
				}

				if (n < 0) {
					ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}

				r->headers_in.server.len = n;
				r->headers_in.server.data = host;
			}

			if (r->http_version < NGX_HTTP_VERSION_10) {

				rc = ngx_http_process_request(r);
				if (rc == IMGZIP_AGAIN)
					return ;
			}

			if (ngx_list_init(&r->headers_in.headers, r->pool, 20, sizeof(ngx_table_elt_t)) != IMGZIP_OK)
			{
				ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			if (ngx_array_init(&r->headers_in.cookies, r->pool, 2, sizeof(ngx_table_elt_t *)) != IMGZIP_OK)
			{
				ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			rev->handler = ngx_http_process_request_headers;
			ngx_http_process_request_headers(rev);

			return;
		}

		if (rc != IMGZIP_AGAIN) {

			/* there was error while a request line parsing */

			log_print(LOG_LEVEL_ERROR, ngx_http_client_errors[rc - NGX_HTTP_CLIENT_ERROR]);
			ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
			return;
		}

		/* IMGZIP_AGAIN: a request line parsing is still incomplete */

		if (r->header_in->pos == r->header_in->end) {

			rv = ngx_http_alloc_large_header_buffer(r, 1);

			if (rv == IMGZIP_ERR) {
				ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			if (rv == IMGZIP_DECLINED) {
				r->request_line.len = r->header_in->end - r->request_start;
				r->request_line.data = r->request_start;

				log_print(LOG_LEVEL_ERROR, "client sent too long URI");
				ngx_http_finalize_request(r, NGX_HTTP_REQUEST_URI_TOO_LARGE);
				return;
			}
		}
	}
}

static void ngx_http_process_request_headers(ngx_event_t *rev) {
	u_char *p;
	size_t len;
	ssize_t n;
	ngx_int_t rc, rv;
	ngx_table_elt_t *h;
	ngx_connection_t *c;
	ngx_http_header_t *hh;
	ngx_http_request_t *r;

	c = rev->data;
	r = c->data;

	log_print(LOG_LEVEL_DEBUG, "http process request header line");

	if (rev->timedout) {
		log_print(LOG_LEVEL_ERROR, "client timed out");
		c->timedout = 1;
		ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
		return;
	}

	rc = IMGZIP_AGAIN;

	for (;;) {

		if (rc == IMGZIP_AGAIN) {

			if (r->header_in->pos == r->header_in->end) {

				rv = ngx_http_alloc_large_header_buffer(r, 0);

				if (rv == IMGZIP_ERR) {
					ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}

				if (rv == IMGZIP_DECLINED) {
					p = r->header_name_start;

					r->lingering_close = 1;

					if (p == NULL) {
						log_print(LOG_LEVEL_ERROR, "client sent too large request");
						ngx_http_finalize_request(r, NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
						return;
					}

					len = r->header_in->end - p;

					if (len > 2048 - 300) {
						len = 2048 - 300;
						p[len++] = '.';
						p[len++] = '.';
						p[len++] = '.';
					}

					log_print(LOG_LEVEL_ERROR, "client sent too long header line: \"%*s\"", len, r->header_name_start);

					ngx_http_finalize_request(r, NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
					return;
				}
			}

			n = ngx_http_read_request_header(r);

			if (n == IMGZIP_AGAIN || n == IMGZIP_ERR) {
				return;
			}
		}

		rc = ngx_http_parse_header_line(r, r->header_in, 0);

		if (rc == IMGZIP_OK) {

			if (r->invalid_header) {

				/* there was error while a header line parsing */

				log_print(LOG_LEVEL_ERROR, "client sent invalid header line: \"%*s\"", r->header_end - r->header_name_start, r->header_name_start);
				continue;
			}

			/* a header line has been parsed successfully */

			h = ngx_list_push(&r->headers_in.headers);
			if (h == NULL) {
				ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			h->hash = r->header_hash;

			h->key.len = r->header_name_end - r->header_name_start;
			h->key.data = r->header_name_start;
			h->key.data[h->key.len] = '\0';

			h->value.len = r->header_end - r->header_start;
			h->value.data = r->header_start;
			h->value.data[h->value.len] = '\0';

			h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
			if (h->lowcase_key == NULL) {
				ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			if (h->key.len == r->lowcase_index) {
				memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

			} else {
				ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
			}

			hh = ngx_hash_find(&headers_in_hash, h->hash, h->lowcase_key, h->key.len);

			if (hh && hh->handler(r, h, hh->offset) != IMGZIP_OK) {
				return;
			}

			log_print(LOG_LEVEL_DEBUG, "http header: \"%V: %V\"", &h->key, &h->value);

			continue;
		}

		if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

			/* a whole header has been parsed successfully */

			log_print(LOG_LEVEL_DEBUG, "http header done");

			r->request_length += r->header_in->pos - r->header_in->start;

			r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

			rc = ngx_http_process_request_header(r);

			if (rc != IMGZIP_OK) {
				return;
			}

			ngx_http_process_request(r);

			return;
		}

		if (rc == IMGZIP_AGAIN) {

			/* a header line parsing is still not complete */

			continue;
		}

		/* rc == NGX_HTTP_PARSE_INVALID_HEADER: "\r" is not followed by "\n" */

		log_print(LOG_LEVEL_ERROR, "client sent invalid header line: \"%*s\\r...\"", r->header_end - r->header_name_start, r->header_name_start);
		ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
		return;
	}
}

static ssize_t ngx_http_read_request_header(ngx_http_request_t *r) {
	ssize_t n;
	ngx_event_t *rev;
	ngx_connection_t *c;

	c = r->connection;
	rev = c->read;

	n = r->header_in->last - r->header_in->pos;

	if (n > 0) {
		return n;
	}

	if (rev->ready) { //读取socket数据
		n = c->recv(c, r->header_in->last, r->header_in->end - r->header_in->last);
	} else {
		n = IMGZIP_AGAIN;
	}

	if (n == IMGZIP_AGAIN) {
		if (!rev->timer_set) {
			ngx_event_add_timer(rev, CLIENT_HEADER_TIMEOUT);
		}

		if (ngx_handle_read_event(rev) != IMGZIP_OK) {
			ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return IMGZIP_ERR;
		}

		return IMGZIP_AGAIN;
	}

	if (n == 0) {
		log_print(LOG_LEVEL_INFO, "client closed prematurely connection");
	}

	if (n == 0 || n == IMGZIP_ERR) {
		c->error = 1;

		ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
		return IMGZIP_ERR;
	}

	r->header_in->last += n;

	return n;
}

static ngx_int_t ngx_http_alloc_large_header_buffer(ngx_http_request_t *r, ngx_uint_t request_line) {
	u_char *old, *new;
	ngx_buf_t *b;
	ngx_http_connection_t *hc;

	if (request_line && r->state == 0) {

		/* the client fills up the buffer with "\r\n" */

		r->request_length += r->header_in->end - r->header_in->start;

		r->header_in->pos = r->header_in->start;
		r->header_in->last = r->header_in->start;

		return IMGZIP_OK;
	}

	old = request_line ? r->request_start : r->header_name_start;

	if (r->state != 0 && (size_t) (r->header_in->pos - old) >= LARGE_CLIENT_HEADER_BUFFERS_SIZE) {
		return IMGZIP_DECLINED;
	}

	hc = r->http_connection;

	if (hc->nfree) {
		b = hc->free[--hc->nfree];

	} else if (hc->nbusy < LARGE_CLIENT_HEADER_BUFFERS_NUM) {

		if (hc->busy == NULL) {
			hc->busy = ngx_palloc(r->connection->pool, LARGE_CLIENT_HEADER_BUFFERS_NUM * sizeof(ngx_buf_t *));
			if (hc->busy == NULL) {
				return IMGZIP_ERR;
			}
		}

		b = ngx_create_temp_buf(r->connection->pool, LARGE_CLIENT_HEADER_BUFFERS_SIZE);
		if (b == NULL) {
			return IMGZIP_ERR;
		}

	} else {
		return IMGZIP_DECLINED;
	}

	hc->busy[hc->nbusy++] = b;

	if (r->state == 0) {
		/*
		 * r->state == 0 means that a header line was parsed successfully
		 * and we do not need to copy incomplete header line and
		 * to relocate the parser header pointers
		 */

		r->request_length += r->header_in->end - r->header_in->start;

		r->header_in = b;

		return IMGZIP_OK;
	}

	r->request_length += old - r->header_in->start;

	new = b->start;

	memcpy(new, old, r->header_in->pos - old);

	b->pos = new + (r->header_in->pos - old);
	b->last = new + (r->header_in->pos - old);

	if (request_line) {
		r->request_start = new;

		if (r->request_end) {
			r->request_end = new + (r->request_end - old);
		}

		r->method_end = new + (r->method_end - old);

		r->uri_start = new + (r->uri_start - old);
		r->uri_end = new + (r->uri_end - old);

		if (r->schema_start) {
			r->schema_start = new + (r->schema_start - old);
			r->schema_end = new + (r->schema_end - old);
		}

		if (r->host_start) {
			r->host_start = new + (r->host_start - old);
			if (r->host_end) {
				r->host_end = new + (r->host_end - old);
			}
		}

		if (r->port_start) {
			r->port_start = new + (r->port_start - old);
			r->port_end = new + (r->port_end - old);
		}

		if (r->uri_ext) {
			r->uri_ext = new + (r->uri_ext - old);
		}

		if (r->args_start) {
			r->args_start = new + (r->args_start - old);
		}

		if (r->http_protocol.data) {
			r->http_protocol.data = new + (r->http_protocol.data - old);
		}

	} else {
		r->header_name_start = new;
		r->header_name_end = new + (r->header_name_end - old);
		r->header_start = new + (r->header_start - old);
		r->header_end = new + (r->header_end - old);
	}

	r->header_in = b;

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t **ph;

	ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);

	if (*ph == NULL) {
		*ph = h;
	}

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_process_unique_header_line(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t **ph;

	ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);

	if (*ph == NULL) {
		*ph = h;
		return IMGZIP_OK;
	}

	log_print(LOG_LEVEL_ERROR, "client sent duplicate header line: \"%V: %V\", "
			"previous value: \"%V: %V\"", &h->key, &h->value, &(*ph)->key, &(*ph)->value);

	ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);

	return IMGZIP_ERR;
}

static ngx_int_t ngx_http_process_host(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	u_char *host;
	ssize_t len;

	if (r->headers_in.host == NULL) {
		r->headers_in.host = h;
	}

	host = h->value.data;
	len = ngx_http_validate_host(r, &host, h->value.len, 0);

	if (len == 0) {
		log_print(LOG_LEVEL_ERROR, "client sent invalid host header");
		ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
		return IMGZIP_ERR;
	}

	if (len < 0) {
		ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return IMGZIP_ERR;
	}

	if (r->headers_in.server.len) {
		return IMGZIP_OK;
	}

	r->headers_in.server.len = len;
	r->headers_in.server.data = host;

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_process_connection(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	if (ngx_strcasestrn(h->value.data, "close", 5 - 1)) {
		r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

	} else if (ngx_strcasestrn(h->value.data, "keep-alive", 10 - 1)) {
		r->headers_in.connection_type = NGX_HTTP_CONNECTION_KEEP_ALIVE;
	}

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_process_user_agent(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	u_char *user_agent, *msie;

	if (r->headers_in.user_agent) {
		return IMGZIP_OK;
	}

	r->headers_in.user_agent = h;

	/* check some widespread browsers while the header is in CPU cache */

	user_agent = h->value.data;

	msie = ngx_strstrn(user_agent, "MSIE ", 5 - 1);

	if (msie && msie + 7 < user_agent + h->value.len) {

		r->headers_in.msie = 1;

		if (msie[6] == '.') {

			switch (msie[5]) {
			case '4':
			case '5':
				r->headers_in.msie6 = 1;
				break;
			case '6':
				if (ngx_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
					r->headers_in.msie6 = 1;
				}
				break;
			}
		}

	}

	if (ngx_strstrn(user_agent, "Opera", 5 - 1)) {
		r->headers_in.opera = 1;
		r->headers_in.msie = 0;
		r->headers_in.msie6 = 0;
	}

	if (!r->headers_in.msie && !r->headers_in.opera) {

		if (ngx_strstrn(user_agent, "Gecko/", 6 - 1)) {
			r->headers_in.gecko = 1;

		} else if (ngx_strstrn(user_agent, "Chrome/", 7 - 1)) {
			r->headers_in.chrome = 1;

		} else if (ngx_strstrn(user_agent, "Safari/", 7 - 1)) {
			r->headers_in.safari = 1;

		} else if (ngx_strstrn(user_agent, "Konqueror", 9 - 1)) {
			r->headers_in.konqueror = 1;
		}
	}

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_process_cookie(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t **cookie;

	cookie = ngx_array_push(&r->headers_in.cookies);
	if (cookie) {
		*cookie = h;
		return IMGZIP_OK;
	}

	ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);

	return IMGZIP_ERR;
}

static ngx_int_t ngx_http_process_request_header(ngx_http_request_t *r) {

	if (r->headers_in.host == NULL && r->http_version > NGX_HTTP_VERSION_10) {
		log_print(LOG_LEVEL_INFO, "client sent HTTP/1.1 request without \"Host\" header");
		ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
		return IMGZIP_ERR;
	}

	if (r->headers_in.content_length) {
		r->headers_in.content_length_n = ngx_atoof(r->headers_in.content_length->value.data, r->headers_in.content_length->value.len);

		if (r->headers_in.content_length_n == IMGZIP_ERR) {
			log_print(LOG_LEVEL_INFO, "client sent invalid \"Content-Length\" header");
			ngx_http_finalize_request(r, NGX_HTTP_LENGTH_REQUIRED);
			return IMGZIP_ERR;
		}
	}

	if ((r->method & NGX_HTTP_PUT) && r->headers_in.content_length_n == -1) {
		log_print(LOG_LEVEL_INFO, "client sent %V method without \"Content-Length\" header", &r->method_name);
		ngx_http_finalize_request(r, NGX_HTTP_LENGTH_REQUIRED);
		return IMGZIP_ERR;
	}

	if (r->method & NGX_HTTP_TRACE) {
		log_print(LOG_LEVEL_INFO, "client sent TRACE method");
		ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
		return IMGZIP_ERR;
	}

	if (r->headers_in.transfer_encoding && ngx_strcasestrn(r->headers_in.transfer_encoding->value.data, "chunked", 7 - 1)) {
		log_print(LOG_LEVEL_INFO, "client sent \"Transfer-Encoding: chunked\" header");
		ngx_http_finalize_request(r, NGX_HTTP_LENGTH_REQUIRED);
		return IMGZIP_ERR;
	}

	if (r->headers_in.connection_type == NGX_HTTP_CONNECTION_KEEP_ALIVE) {
		if (r->headers_in.keep_alive) {
			r->headers_in.keep_alive_n = ngx_atotm(r->headers_in.keep_alive->value.data, r->headers_in.keep_alive->value.len);
		}
	}

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_process_request(ngx_http_request_t *r) {
	ngx_connection_t *c;

	c = r->connection;

	if (r->plain_http) {
		log_print(LOG_LEVEL_INFO, "client sent plain HTTP request to HTTPS port");
		ngx_http_finalize_request(r, NGX_HTTP_TO_HTTPS);
		return IMGZIP_ERR;
	}

	if (c->read->timer_set) {
		ngx_event_del_timer(c->read);
	}

	c->read->handler = ngx_http_request_handler;
	c->write->handler = ngx_http_request_handler;
	r->read_event_handler = ngx_http_block_reading;

	ngx_http_handler(r);

	ngx_http_run_posted_requests(c);
	return IMGZIP_OK;
}

static ssize_t ngx_http_validate_host(ngx_http_request_t *r, u_char **host, size_t len, ngx_uint_t alloc) {
	u_char *h, ch;
	size_t i, last;
	ngx_uint_t dot;

	last = len;
	h = *host;
	dot = 0;

	for (i = 0; i < len; i++) {
		ch = h[i];

		if (ch == '.') {
			if (dot) {
				return 0;
			}

			dot = 1;
			continue;
		}

		dot = 0;

		if (ch == ':') {
			last = i;
			continue;
		}

		if (ngx_path_separator(ch) || ch == '\0') {
			return 0;
		}

		if (ch >= 'A' || ch < 'Z') {
			alloc = 1;
		}
	}

	if (dot) {
		last--;
	}

	if (alloc) {
		*host = ngx_pnalloc(r->pool, last);
		if (*host == NULL) {
			return -1;
		}

		ngx_strlow(*host, h, last);
	}

	return last;
}

static void ngx_http_request_handler(ngx_event_t *ev) {
	ngx_connection_t *c;
	ngx_http_request_t *r;

	c = ev->data;
	r = c->data;

	if (ev->write) {
		r->write_event_handler(r);

	} else {
		r->read_event_handler(r);
	}

	ngx_http_run_posted_requests(c);
}

void ngx_http_run_posted_requests(ngx_connection_t *c) {
	ngx_http_request_t *r;
	ngx_http_posted_request_t *pr;

	for (;;) {

		if (c->destroyed) {
			return;
		}

		r = c->data;
		pr = r->posted_requests;

		if (pr == NULL) {
			return;
		}

		r->posted_requests = pr->next;

		r = pr->request;

		log_print(LOG_LEVEL_DEBUG, "http posted request: \"%V?%V\"", &r->uri, &r->args);

		r->write_event_handler(r);
	}
}

ngx_int_t ngx_http_post_request(ngx_http_request_t *r, ngx_http_posted_request_t *pr) {
	ngx_http_posted_request_t **p;

	if (pr == NULL) {
		pr = ngx_palloc(r->pool, sizeof(ngx_http_posted_request_t));
		if (pr == NULL) {
			return IMGZIP_ERR;
		}
	}

	pr->request = r;
	pr->next = NULL;

	for (p = &r->posted_requests; *p; p = &(*p)->next) { /* void */
	}

	*p = pr;

	return IMGZIP_OK;
}

void ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
	ngx_connection_t *c;

	c = r->connection;
	log_print(LOG_LEVEL_DEBUG, "close %s,port:%d\n", inet_ntoa(((struct sockaddr_in*) c->sockaddr)->sin_addr), ntohs(((struct sockaddr_in*) c->sockaddr)->sin_port));

	r->content_handler = NULL;
	log_print(LOG_LEVEL_DEBUG, "http finalize request: %d, \"%V?%V\" a:%d, c:%d", rc, &r->uri, &r->args, r == c->data, r->count);

	if (rc == IMGZIP_DONE) {
		ngx_http_finalize_connection(r);
		return;
	}

	if (rc == IMGZIP_OK && r->filter_finalize) {
		c->error = 1;
		return;
	}

	if (rc == IMGZIP_ERR || rc == NGX_HTTP_REQUEST_TIME_OUT || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST || c->error) {

		ngx_http_terminate_request(r, rc);
		return;
	}

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE || rc == NGX_HTTP_CREATED || rc == NGX_HTTP_NO_CONTENT)	{
		if (rc == NGX_HTTP_CLOSE) {
			ngx_http_terminate_request(r, rc);
			return;
		}

		if (c->read->timer_set) {
			ngx_event_del_timer(c->read);
		}

		if (c->write->timer_set) {
			ngx_event_del_timer(c->write);
		}

		c->read->handler = ngx_http_request_handler;
		c->write->handler = ngx_http_request_handler;

		ngx_http_finalize_request(r, ngx_http_special_response_handler(r, rc));
		return;
}
	if (c->buffered) {

		if (ngx_http_set_write_handler(r) != IMGZIP_OK) {
			ngx_http_terminate_request(r, 0);
		}

		return;
	}
	if (r != c->data) {
		log_print(LOG_LEVEL_ERROR, "http finalize non-active request: \"%V?%V\"", &r->uri, &r->args);
		return;
	}

	r->done = 1;
	r->write_event_handler = ngx_http_request_empty_handler;

	if (c->read->timer_set) {
		ngx_event_del_timer(c->read);
	}

	if (c->write->timer_set) {
		ngx_event_del_timer(c->write);
	}

	if (c->read->eof) {
		ngx_http_close_request(r, 0);
		return;
	}

	ngx_http_finalize_connection(r);
}

static void ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc) {
	ngx_http_cleanup_t *cln;
	ngx_http_request_t *mr;

	mr = r;

	log_print(LOG_LEVEL_DEBUG, "http terminate request count:%d", mr->count);

	if (rc > 0 && (mr->headers_out.status == 0 || mr->connection->sent == 0)) {
		mr->headers_out.status = rc;
	}

	cln = mr->cleanup;
	mr->cleanup = NULL;

	while (cln) {
		if (cln->handler) {
			cln->handler(cln->data);
		}

		cln = cln->next;
	}

	log_print(LOG_LEVEL_DEBUG, "http terminate cleanup count:%d ", mr->count);

	ngx_http_close_request(mr, rc);
}


static void ngx_http_finalize_connection(ngx_http_request_t *r) {

	if (r->count != 1) {

		if (r->discard_body) {
			r->read_event_handler = ngx_http_discarded_request_body_handler;
			ngx_event_add_timer(r->connection->read, LINGERING_TIMEOUT);

			if (r->lingering_time == 0) {
				r->lingering_time = ngx_time() + (time_t) (LINGERING_TIME / 1000);
			}
		}

		ngx_http_close_request(r, 0);
		return;
	}

	if (!ngx_terminate && !ngx_exiting && r->keepalive && KEEPALIVE_TIMEOUT > 0) {
		ngx_http_set_keepalive(r);
		return;
	}

	ngx_http_close_request(r, 0);
}

void ngx_http_block_reading(ngx_http_request_t *r) {

	/* aio does not call this handler */

}

void ngx_http_test_reading(ngx_http_request_t *r) {
	int n;
	char buf[1];
	ngx_err_t err;
	ngx_event_t *rev;
	ngx_connection_t *c;

	c = r->connection;
	rev = c->read;

	log_print(LOG_LEVEL_DEBUG, "http test reading");

	n = recv(c->fd, buf, 1, MSG_PEEK);

	if (n == 0) {
		rev->eof = 1;
		c->error = 1;
		err = 0;

		goto closed;

	} else if (n == -1) {
		err = errno;

		if (err != EAGAIN) {
			rev->eof = 1;
			c->error = 1;

			goto closed;
		}
	}

	/* aio does not call this handler */

	return;

	closed:

	if (err) {
		rev->error = 1;
	}

	log_print(LOG_LEVEL_ERROR, "client closed prematurely connection");

	ngx_http_finalize_request(r, 0);
}

static void ngx_http_set_keepalive(ngx_http_request_t *r) {
	ngx_int_t i;
	ngx_buf_t *b, *f;
	ngx_event_t *rev, *wev;
	ngx_connection_t *c;
	ngx_http_connection_t *hc;

	c = r->connection;
	rev = c->read;

	log_print(LOG_LEVEL_DEBUG, "set http keepalive handler");

	if (r->discard_body) {
		r->write_event_handler = ngx_http_request_empty_handler;
		r->lingering_time = ngx_time() + (time_t) (LINGERING_TIME / 1000);
		ngx_event_add_timer(rev, LINGERING_TIMEOUT);
		return;
	}

	hc = r->http_connection;
	b = r->header_in;

	if (b->pos < b->last) {

		/* the pipelined request */

		if (b != c->buffer) {

			/*
			 * If the large header buffers were allocated while the previous
			 * request processing then we do not use c->buffer for
			 * the pipelined request (see ngx_http_init_request()).
			 *
			 * Now we would move the large header buffers to the free list.
			 */

			if (hc->free == NULL) {
				hc->free = ngx_palloc(c->pool, LARGE_CLIENT_HEADER_BUFFERS_NUM * sizeof(ngx_buf_t *));

				if (hc->free == NULL) {
					ngx_http_close_request(r, 0);
					return;
				}
			}

			for (i = 0; i < hc->nbusy - 1; i++) {
				f = hc->busy[i];
				hc->free[hc->nfree++] = f;
				f->pos = f->start;
				f->last = f->start;
			}

			hc->busy[0] = b;
			hc->nbusy = 1;
		}
	}

	r->keepalive = 0;

	ngx_http_free_request(r, 0);

	c->data = hc;

	ngx_event_add_timer(rev, KEEPALIVE_TIMEOUT);

	if (ngx_handle_read_event(rev) != IMGZIP_OK) {
		ngx_http_close_connection(c);
		return;
	}

	wev = c->write;
	wev->handler = ngx_http_empty_handler;

	if (b->pos < b->last) {

		log_print(LOG_LEVEL_DEBUG, "pipelined request");

		hc->pipeline = 1;

		rev->handler = ngx_http_init_request;
		ngx_locked_post_event(rev, &ngx_posted_events);
		return;
	}

	hc->pipeline = 0;

	/*
	 * To keep a memory footprint as small as possible for an idle
	 * keepalive connection we try to free the ngx_http_request_t and
	 * c->buffer's memory if they were allocated outside the c->pool.
	 * The large header buffers are always allocated outside the c->pool and
	 * are freed too.
	 */

	if (ngx_pfree(c->pool, r) == IMGZIP_OK) {
		hc->request = NULL;
	}

	b = c->buffer;

	if (ngx_pfree(c->pool, b->start) == IMGZIP_OK) {

		/*
		 * the special note for ngx_http_keepalive_handler() that
		 * c->buffer's memory was freed
		 */

		b->pos = NULL;

	} else {
		b->pos = b->start;
		b->last = b->start;
	}

	log_print(LOG_LEVEL_DEBUG, "hc free: %p %d", hc->free, hc->nfree);

	if (hc->free) {
		for (i = 0; i < hc->nfree; i++) {
			ngx_pfree(c->pool, hc->free[i]->start);
			hc->free[i] = NULL;
		}

		hc->nfree = 0;
	}

	log_print(LOG_LEVEL_DEBUG, "hc busy: %p %d", hc->busy, hc->nbusy);

	if (hc->busy) {
		for (i = 0; i < hc->nbusy; i++) {
			ngx_pfree(c->pool, hc->busy[i]->start);
			hc->busy[i] = NULL;
		}

		hc->nbusy = 0;
	}

	rev->handler = ngx_http_keepalive_handler;

	c->idle = 1;
	ngx_reusable_connection(c, 1);

	if (rev->ready) {
		ngx_locked_post_event(rev, &ngx_posted_events);
	}
}

static void ngx_http_keepalive_handler(ngx_event_t *rev) {
	size_t size;
	ssize_t n;
	ngx_buf_t *b;
	ngx_connection_t *c;

	c = rev->data;

	log_print(LOG_LEVEL_DEBUG, "http keepalive handler");

	if (rev->timedout || c->close) {
		ngx_http_close_connection(c);
		return;
	}

	b = c->buffer;
	size = b->end - b->start;

	if (b->pos == NULL) {

		/*
		 * The c->buffer's memory was freed by ngx_http_set_keepalive().
		 * However, the c->buffer->start and c->buffer->end were not changed
		 * to keep the buffer size.
		 */

		b->pos = ngx_palloc(c->pool, size);
		if (b->pos == NULL) {
			ngx_http_close_connection(c);
			return;
		}

		b->start = b->pos;
		b->last = b->pos;
		b->end = b->pos + size;
	}

	/*
	 * MSIE closes a keepalive connection with RST flag
	 * so we ignore ECONNRESET here.
	 */

	errno = 0;

	n = c->recv(c, b->last, size);

	if (n == IMGZIP_AGAIN) {
		if (ngx_handle_read_event(rev) != IMGZIP_OK) {
			ngx_http_close_connection(c);
		}

		return;
	}

	if (n == IMGZIP_ERR) {
		ngx_http_close_connection(c);
		return;
	}

	if (n == 0) {
		log_print(LOG_LEVEL_ERROR, "client %V closed keepalive connection", &c->addr_text);
		ngx_http_close_connection(c);
		return;
	}

	b->last += n;

	c->idle = 0;
	ngx_reusable_connection(c, 0);

	ngx_http_init_request(rev);
}

void ngx_http_empty_handler(ngx_event_t *wev) {
	log_print(LOG_LEVEL_DEBUG, "http empty handler");

	return;
}

void ngx_http_request_empty_handler(ngx_http_request_t *r) {
	log_print(LOG_LEVEL_DEBUG, "http request empty handler");

	return;
}

ngx_int_t ngx_http_send_special(ngx_http_request_t *r, ngx_uint_t flags) {
	ngx_buf_t *b;
	ngx_chain_t out;

	b = ngx_calloc_buf(r->pool);
	if (b == NULL) {
		return IMGZIP_ERR;
	}

	if (flags & NGX_HTTP_LAST) {

		b->last_buf = 1;

	}

	if (flags & NGX_HTTP_FLUSH) {
		b->flush = 1;
	}

	out.buf = b;
	out.next = NULL;

	return ngx_http_output_filter(r, &out);
}

static void ngx_http_close_request(ngx_http_request_t *r, ngx_int_t rc) {
	ngx_connection_t *c;

	c = r->connection;

	log_print(LOG_LEVEL_DEBUG, "http request count:%d ", r->count);

	if (r->count == 0) {
		log_print(LOG_LEVEL_ERROR, "http request count is zero");
	}

	r->count--;

	if (r->count) {
		return;
	}

	ngx_http_free_request(r, rc);
	ngx_http_close_connection(c);
}

static void ngx_http_free_request(ngx_http_request_t *r, ngx_int_t rc) {
	ngx_http_cleanup_t *cln;

	log_print(LOG_LEVEL_DEBUG, "http close request");

	if (r->pool == NULL) {
		log_print(LOG_LEVEL_INFO, "http request already closed");
		return;
	}

	for (cln = r->cleanup; cln; cln = cln->next) {
		if (cln->handler) {
			cln->handler(cln->data);
		}
	}

	if (rc > 0 && (r->headers_out.status == 0 || r->connection->sent == 0)) {
		r->headers_out.status = rc;
	}
	ngx_http_log_handler(r);
	r->request_line.len = 0;

	r->connection->destroyed = 1;

	ngx_destroy_pool(r->pool);
}

static void ngx_http_close_connection(ngx_connection_t *c) {
	ngx_pool_t *pool;

	log_print(LOG_LEVEL_DEBUG, "close http connection: %d", c->fd);

	c->destroyed = 1;

	pool = c->pool;

	ngx_close_connection(c);

	ngx_destroy_pool(pool);
}
ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *in) {
	ngx_int_t rc;
	ngx_connection_t *c;

	c = r->connection;

	rc = ngx_http_write_filter(r, in);

	if (rc == IMGZIP_ERR) {
		/* IMGZIP_ERR may be returned by any filter */
		c->error = 1;
	}

	return rc;
}

static ngx_int_t ngx_http_set_write_handler(ngx_http_request_t *r) {
	ngx_event_t *wev;

	r->http_state = NGX_HTTP_WRITING_REQUEST_STATE;

	r->read_event_handler = r->discard_body ? ngx_http_discarded_request_body_handler : ngx_http_test_reading;
	r->write_event_handler = ngx_http_writer;

	wev = r->connection->write;

	ngx_event_add_timer(wev, SEND_TIMEOUT);

	if (ngx_handle_write_event(wev) != IMGZIP_OK) {
		ngx_http_close_request(r, 0);
		return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}

static void ngx_http_writer(ngx_http_request_t *r) {
	int rc;
	ngx_event_t *wev;
	ngx_connection_t *c;

	c = r->connection;
	wev = c->write;

	log_print(LOG_LEVEL_DEBUG, "http writer handler: \"%V?%V\"", &r->uri, &r->args);

	if (wev->timedout) {

		log_print(LOG_LEVEL_ERROR, "client timed out");
		c->timedout = 1;

		ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
		return;

	}

	rc = ngx_http_output_filter(r, NULL);

	if (rc == IMGZIP_ERR) {
		ngx_http_finalize_request(r, rc);
		return;
	}

	if (c->buffered) {

		if (!wev->ready) {
			ngx_event_add_timer(wev, SEND_TIMEOUT);
		}

		if (ngx_handle_write_event(wev) != IMGZIP_OK) {
			ngx_http_close_request(r, 0);
		}

		return;
	}

	r->write_event_handler = ngx_http_request_empty_handler;

	ngx_http_finalize_request(r, rc);
}

ngx_int_t ngx_http_send_header(ngx_http_request_t *r) {
	if (r->err_status) {
		r->headers_out.status = r->err_status;
		r->headers_out.status_line.len = 0;
	}

	return ngx_http_header_filter(r);
}
