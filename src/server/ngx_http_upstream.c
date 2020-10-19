/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_http.h"
#include "ngx_http_upstream.h"
#include "ngx_event.h"
#include "ngx_http_upstream_round_robin.h"
#define client_body_buffer_size 409600
#define buffer_size 409600
#define read_timeout 2000
#define NGX_MAX_SIZE_T_VALUE  9223372036854775807LL

static void ngx_http_upstream_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc);
static void ngx_http_upstream_cleanup(void *data);
static void ngx_http_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_handler(ngx_event_t *ev);
static void ngx_http_upstream_send_request_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_process_header(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_uint_t ft_type);
static ngx_int_t ngx_http_upstream_reinit(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_send_request_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_send_request(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_test_connect(ngx_connection_t *c);
static ngx_int_t ngx_http_upstream_test_next(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_process_headers(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_process_body_in_memory(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_copy_header_line(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_http_upstream_next_t ngx_http_upstream_next_errors[] = { { 500, NGX_HTTP_UPSTREAM_FT_HTTP_500 }, { 502, NGX_HTTP_UPSTREAM_FT_HTTP_502 }, { 503,
		NGX_HTTP_UPSTREAM_FT_HTTP_503 }, { 504, NGX_HTTP_UPSTREAM_FT_HTTP_504 }, { 0, 0 } };
static char ngx_http_proxy_version[] = " HTTP/1.0" CRLF;

static ngx_int_t ngx_http_proxy_reinit_request(ngx_http_request_t *r);
static void ngx_http_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
static ngx_int_t ngx_http_proxy_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_process_status_line(ngx_http_request_t *r);

static ngx_int_t ngx_http_upstream_copy_content_type(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_upstream_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_copy_content_length(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_ignore_header_line(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_upstream_rewrite_refresh(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_set_cookie(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_expires(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_copy_allow_ranges(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_copy_last_modified(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_cache_control(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_upstream_process_charset(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_buffering(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_upstream_process_limit_rate(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_upstream_process_accel_expires(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_rewrite_location(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
//static ngx_int_t ngx_http_upstream_copy_multi_header_lines(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
ngx_hash_t upstream_headers_in_hash;
ngx_http_upstream_header_t ngx_http_upstream_headers_in[] = {

{ ngx_string("Status"), ngx_http_upstream_process_header_line, offsetof(ngx_http_upstream_headers_in_t, status), ngx_http_upstream_copy_header_line, 0, 0 },

{ ngx_string("Content-Type"), ngx_http_upstream_process_header_line, offsetof(ngx_http_upstream_headers_in_t, content_type), ngx_http_upstream_copy_content_type, 0, 1 },

{ ngx_string("Content-Length"), ngx_http_upstream_process_header_line, offsetof(ngx_http_upstream_headers_in_t, content_length), ngx_http_upstream_copy_content_length, 0, 0 },

{ ngx_string("Date"), ngx_http_upstream_process_header_line, offsetof(ngx_http_upstream_headers_in_t, date), ngx_http_upstream_copy_header_line,
		offsetof(ngx_http_headers_out_t, date), 0 },

{ ngx_string("Last-Modified"), ngx_http_upstream_process_header_line, offsetof(ngx_http_upstream_headers_in_t, last_modified), ngx_http_upstream_copy_last_modified, 0, 0 },

{ ngx_string("ETag"), ngx_http_upstream_process_header_line, offsetof(ngx_http_upstream_headers_in_t, etag), ngx_http_upstream_copy_header_line,
		offsetof(ngx_http_headers_out_t, etag), 0 },

{ ngx_string("Server"), ngx_http_upstream_process_header_line, offsetof(ngx_http_upstream_headers_in_t, server), ngx_http_upstream_copy_header_line,
		offsetof(ngx_http_headers_out_t, server), 0 },

{ ngx_string("WWW-Authenticate"), ngx_http_upstream_process_header_line, offsetof(ngx_http_upstream_headers_in_t, www_authenticate), ngx_http_upstream_copy_header_line, 0, 0 },

{ ngx_string("Location"), ngx_http_upstream_process_header_line, offsetof(ngx_http_upstream_headers_in_t, location), ngx_http_upstream_rewrite_location, 0, 0 },

{ ngx_string("Refresh"), ngx_http_upstream_ignore_header_line, 0, ngx_http_upstream_rewrite_refresh, 0, 0 },

{ ngx_string("Set-Cookie"), ngx_http_upstream_process_set_cookie, 0, ngx_http_upstream_copy_header_line, 0, 1 },

{ ngx_string("Content-Disposition"), ngx_http_upstream_ignore_header_line, 0, ngx_http_upstream_copy_header_line, 0, 1 },

{ ngx_string("Cache-Control"), ngx_http_upstream_process_cache_control, 0, ngx_http_upstream_copy_header_line, offsetof(ngx_http_headers_out_t, cache_control), 1 },

{ ngx_string("Expires"), ngx_http_upstream_process_expires, 0, ngx_http_upstream_copy_header_line, offsetof(ngx_http_headers_out_t, expires), 1 },

{ ngx_string("Accept-Ranges"), ngx_http_upstream_process_header_line, offsetof(ngx_http_upstream_headers_in_t, accept_ranges), ngx_http_upstream_copy_allow_ranges,
		offsetof(ngx_http_headers_out_t, accept_ranges), 1 },

{ ngx_string("Connection"), ngx_http_upstream_ignore_header_line, 0, ngx_http_upstream_ignore_header_line, 0, 0 },

{ ngx_string("Keep-Alive"), ngx_http_upstream_ignore_header_line, 0, ngx_http_upstream_ignore_header_line, 0, 0 },

{ ngx_string("X-Powered-By"), ngx_http_upstream_ignore_header_line, 0, ngx_http_upstream_copy_header_line, 0, 0 },

{ ngx_string("X-Accel-Expires"), ngx_http_upstream_process_accel_expires, 0, ngx_http_upstream_copy_header_line, 0, 0 },

{ ngx_string("X-Accel-Redirect"), ngx_http_upstream_process_header_line, offsetof(ngx_http_upstream_headers_in_t, x_accel_redirect), ngx_http_upstream_copy_header_line, 0, 0 },

{ ngx_string("X-Accel-Limit-Rate"), ngx_http_upstream_process_limit_rate, 0, ngx_http_upstream_copy_header_line, 0, 0 },

{ ngx_string("X-Accel-Buffering"), ngx_http_upstream_process_buffering, 0, ngx_http_upstream_copy_header_line, 0, 0 },

{ ngx_string("X-Accel-Charset"), ngx_http_upstream_process_charset, 0, ngx_http_upstream_copy_header_line, 0, 0 },

{ ngx_null_string, NULL, 0, NULL, 0, 0 } };
typedef struct {
	ngx_http_status_t status;
} ngx_http_proxy_ctx_t;

ngx_int_t ngx_http_upstream_init(ngx_pool_t *pool) {
	ngx_array_t headers_in;
	ngx_hash_key_t *hk;
	ngx_hash_init_t hash;
	ngx_http_upstream_header_t *header;
	ngx_pool_t *temp_pool = ngx_create_pool(1024);
	if (ngx_array_init(&headers_in, temp_pool, 32, sizeof(ngx_hash_key_t)) != IMGZIP_OK) {
		ngx_destroy_pool(temp_pool);
		return IMGZIP_ERR;
	}
	for (header = ngx_http_upstream_headers_in; header->name.len; header++) {
		hk = ngx_array_push(&headers_in);
		if (hk == NULL) {
			ngx_destroy_pool(temp_pool);
			return IMGZIP_ERR;
		}

		hk->key = header->name;
		hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
		hk->value = header;
	}

	hash.hash = &upstream_headers_in_hash;
	hash.key = ngx_hash_key_lc;
	hash.max_size = 512;
	hash.bucket_size = ngx_align(64, ngx_cacheline_size);
	hash.name = "upstream_headers_in_hash";
	hash.pool = pool;
	hash.temp_pool = NULL;

	if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != IMGZIP_OK) {
		ngx_destroy_pool(temp_pool);
		return IMGZIP_ERR;
	}
	ngx_destroy_pool(temp_pool);
	return IMGZIP_OK;
}

void ngx_http_upstream_init_request(ngx_http_request_t *r) {

	ngx_connection_t *c;
	ngx_http_cleanup_t *cln;
	ngx_http_upstream_t *u;
	ngx_http_proxy_ctx_t *ctx;
	c = r->connection;

	if (c->read->timer_set) {
		ngx_event_del_timer(c->read);
	}

	if (ngx_http_upstream_create(r) != IMGZIP_OK) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	u = r->upstream;

	if (r->request_body) {
		u->request_bufs = r->request_body->bufs;
	}
	if (ngx_http_proxy_create_request(r) != IMGZIP_OK) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_ctx_t));
	if (ctx == NULL) {
		return;
	}

	ngx_http_set_ctx(r, ctx, 0);
	u->output.pool = r->pool;
	u->output.bufs.num = 1;
	u->output.bufs.size = client_body_buffer_size;
	u->output.output_filter = ngx_chain_writer;
	u->output.filter_ctx = &u->writer;

	u->writer.pool = r->pool;

	cln = ngx_http_cleanup_add(r, 0);
	if (cln == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	cln->handler = ngx_http_upstream_cleanup;
	cln->data = r;
	u->cleanup = &cln->handler;
	ngx_http_upstream_connect(r, u);

	return;

}

ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size) {
	ngx_http_cleanup_t *cln;

	cln = ngx_palloc(r->pool, sizeof(ngx_http_cleanup_t));
	if (cln == NULL) {
		return NULL;
	}

	if (size) {
		cln->data = ngx_palloc(r->pool, size);
		if (cln->data == NULL) {
			return NULL;
		}

	} else {
		cln->data = NULL;
	}

	cln->handler = NULL;
	cln->next = r->cleanup;

	r->cleanup = cln;

	log_print(LOG_LEVEL_DEBUG, "http cleanup add: %p", cln);

	return cln;
}

static void ngx_http_upstream_cleanup(void *data) {
	ngx_http_request_t *r = data;

	ngx_http_upstream_t *u;

	log_print(LOG_LEVEL_DEBUG, "cleanup http upstream request: \"%V\"", &r->uri);

	u = r->upstream;

	ngx_http_upstream_finalize_request(r, u, IMGZIP_DONE);
}

static void ngx_http_upstream_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc) {

	log_print(LOG_LEVEL_DEBUG, "finalize http upstream request: %i", rc);

	if (u->cleanup) {
		*u->cleanup = NULL;
		u->cleanup = NULL;
	}

	ngx_http_proxy_finalize_request(r, rc);
	ngx_http_upstream_free_round_robin_peer(&u->peer, 0);
	if (u->peer.connection) {

		log_print(LOG_LEVEL_DEBUG, "close http upstream connection: %d", u->peer.connection->fd);

		ngx_close_connection(u->peer.connection);
	}

	u->peer.connection = NULL;

	if (rc != IMGZIP_OK) {
		u->headers_in.status_n = rc;
	}

	if (r->content_handler && rc != IMGZIP_DONE) {
		r->content_handler(r);
	}
}

static void ngx_http_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_int_t rc;
	ngx_connection_t *c;

	r->connection->single_connection = 0;

	rc = ngx_event_connect_peer(&u->peer);

	log_print(LOG_LEVEL_DEBUG, "http upstream connect: %i", rc);

	if (rc == IMGZIP_ERR) {
		ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	if (rc == IMGZIP_BUSY) {
		log_print(LOG_LEVEL_ERROR, "no live upstreams");
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_NOLIVE);
		return;
	}

	if (rc == IMGZIP_DECLINED) {
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
		return;
	}

	/* rc == IMGZIP_OK || rc == IMGZIP_AGAIN */

	c = u->peer.connection;

	c->data = r;

	c->write->handler = ngx_http_upstream_handler;
	c->read->handler = ngx_http_upstream_handler;

	u->write_event_handler = ngx_http_upstream_send_request_handler;
	u->read_event_handler = ngx_http_upstream_process_header;

	c->sendfile &= r->connection->sendfile;
	u->output.sendfile = c->sendfile;

	c->pool = r->pool;

	/* init or reinit the ngx_output_chain() and ngx_chain_writer() contexts */

	u->writer.out = NULL;
	u->writer.last = &u->writer.out;
	u->writer.connection = c;
	u->writer.limit = 0;

	if (u->request_sent) {
		if (ngx_http_upstream_reinit(r, u) != IMGZIP_OK) {
			ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}

	u->request_sent = 0;

	if (rc == IMGZIP_AGAIN) {
		ngx_event_add_timer(c->write, CONNECT_TIMEOUT);
		return;
	}

	ngx_http_upstream_send_request(r, u);
}

static void ngx_http_upstream_handler(ngx_event_t *ev) {
	ngx_connection_t *c;
	ngx_http_request_t *r;
	ngx_http_upstream_t *u;

	c = ev->data;
	r = c->data;

	u = r->upstream;
	c = r->connection;

	if (ev->write) {
		u->write_event_handler(r, u);

	} else {
		u->read_event_handler(r, u);
	}

	ngx_http_run_posted_requests(c);
}

static void ngx_http_upstream_send_request_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_connection_t *c;

	c = u->peer.connection;

	log_print(LOG_LEVEL_DEBUG, "http upstream send request handler");

	if (c->write->timedout) {
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
		return;
	}

	if (u->header_sent) {
		u->write_event_handler = ngx_http_upstream_dummy_handler;

		(void) ngx_handle_write_event(c->write);

		return;
	}

	ngx_http_upstream_send_request(r, u);
}

static void ngx_http_upstream_process_header(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ssize_t n;
	ngx_int_t rc;
	ngx_connection_t *c;

	c = u->peer.connection;

	log_print(LOG_LEVEL_DEBUG, "http upstream process header");

	if (c->read->timedout) {
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
		return;
	}

	if (!u->request_sent && ngx_http_upstream_test_connect(c) != IMGZIP_OK) {
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
		return;
	}

	if (u->buffer.start == NULL) {
		u->buffer.start = ngx_palloc(r->pool, buffer_size);
		if (u->buffer.start == NULL) {
			ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		u->buffer.pos = u->buffer.start;
		u->buffer.last = u->buffer.start;
		u->buffer.end = u->buffer.start + buffer_size;
		u->buffer.temporary = 1;

		u->buffer.tag = u->output.tag;

		if (ngx_list_init(&u->headers_in.headers, r->pool, 8, sizeof(ngx_table_elt_t)) != IMGZIP_OK) {
			ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

	}

	for (;;) {

		n = c->recv(c, u->buffer.last, u->buffer.end - u->buffer.last);

		if (n == IMGZIP_AGAIN) {

			if (ngx_handle_read_event(c->read) != IMGZIP_OK) {
				ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			return;
		}

		if (n == 0) {
			log_print(LOG_LEVEL_ERROR, "upstream prematurely closed connection");
		}

		if (n == IMGZIP_ERR || n == 0) {
			ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
			return;
		}

		u->buffer.last += n;

		rc = ngx_http_proxy_process_status_line(r);

		if (rc == IMGZIP_AGAIN) {

			if (u->buffer.pos == u->buffer.end) {
				log_print(LOG_LEVEL_ERROR, "upstream sent too big header");

				ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
				return;
			}

			continue;
		}

		break;
	}

	if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
		return;
	}

	if (rc == IMGZIP_ERR) {
		ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	/* rc == IMGZIP_OK */

	if (u->headers_in.status_n > NGX_HTTP_SPECIAL_RESPONSE) {

		if (ngx_http_upstream_test_next(r, u) == IMGZIP_OK) {
			return;
		}

	}

	if (ngx_http_upstream_process_headers(r, u) != IMGZIP_OK) {
		return;
	}

	u->read_event_handler = ngx_http_upstream_process_body_in_memory;

	ngx_http_upstream_process_body_in_memory(r, u);
}

static void ngx_http_upstream_process_body_in_memory(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	size_t size, buf_size, pos;
	ssize_t n;
	ngx_buf_t *b;
	ngx_event_t *rev;
	ngx_connection_t *c;

	c = u->peer.connection;
	rev = c->read;

	log_print(LOG_LEVEL_DEBUG, "http upstream process body on memory");

	if (rev->timedout) {
		log_print(LOG_LEVEL_ERROR, "upstream timed out");
		ngx_http_upstream_finalize_request(r, u, ETIMEDOUT);
		return;
	}

	b = &u->buffer;

	for (;;) {

		size = b->end - b->last;

		if (size == 0) {
			buf_size = b->end - b->start;
			pos = b->pos - b->start;
			b->start = ngx_prealloc(r->pool, b->start, buf_size, buf_size + client_body_buffer_size);
			if (b->start == NULL) {
				ngx_http_upstream_finalize_request(r, u, IMGZIP_ERR);
				return;
			}
			b->pos = b->start + pos;
			b->last = b->start + buf_size;
			b->end = b->start + buf_size + client_body_buffer_size;
			size = b->end - b->last;
		}
		n = c->recv(c, b->last, size);
		if (n == IMGZIP_AGAIN) {
			break;
		}

		if (n == 0 || n == IMGZIP_ERR) {
			ngx_http_upstream_finalize_request(r, u, n);
			return;
		}
		u->buffer.last += n;
		if (!rev->ready) {
			break;
		}
	}

	if (ngx_handle_read_event(rev) != IMGZIP_OK) {
		ngx_http_upstream_finalize_request(r, u, IMGZIP_ERR);
		return;
	}
	if (rev->active) {
		ngx_event_add_timer(rev, read_timeout);

	} else if (rev->timer_set) {
		ngx_event_del_timer(rev);
	}
}

static void ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_uint_t ft_type) {
	ngx_uint_t status, state;

	log_print(LOG_LEVEL_DEBUG, "http next upstream, %xi", ft_type);

	if (ft_type == NGX_HTTP_UPSTREAM_FT_HTTP_404) {
		state = NGX_PEER_NEXT;
	} else {
		state = NGX_PEER_FAILED;
	}

	if (ft_type != NGX_HTTP_UPSTREAM_FT_NOLIVE) {
		ngx_http_upstream_free_round_robin_peer(&u->peer, state);
	}

	if (ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT) {
		log_print(LOG_LEVEL_ERROR, "upstream timed out");
	}

	switch (ft_type) {

	case NGX_HTTP_UPSTREAM_FT_TIMEOUT:
		status = NGX_HTTP_GATEWAY_TIME_OUT;
		break;

	case NGX_HTTP_UPSTREAM_FT_HTTP_500:
		status = NGX_HTTP_INTERNAL_SERVER_ERROR;
		break;

	case NGX_HTTP_UPSTREAM_FT_HTTP_404:
		status = NGX_HTTP_NOT_FOUND;
		break;

	default:
		status = NGX_HTTP_BAD_GATEWAY;
		break;
	}

	if (r->connection->error) {
		ngx_http_upstream_finalize_request(r, u, NGX_HTTP_CLIENT_CLOSED_REQUEST);
		return;
	}

	if (u->peer.tries == 0) {

		ngx_http_upstream_finalize_request(r, u, status);
		return;
	}

	if (u->peer.connection) {
		log_print(LOG_LEVEL_DEBUG, "close http upstream connection: %d", u->peer.connection->fd);

		ngx_close_connection(u->peer.connection);
	}

	ngx_http_upstream_connect(r, u);
}

static ngx_int_t ngx_http_upstream_reinit(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_chain_t *cl;

	if (ngx_http_proxy_reinit_request(r) != IMGZIP_OK) {
		return IMGZIP_ERR;
	}

	ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));

	if (ngx_list_init(&u->headers_in.headers, r->pool, 8, sizeof(ngx_table_elt_t)) != IMGZIP_OK) {
		return IMGZIP_ERR;
	}

	/* reinit the request chain */

	for (cl = u->request_bufs; cl; cl = cl->next) {
		cl->buf->pos = cl->buf->start;
	}

	/* reinit the subrequest's ngx_output_chain() context */

	u->output.buf = NULL;
	u->output.in = NULL;
	u->output.busy = NULL;

	/* reinit u->buffer */

	u->buffer.pos = u->buffer.start;

	u->buffer.last = u->buffer.pos;

	return IMGZIP_OK;
}

static void ngx_http_upstream_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
}

static void ngx_http_upstream_send_request(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_int_t rc;
	ngx_connection_t *c;

	c = u->peer.connection;

	log_print(LOG_LEVEL_DEBUG, "http upstream send request");

	if (!u->request_sent && ngx_http_upstream_test_connect(c) != IMGZIP_OK) {
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
		return;
	}

	rc = ngx_output_chain(&u->output, u->request_sent ? NULL : u->request_bufs);

	u->request_sent = 1;

	if (rc == IMGZIP_ERR) {
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
		return;
	}

	if (c->write->timer_set) {
		ngx_event_del_timer(c->write);
	}

	if (rc == IMGZIP_AGAIN) {
		ngx_event_add_timer(c->write, SEND_TIMEOUT);

		if (ngx_handle_write_event(c->write) != IMGZIP_OK) {
			ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		return;
	}

	/* rc == IMGZIP_OK */

	if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
		if (ngx_tcp_push(c->fd) == IMGZIP_ERR) {
			log_print(LOG_LEVEL_ERROR, "ngx_tcp_push(c->fd) failed");
			ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
	}

	ngx_event_add_timer(c->read, read_timeout);

	if (c->read->ready) {

		ngx_http_upstream_process_header(r, u);
		return;
	}

	u->write_event_handler = ngx_http_upstream_dummy_handler;

	if (ngx_handle_write_event(c->write) != IMGZIP_OK) {
		ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
}

static ngx_int_t ngx_http_upstream_test_connect(ngx_connection_t *c) {
	int err;
	socklen_t len;

	{
		err = 0;
		len = sizeof(int);

		/*
		 * BSDs and Linux return 0 and set a pending error in err
		 * Solaris returns -1 and sets errno
		 */

		if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
			err = errno;
		}

		if (err) {
			log_print(LOG_LEVEL_ERROR, "connect() failed");
			return IMGZIP_ERR;
		}
	}

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_upstream_test_next(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_uint_t status;
	ngx_http_upstream_next_t *un;

	status = u->headers_in.status_n;

	for (un = ngx_http_upstream_next_errors; un->status; un++) {

		if (status != un->status) {
			continue;
		}

		if (u->peer.tries > 1) {
			ngx_http_upstream_next(r, u, un->mask);
			return IMGZIP_OK;
		}

	}

	return IMGZIP_DECLINED;
}

static ngx_int_t ngx_http_upstream_process_headers(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_uint_t i;
	ngx_list_part_t *part;
	ngx_table_elt_t *h;
	ngx_http_upstream_header_t *hh;

	part = &u->headers_in.headers.part;
	h = part->elts;

	for (i = 0; /* void */; i++) {

		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}

			part = part->next;
			h = part->elts;
			i = 0;
		}

		hh = ngx_hash_find(&upstream_headers_in_hash, h[i].hash, h[i].lowcase_key, h[i].key.len);

		if (hh) {
			if (hh->copy_handler(r, &h[i], hh->conf) != IMGZIP_OK) {
				ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return IMGZIP_DONE;
			}

			continue;
		}

		if (ngx_http_upstream_copy_header_line(r, &h[i], 0) != IMGZIP_OK) {
			ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return IMGZIP_DONE;
		}
	}

	if (r->headers_out.server && r->headers_out.server->value.data == NULL) {
		r->headers_out.server->hash = 0;
	}

	if (r->headers_out.date && r->headers_out.date->value.data == NULL) {
		r->headers_out.date->hash = 0;
	}

	r->headers_out.status = u->headers_in.status_n;
	r->headers_out.status_line = u->headers_in.status_line;

	u->headers_in.content_length_n = r->headers_out.content_length_n;

	return IMGZIP_OK;
}
static ngx_int_t ngx_http_upstream_copy_header_line(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t *ho, **ph;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return IMGZIP_ERR;
	}

	*ho = *h;

	if (offset) {
		ph = (ngx_table_elt_t **) ((char *) &r->headers_out + offset);
		*ph = ho;
	}

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_proxy_create_request(ngx_http_request_t *r) {
	size_t len, uri_len, loc_len;
	uintptr_t escape;
	ngx_buf_t *b;
	ngx_str_t method;
	ngx_chain_t *cl;
	ngx_http_upstream_t *u;

	u = r->upstream;

	method = r->method_name;
	method.len++;

	len = method.len + sizeof(ngx_http_proxy_version) - 1 + sizeof(CRLF) - 1;

	escape = 0;
	loc_len = 0;
	uri_len = r->unparsed_uri.len;

	if (uri_len == 0) {
		log_print(LOG_LEVEL_ERROR, "zero length URI to proxy");
		return IMGZIP_ERR;
	}

	len += uri_len;

	b = ngx_create_temp_buf(r->pool, len);
	if (b == NULL) {
		return IMGZIP_ERR;
	}

	cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL) {
		return IMGZIP_ERR;
	}

	cl->buf = b;

	/* the request line */

	b->last = ngx_cpymem(b->last, method.data, method.len);

	u->uri.data = b->last;

	b->last = ngx_cpymem(b->last, r->unparsed_uri.data, r->unparsed_uri.len);

	u->uri.len = b->last - u->uri.data;

	b->last = ngx_cpymem(b->last, ngx_http_proxy_version,
			sizeof(ngx_http_proxy_version) - 1);

	/* add "\r\n" at the header end */
	*b->last++ = CR;
	*b->last++ = LF;

	log_print(LOG_LEVEL_DEBUG, "http proxy header:\n\"%*s\"", (size_t) (b->last - b->pos), b->pos);

	u->request_bufs = cl;

	b->flush = 1;
	cl->next = NULL;

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_proxy_reinit_request(ngx_http_request_t *r) {

	r->upstream->process_header = ngx_http_proxy_process_status_line;
	r->state = 0;

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_proxy_process_status_line(ngx_http_request_t *r) {
	size_t len;
	ngx_int_t rc;
	ngx_http_upstream_t *u;
	ngx_http_proxy_ctx_t *ctx;
	u = r->upstream;
	ctx = ngx_http_get_module_ctx(r, 0);
	rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

	if (rc == IMGZIP_AGAIN) {
		return rc;
	}

	if (rc == IMGZIP_ERR) {

		log_print(LOG_LEVEL_ERROR, "upstream sent no valid HTTP/1.0 header");

		r->http_version = NGX_HTTP_VERSION_9;

		return IMGZIP_OK;
	}

	u->headers_in.status_n = ctx->status.code;

	len = ctx->status.end - ctx->status.start;
	u->headers_in.status_line.len = len;

	u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
	if (u->headers_in.status_line.data == NULL) {
		return IMGZIP_ERR;
	}

	memcpy(u->headers_in.status_line.data, ctx->status.start, len);

	log_print(LOG_LEVEL_DEBUG, "http proxy status %ui \"%V\"", u->headers_in.status_n, &u->headers_in.status_line);

	u->process_header = ngx_http_proxy_process_header;

	return ngx_http_proxy_process_header(r);
}

static ngx_int_t ngx_http_proxy_process_header(ngx_http_request_t *r) {
	ngx_int_t rc;
	ngx_table_elt_t *h;
	ngx_http_upstream_header_t *hh;

	for (;;) {

		rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

		if (rc == IMGZIP_OK) {

			/* a header line has been parsed successfully */

			h = ngx_list_push(&r->upstream->headers_in.headers);
			if (h == NULL) {
				return IMGZIP_ERR;
			}

			h->hash = r->header_hash;

			h->key.len = r->header_name_end - r->header_name_start;
			h->value.len = r->header_end - r->header_start;

			h->key.data = ngx_pnalloc(r->pool, h->key.len + 1 + h->value.len + 1 + h->key.len);
			if (h->key.data == NULL) {
				return IMGZIP_ERR;
			}

			h->value.data = h->key.data + h->key.len + 1;
			h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

			ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);
			ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

			if (h->key.len == r->lowcase_index) {
				memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

			} else {
				ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
			}

			hh = ngx_hash_find(&upstream_headers_in_hash, h->hash, h->lowcase_key, h->key.len);

			if (hh && hh->handler(r, h, hh->conf) != IMGZIP_OK) {
				return IMGZIP_ERR;
			}

			log_print(LOG_LEVEL_DEBUG, "http proxy header: \"%V: %V\"", &h->key, &h->value);

			continue;
		}

		if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

			/* a whole header has been parsed successfully */

			log_print(LOG_LEVEL_DEBUG, "http proxy header done");

			/*
			 * if no "Server" and "Date" in header line,
			 * then add the special empty headers
			 */

			if (r->upstream->headers_in.server == NULL) {
				h = ngx_list_push(&r->upstream->headers_in.headers);
				if (h == NULL) {
					return IMGZIP_ERR;
				}

				h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
												ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

				ngx_str_set(&h->key, "Server");
				ngx_str_null(&h->value);
				h->lowcase_key = (u_char *) "server";
			}

			if (r->upstream->headers_in.date == NULL) {
				h = ngx_list_push(&r->upstream->headers_in.headers);
				if (h == NULL) {
					return IMGZIP_ERR;
				}

				h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

				ngx_str_set(&h->key, "Date");
				ngx_str_null(&h->value);
				h->lowcase_key = (u_char *) "date";
			}

			return IMGZIP_OK;
		}

		if (rc == IMGZIP_AGAIN) {
			return IMGZIP_AGAIN;
		}

		/* there was error while a header line parsing */

		log_print(LOG_LEVEL_ERROR, "upstream sent invalid header");

		return NGX_HTTP_UPSTREAM_INVALID_HEADER;
	}
}
static void ngx_http_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
	log_print(LOG_LEVEL_DEBUG, "finalize http proxy request");

	return;
}
ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r) {
	ngx_http_upstream_t *u;

	u = r->upstream;

	if (u && u->cleanup) {
		ngx_http_upstream_cleanup(r);
	}

	u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
	if (u == NULL) {
		return IMGZIP_ERR;
	}
	r->upstream = u;
	ngx_http_upstream_init_round_robin_peer(r);

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_upstream_copy_content_type(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	u_char *p, *last;

	r->headers_out.content_type_len = h->value.len;
	r->headers_out.content_type = h->value;
	r->headers_out.content_type_lowcase = NULL;

	for (p = h->value.data; *p; p++) {

		if (*p != ';') {
			continue;
		}

		last = p;

		while (*++p == ' ') { /* void */
		}

		if (*p == '\0') {
			return IMGZIP_OK;
		}

		if (ngx_strncasecmp(p, (u_char *) "charset=", 8) != 0) {
			continue;
		}

		p += 8;

		r->headers_out.content_type_len = last - h->value.data;

		if (*p == '"') {
			p++;
		}

		last = h->value.data + h->value.len;

		if (*(last - 1) == '"') {
			last--;
		}

		r->headers_out.charset.len = last - p;
		r->headers_out.charset.data = p;

		return IMGZIP_OK;
	}

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_upstream_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t **ph;

	ph = (ngx_table_elt_t **) ((char *) &r->upstream->headers_in + offset);

	if (*ph == NULL) {
		*ph = h;
	}

	return IMGZIP_OK;
}
static ngx_int_t ngx_http_upstream_copy_content_length(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
//	ngx_table_elt_t *ho;

//	ho = ngx_list_push(&r->headers_out.headers);
//	if (ho == NULL) {
//		return IMGZIP_ERR;
//	}
//
//	*ho = *h;
//
//	r->headers_out.content_length = ho;
//	r->headers_out.content_length_n = ngx_atoof(h->value.data, h->value.len);

	return IMGZIP_OK;
}
static ngx_int_t ngx_http_upstream_ignore_header_line(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	return IMGZIP_OK;
}

static ngx_int_t ngx_http_upstream_rewrite_refresh(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	u_char *p;
	ngx_int_t rc;
	ngx_table_elt_t *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return IMGZIP_ERR;
	}

	*ho = *h;

	if (r->upstream->rewrite_redirect) {

		p = ngx_strcasestrn(ho->value.data, "url=", 4 - 1);

		if (p) {
			rc = r->upstream->rewrite_redirect(r, ho, p + 4 - ho->value.data);

		} else {
			return IMGZIP_OK;
		}

		if (rc == IMGZIP_DECLINED) {
			return IMGZIP_OK;
		}

		if (rc == IMGZIP_OK) {
			r->headers_out.refresh = ho;

		}

		return rc;
	}

	r->headers_out.refresh = ho;

	return IMGZIP_OK;
}
static ngx_int_t ngx_http_upstream_process_set_cookie(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {

	return IMGZIP_OK;
}
static ngx_int_t ngx_http_upstream_process_expires(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_http_upstream_t *u;

	u = r->upstream;
	u->headers_in.expires = h;

	return IMGZIP_OK;
}
static ngx_int_t ngx_http_upstream_copy_allow_ranges(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return IMGZIP_ERR;
	}

	*ho = *h;

	r->headers_out.accept_ranges = ho;

	return IMGZIP_OK;
}
static ngx_int_t ngx_http_upstream_copy_last_modified(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return IMGZIP_ERR;
	}

	*ho = *h;

	r->headers_out.last_modified = ho;

	return IMGZIP_OK;
}
static ngx_int_t ngx_http_upstream_process_cache_control(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {

	ngx_http_upstream_t *u;

	u = r->upstream;
	u->headers_in.cache_control = h;

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_upstream_process_charset(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {

	r->headers_out.override_charset = &h->value;

	return IMGZIP_OK;
}
static ngx_int_t ngx_http_upstream_process_buffering(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_upstream_process_limit_rate(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_upstream_process_accel_expires(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_http_upstream_t *u;

	u = r->upstream;
	u->headers_in.x_accel_expires = h;

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_upstream_rewrite_location(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_int_t rc;
	ngx_table_elt_t *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return IMGZIP_ERR;
	}

	*ho = *h;

	if (r->upstream->rewrite_redirect) {
		rc = r->upstream->rewrite_redirect(r, ho, 0);

		if (rc == IMGZIP_DECLINED) {
			return IMGZIP_OK;
		}

		if (rc == IMGZIP_OK) {
			r->headers_out.location = ho;

		}

		return rc;
	}

	if (ho->value.data[0] != '/') {
		r->headers_out.location = ho;
	}

	/*
	 * we do not set r->headers_out.location here to avoid the handling
	 * the local redirects without a host name by ngx_http_header_filter()
	 */

	return IMGZIP_OK;
}
//static ngx_int_t ngx_http_upstream_copy_multi_header_lines(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
//	ngx_array_t *pa;
//	ngx_table_elt_t *ho, **ph;
//
//	pa = (ngx_array_t *) ((char *) &r->headers_out + offset);
//
//	if (pa->elts == NULL) {
//		if (ngx_array_init(pa, r->pool, 2, sizeof(ngx_table_elt_t *)) != IMGZIP_OK) {
//			return IMGZIP_ERR;
//		}
//	}
//
//	ph = ngx_array_push(pa);
//	if (ph == NULL) {
//		return IMGZIP_ERR;
//	}
//
//	ho = ngx_list_push(&r->headers_out.headers);
//	if (ho == NULL) {
//		return IMGZIP_ERR;
//	}
//
//	*ho = *h;
//	*ph = ho;
//
//	return IMGZIP_OK;
//}

