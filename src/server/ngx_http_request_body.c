/*
 *
 *  Created on: 2013-03-22
 *      Author: lizhitao
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_http.h"
#include "ngx_connection.h"
#include "ngx_event.h"
#define client_body_buffer_size 2048000
#define client_body_timeout 10000
#define client_body_max_size 10*1024*1024
static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r);

/*
 * on completion ngx_http_read_client_request_body() adds to
 * r->request_body->bufs one or two bufs:
 *    *) one memory buf that was preread in r->header_in;
 *    *) one memory or file buf that contains the rest of the body
 */

ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r, ngx_http_client_body_handler_pt post_handler) {
	size_t preread;
	ssize_t size;
	ngx_buf_t *b;
	ngx_http_request_body_t *rb;

	if (r->request_body || r->discard_body) {
		post_handler(r);
		return IMGZIP_OK;
	}
	if (r->headers_in.content_length_n > client_body_max_size) {
		return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
	}
	if (ngx_http_test_expect(r) != IMGZIP_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
	if (rb == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->request_body = rb;

	if (r->headers_in.content_length_n < 0) {
		post_handler(r);
		return IMGZIP_OK;
	}

	if (r->headers_in.content_length_n == 0) {

		post_handler(r);

		return IMGZIP_OK;
	}

	rb->post_handler = post_handler;

	/*
	 * set by ngx_pcalloc():
	 *
	 *     rb->bufs = NULL;
	 *     rb->buf = NULL;
	 *     rb->rest = 0;
	 */

	preread = r->header_in->last - r->header_in->pos;

	if (preread) {

		/* there is the pre-read part of the request body */

		b = ngx_calloc_buf(r->pool);
		if (b == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		b->temporary = 1;
		b->start = r->header_in->pos;
		b->pos = r->header_in->pos;
		b->last = r->header_in->last;
		b->end = r->header_in->end;

		rb->buf = b;

		if ((off_t) preread >= r->headers_in.content_length_n) {

			/* the whole request body was pre-read */

			r->header_in->pos += (size_t) r->headers_in.content_length_n;
			r->request_length += r->headers_in.content_length_n;
			b->last = r->header_in->pos;

			post_handler(r);

			return IMGZIP_OK;
		}

		/*
		 * to not consider the body as pipelined request in
		 * ngx_http_set_keepalive()
		 */
		r->header_in->pos = r->header_in->last;

		r->request_length += preread;

		rb->rest = r->headers_in.content_length_n - preread;

		if (rb->rest <= (off_t) (b->end - b->last)) {

			r->read_event_handler = ngx_http_read_client_request_body_handler;

			return ngx_http_do_read_client_request_body(r);
		}

	} else {
		b = NULL;
		rb->rest = r->headers_in.content_length_n;
	}

	size = r->headers_in.content_length_n;

	rb->buf = ngx_create_temp_buf(r->pool, size);
	if (rb->buf == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (b) {
		size = b->last - b->pos;
		memcpy(rb->buf->pos, b->pos, size);
		rb->buf->last += size;

	}

	r->read_event_handler = ngx_http_read_client_request_body_handler;

	return ngx_http_do_read_client_request_body(r);
}

static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r) {
	ngx_int_t rc;

	if (r->connection->read->timedout) {
		r->connection->timedout = 1;
		ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
		return;
	}

	rc = ngx_http_do_read_client_request_body(r);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		ngx_http_finalize_request(r, rc);
	}
}

static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r) {
	size_t size;
	ssize_t n;
	ngx_connection_t *c;
	ngx_http_request_body_t *rb;

	c = r->connection;
	rb = r->request_body;

	log_print(LOG_LEVEL_DEBUG, "http read client request body");

	for (;;) {
		for (;;) {
			if (rb->buf->last == rb->buf->end) {
				break;
			}

			size = rb->buf->end - rb->buf->last;

			if ((off_t) size > rb->rest) {
				size = (size_t) rb->rest;
			}

			n = c->recv(c, rb->buf->last, size);

			if (n == IMGZIP_AGAIN) {
				break;
			}

			if (n == 0) {
				log_print(LOG_LEVEL_INFO, "client closed prematurely connection");
			}

			if (n == 0 || n == IMGZIP_ERR) {
				c->error = 1;
				return NGX_HTTP_BAD_REQUEST;
			}

			rb->buf->last += n;
			rb->rest -= n;
			r->request_length += n;

			if (rb->rest == 0) {
				break;
			}

			if (rb->buf->last < rb->buf->end) {
				break;
			}
		}

		log_print(LOG_LEVEL_DEBUG, "http client request body rest %O", rb->rest);

		if (rb->rest == 0) {
			break;
		}

		if (!c->read->ready) {
			ngx_event_add_timer(c->read, client_body_timeout);

			if (ngx_handle_read_event(c->read) != IMGZIP_OK) {
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			return IMGZIP_AGAIN;
		}
	}

	if (c->read->timer_set) {
		ngx_event_del_timer(c->read);
	}

	r->read_event_handler = ngx_http_block_reading;
printf("before rb->post_handler\n");
	rb->post_handler(r);
printf("rb->post_handler\n");
	return IMGZIP_OK;
}

static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r) {
	ngx_int_t n;
	ngx_str_t *expect;

	if (r->expect_tested || r->headers_in.expect == NULL || r->http_version < NGX_HTTP_VERSION_11)
	{
		return IMGZIP_OK;
	}

	r->expect_tested = 1;

	expect = &r->headers_in.expect->value;

	if (expect->len != sizeof("100-continue") - 1 || ngx_strncasecmp(expect->data, (u_char *) "100-continue", sizeof("100-continue") - 1) != 0) {
		return IMGZIP_OK;
	}

	n = r->connection->send(r->connection, (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF, sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

	if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
		return IMGZIP_OK;
	}

	/* we assume that such small packet should be send successfully */

	return IMGZIP_ERR;
}
