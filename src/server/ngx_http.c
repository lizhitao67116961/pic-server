/*
 *
 *  Created on: 2013-03-06
 *      Author: lizhitao
 */


#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_http.h"
#include "ngx_connection.h"
#include "ngx_http_upstream.h"
ngx_hash_t headers_in_hash;

ngx_uint_t ngx_http_max_module = 3;

ngx_int_t (*ngx_http_top_header_filter)(ngx_http_request_t *r);
ngx_int_t (*ngx_http_top_body_filter)(ngx_http_request_t *r, ngx_chain_t *ch);

ngx_str_t ngx_http_html_default_types[] = { ngx_string("text/html"), ngx_null_string };

ngx_int_t ngx_http_init_headers_in_hash(ngx_pool_t *pool) {
	ngx_array_t headers_in;
	ngx_hash_key_t *hk;
	ngx_hash_init_t hash;
	ngx_http_header_t *header;
	ngx_pool_t *temp_pool = ngx_create_pool(1024);
	if (ngx_array_init(&headers_in, temp_pool, 32, sizeof(ngx_hash_key_t)) != IMGZIP_OK) {
		return IMGZIP_ERR;
	}

	for (header = ngx_http_headers_in; header->name.len; header++) {
		hk = ngx_array_push(&headers_in);
		if (hk == NULL) {
			return IMGZIP_ERR;
		}

		hk->key = header->name;
		hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
		hk->value = header;
	}

	hash.hash = &headers_in_hash;
	hash.key = ngx_hash_key_lc;
	hash.max_size = 512;
	hash.bucket_size = ngx_align(64, ngx_cacheline_size);
	hash.name = "headers_in_hash";
	hash.pool = pool;
	hash.temp_pool = NULL;

	if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != IMGZIP_OK) {
		ngx_destroy_pool(temp_pool);
		return IMGZIP_ERR;
	}
	ngx_destroy_pool(temp_pool);
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

static ngx_int_t ngx_http_read_discarded_request_body(ngx_http_request_t *r) {
	size_t size;
	ssize_t n;
	u_char buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];

	for (;;) {
		if (r->headers_in.content_length_n == 0) {
			r->read_event_handler = ngx_http_block_reading;
			return IMGZIP_OK;
		}

		if (!r->connection->read->ready) {
			return IMGZIP_AGAIN;
		}

		size = (r->headers_in.content_length_n > NGX_HTTP_DISCARD_BUFFER_SIZE) ? NGX_HTTP_DISCARD_BUFFER_SIZE : (size_t) r->headers_in.content_length_n;

		n = r->connection->recv(r->connection, buffer, size);

		if (n == IMGZIP_ERR) {
			r->connection->error = 1;
			return IMGZIP_OK;
		}

		if (n == IMGZIP_AGAIN) {
			return IMGZIP_AGAIN;
		}

		if (n == 0) {
			return IMGZIP_OK;
		}

		r->headers_in.content_length_n -= n;
	}
	return IMGZIP_OK;
}

void ngx_http_handler(ngx_http_request_t *r) {

	r->connection->unexpected_eof = 0;

	if (!r->internal) {
		switch (r->headers_in.connection_type) {
		case 0:
			r->keepalive = (r->http_version > NGX_HTTP_VERSION_10);
			break;

		case NGX_HTTP_CONNECTION_CLOSE:
			r->keepalive = 0;
			break;

		case NGX_HTTP_CONNECTION_KEEP_ALIVE:
			r->keepalive = 1;
			break;
		}
		r->keepalive = 0;
		r->lingering_close = (r->headers_in.content_length_n > 0);

	}
	r->write_event_handler = ngx_http_core_run_phases;
	ngx_int_t rc = ngx_http_image_handler(r);
	if (rc == IMGZIP_AGAIN) {
		return ;
	}
	if (rc != IMGZIP_OK) {

		return ngx_http_finalize_request(r, rc);
	}
}
void ngx_http_core_run_phases(ngx_http_request_t *r) {
	log_print(LOG_LEVEL_DEBUG, "ngx_http_core_run_phases");
}
void ngx_http_discarded_request_body_handler(ngx_http_request_t *r) {
	ngx_int_t rc;
	uintptr_t timer;
	ngx_event_t *rev;
	ngx_connection_t *c;

	c = r->connection;
	rev = c->read;

	if (rev->timedout) {
		c->timedout = 1;
		c->error = 1;
		ngx_http_finalize_request(r, IMGZIP_ERR);
		return;
	}

	if (r->lingering_time) {
		timer = (uintptr_t) (r->lingering_time - ngx_time());

		if (timer <= 0) {
			r->discard_body = 0;
			r->lingering_close = 0;
			ngx_http_finalize_request(r, IMGZIP_ERR);
			return;
		}

	} else {
		timer = 0;
	}

	rc = ngx_http_read_discarded_request_body(r);

	if (rc == IMGZIP_OK) {
		r->discard_body = 0;
		r->lingering_close = 0;
		ngx_http_finalize_request(r, IMGZIP_DONE);
		return;
	}

	/* rc == NGX_AGAIN */

	if (ngx_handle_read_event(rev) != IMGZIP_OK) {
		c->error = 1;
		ngx_http_finalize_request(r, IMGZIP_ERR);
		return;
	}

	if (timer) {

		timer *= 1000;

		if (timer > LINGERING_TIMEOUT) {
			timer = LINGERING_TIMEOUT;
		}

		ngx_event_add_timer(rev, timer);
	}
}
ngx_int_t ngx_http_discard_request_body(ngx_http_request_t *r) {
	ssize_t size;
	ngx_event_t *rev;

	if (r->discard_body) {
		return IMGZIP_OK;
	}

	if (ngx_http_test_expect(r) != IMGZIP_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	rev = r->connection->read;

	if (rev->timer_set) {
		ngx_event_del_timer(rev);
	}

	if (r->headers_in.content_length_n <= 0 || r->request_body) {
		return IMGZIP_OK;
	}

	size = r->header_in->last - r->header_in->pos;

	if (size) {
		if (r->headers_in.content_length_n > size) {
			r->header_in->pos += size;
			r->headers_in.content_length_n -= size;

		} else {
			r->header_in->pos += (size_t) r->headers_in.content_length_n;
			r->headers_in.content_length_n = 0;
			return IMGZIP_OK;
		}
	}

	r->read_event_handler = ngx_http_discarded_request_body_handler;

	if (ngx_handle_read_event(rev) != IMGZIP_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_http_read_discarded_request_body(r) == IMGZIP_OK) {
		r->lingering_close = 0;

	} else {
		r->count++;
		r->discard_body = 1;
	}

	return IMGZIP_OK;
}

void ngx_http_rd_check_broken_connection(ngx_http_request_t *r) {
	ngx_http_check_broken_connection(r, r->connection->read);
}

void ngx_http_wr_check_broken_connection(ngx_http_request_t *r) {
	ngx_http_check_broken_connection(r, r->connection->write);
}

void ngx_http_check_broken_connection(ngx_http_request_t *r, ngx_event_t *ev) {
	int n;
	char buf[1];
	ngx_err_t err;
	ngx_connection_t *c;
	ngx_http_upstream_t *u;

	log_print(LOG_LEVEL_DEBUG, "http upstream check client, write event:%d, \"%V\"", ev->write, &r->uri);

	c = r->connection;
	u = r->upstream;

	if (c->error) {
		if (r->upstream->peer.connection){
			ngx_close_connection(r->upstream->peer.connection);
		}
		ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
		return;
	}

	n = recv(c->fd, buf, 1, MSG_PEEK);

	err = errno;

	log_print(LOG_LEVEL_DEBUG, "http upstream recv(): %d", n);

	if (ev->write && (n >= 0 || err == EAGAIN)) {
		return;
	}

	if (n > 0) {
		return;
	}

	if (n == -1) {
		if (err == EAGAIN) {
			return;
		}

		ev->error = 1;

	} else { /* n == 0 */
		err = 0;
	}

	ev->eof = 1;
	c->error = 1;

	log_print(LOG_LEVEL_ERROR, "client closed prematurely connection");

	if(r->upstream->peer.connection){
		ngx_close_connection(r->upstream->peer.connection);
	}
	ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);

}
