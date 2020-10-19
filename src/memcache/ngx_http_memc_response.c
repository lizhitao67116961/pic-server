/*
 *
 *  Created on: 2013-4-2
 *      Author: lizhitao
 */


#include "ngx_http_memc_response.h"

u_char ngx_http_memc_end[] = CRLF "END" CRLF;
static void ngx_http_memc_process_body_in_memory(ngx_http_request_t *r, ngx_http_upstream_t *u);
ngx_int_t ngx_http_memc_process_set_header(ngx_http_request_t *r) {
	u_char *p;
	u_char *pe;
	ngx_http_upstream_t *u;
	ngx_uint_t status;

	status = NGX_HTTP_OK;

	u = r->upstream;

	p = u->buffer.pos;
	pe = u->buffer.last - 1;
	if (*pe != LF) {
		return IMGZIP_AGAIN;
	}
	pe--;
	*pe = '\0';
	if (strncmp((char*) p, "STORED", sizeof("STORED") - 1) != 0) {
		log_print(LOG_LEVEL_ERROR, "memcache stor error,return value:%s", p);
	}
	ngx_http_memc_finalize_request(r, IMGZIP_OK);
	return IMGZIP_OK;
}

ngx_int_t ngx_http_memc_empty_filter_init(void *data) {
	ngx_http_memc_ctx_t *ctx = data;
	ngx_http_upstream_t *u;

	u = ctx->request->upstream;

	u->length = 0;

	/* to persuade ngx_http_upstream_keepalive (if any)
	 to cache the connection if the status is neither
	 200 nor 404. */

	return IMGZIP_OK;
}

ngx_int_t ngx_http_memc_empty_filter(void *data, ssize_t bytes) {
	ngx_http_memc_ctx_t *ctx = data;
	ngx_http_upstream_t *u;

	u = ctx->request->upstream;

	/* recover the buffer for subrequests in memory */
//	u->buffer.last += ctx->body_length;
	return IMGZIP_OK;
}

ngx_int_t ngx_http_memc_get_cmd_filter_init(void *data) {
	ngx_http_memc_ctx_t *ctx = data;

	ngx_http_upstream_t *u;

	u = ctx->request->upstream;

	u->length += NGX_HTTP_MEMC_END;

	return IMGZIP_OK;
}

ngx_int_t ngx_http_memc_get_cmd_filter(void *data, ssize_t bytes) {
	ngx_http_memc_ctx_t *ctx = data;

	u_char *last;
	ngx_buf_t *b;
	ngx_chain_t *cl, **ll;
	ngx_http_upstream_t *u;

	u = ctx->request->upstream;
	b = &u->buffer;

	if (u->length == ctx->rest) {

		if (strncmp((char*) b->last, (char*) (ngx_http_memc_end + NGX_HTTP_MEMC_END - ctx->rest), bytes) != 0) {
			log_print(LOG_LEVEL_ERROR, "memcached send invalid trailer");

			u->length = 0;
			ctx->rest = 0;

			return IMGZIP_OK;
		}

		u->length -= bytes;
		ctx->rest -= bytes;

		if (u->length == 0) {
			u->keepalive = 1;
		}

		return IMGZIP_OK;
	}

	for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
		ll = &cl->next;
	}

	cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
	if (cl == NULL) {
		return IMGZIP_ERR;
	}

	cl->buf->flush = 1;
	cl->buf->memory = 1;

	*ll = cl;

	last = b->last;
	cl->buf->pos = last;
	b->last += bytes;
	cl->buf->last = b->last;
	cl->buf->tag = u->output.tag;

	if (bytes <= (ssize_t) (u->length - NGX_HTTP_MEMC_END)) {
		u->length -= bytes;
		return IMGZIP_OK;
	}

	last += u->length - NGX_HTTP_MEMC_END;

	if (strncmp((char*) last, (char*) ngx_http_memc_end, b->last - last) != 0) {
		log_print(LOG_LEVEL_ERROR, "memcached send invalid trailer");

		b->last = last;
		cl->buf->last = last;
		u->length = 0;
		ctx->rest = 0;

		return IMGZIP_OK;

	}

	ctx->rest -= b->last - last;
	b->last = last;
	cl->buf->last = last;
	u->length = ctx->rest;

	if (u->length == 0) {
		u->keepalive = 1;
	}

	return IMGZIP_OK;
}

ngx_int_t ngx_http_memc_process_get_cmd_header(ngx_http_request_t *r) {
	u_char *p, *len;
	ngx_str_t line;
	ngx_http_upstream_t *u;
	ngx_http_memc_ctx_t *ctx;
	ngx_str_t *flags_vv;

	u = r->upstream;
	ctx = ngx_http_get_module_ctx(r, 1);
	for (p = u->buffer.pos; p < u->buffer.last; p++) {
		if (*p == LF) {
			goto found;
		}
	}

	return IMGZIP_AGAIN;

	found:

	*p = '\0';

	line.len = p - u->buffer.pos - 1;
	line.data = u->buffer.pos;

	log_print(LOG_LEVEL_DEBUG, "memcached: \"%V\"", &line);

	p = u->buffer.pos;
	if (strncmp((char*) p, "VALUE ", sizeof("VALUE ") - 1) == 0) {
		p += sizeof("VALUE ") - 1;

		if (strncmp((char*) p, (char*) ctx->key.data, ctx->key.len) != 0) {
			log_print(LOG_LEVEL_ERROR, "memcached send invalid key in response \"%V\" "
					"for key \"%V\"", &line, &ctx->key);

			return IMGZIP_ERR;
		}

		p += ctx->key.len;

		if (*p++ != ' ') {
			log_print(LOG_LEVEL_ERROR, "memcached send invalid response: \"%V\"", &line);
			goto no_valid;
		}

		/* save flags */

		flags_vv = &ctx->memc_flags_vv;

		flags_vv->data = p;

		while (*p) {
			if (*p++ == ' ') {
				flags_vv->len = p - 1 - flags_vv->data;
				r->headers_out.last_modified_time = ngx_atotm(flags_vv->data, flags_vv->len);
				goto length;
			}
		}
		log_print(LOG_LEVEL_ERROR, "memcached send invalid response: \"%V\"", &line);
		goto no_valid;

		length:

		len = p;

		while (*p && *p++ != CR) { /* void */
		}

		u->headers_in.content_length_n = ngx_atoof(len, p - len - 1);
		if (u->headers_in.content_length_n == -1) {

			log_print(LOG_LEVEL_ERROR, "memcached send invalid length in response \"%V\" for key \"%V\"", &line, &ctx->key);
			return IMGZIP_ERR;
		}

		u->headers_in.status_n = NGX_HTTP_OK;
		u->buffer.pos = p + 1;
		u->read_event_handler = ngx_http_memc_process_body_in_memory;

		ngx_http_memc_process_body_in_memory(r, u);
		return IMGZIP_OK;
	}

	if (strcmp((char*) p, "END\x0d") == 0) {
		log_print(LOG_LEVEL_INFO, "key: \"%V\" was not found by memcached", &ctx->key);
		u->headers_in.status_n = NGX_HTTP_NOT_FOUND;
		u->keepalive = 1;
		ngx_http_memc_finalize_request(r, IMGZIP_OK);
		return IMGZIP_OK;
	}

	no_valid:

	log_print(LOG_LEVEL_ERROR, "memcached send invalid response: \"%V\"", &line);

	return IMGZIP_ERR;
}

static void ngx_http_memc_process_body_in_memory(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	size_t size, buf_size, pos;
	ssize_t n;
	ngx_buf_t *b;
	ngx_event_t *rev;
	ngx_connection_t *c;

	c = u->peer.connection;
	rev = c->read;

	log_print(LOG_LEVEL_DEBUG, "http memc process body on memory");

	if (rev->timedout) {
		log_print(LOG_LEVEL_ERROR, "memc timed out");
		ngx_http_memc_finalize_request(r, NGX_HTTP_GATEWAY_TIME_OUT);
		return;
	}
	b = &u->buffer;
	if (u->headers_in.content_length_n + sizeof("\x0d\x0aEND\x0d\x0a") == b->last - b->pos) {
		u->headers_in.status_n = NGX_HTTP_OK;
		u->keepalive = 1;
		ngx_http_memc_finalize_request(r, IMGZIP_OK);
		return;
	}

	for (;;) {

		size = b->end - b->last;

		if (size == 0) {
			buf_size = b->end - b->start;
			pos = b->pos - b->start;
			b->start = ngx_prealloc(r->pool, b->start, buf_size, buf_size + client_body_buffer_size);
			if (b->start == NULL) {
				ngx_http_memc_finalize_request(r, IMGZIP_ERR);
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
		if (n == IMGZIP_ERR) {
			ngx_http_memc_finalize_request(r, n);
			return;
		}
		u->buffer.last += n;
		if (n == 0 || u->headers_in.content_length_n + sizeof("\x0d\x0aEND\x0d\x0a") == b->last - b->pos) {
			b->last -= sizeof("\x0d\x0aEND\x0d\x0a");
			u->headers_in.status_n = NGX_HTTP_OK;
			u->keepalive = 1;
			ngx_http_memc_finalize_request(r, IMGZIP_OK);
			return;
		}

		if (!rev->ready) {
			break;
		}
	}

	if (ngx_handle_read_event(rev) != IMGZIP_OK) {
		ngx_http_memc_finalize_request(r, IMGZIP_ERR);
		return;
	}

	if (rev->active) {
		ngx_event_add_timer(rev, read_timeout);

	} else if (rev->timer_set) {
		ngx_event_del_timer(rev);
	}
}
