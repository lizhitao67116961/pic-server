/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_http.h"
#include "ngx_connection.h"

ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in) {
	off_t size;
	ngx_uint_t last, flush;
	ngx_chain_t *cl, *ln, **ll, *chain;
	ngx_connection_t *c;

	c = r->connection;

	if (c->error) {
		printf("I will return IMGZIP_ERR\n");
		return IMGZIP_ERR;
	}

	size = 0;
	flush = 0;
	last = 0;
	ll = &r->out;

	/* find the size, the flush point and the last link of the saved chain */

	for (cl = r->out; cl; cl = cl->next) {
		ll = &cl->next;

		size += ngx_buf_size(cl->buf);

		if (cl->buf->flush || cl->buf->recycled) {
			flush = 1;
		}

		if (cl->buf->last_buf) {
			last = 1;
		}
	}

	/* add the new chain to the existent one */

	for (ln = in; ln; ln = ln->next) {
		cl = ngx_alloc_chain_link(r->pool);
		if (cl == NULL) {
			return IMGZIP_ERR;
		}

		cl->buf = ln->buf;
		*ll = cl;
		ll = &cl->next;

		size += ngx_buf_size(cl->buf);

		if (cl->buf->flush || cl->buf->recycled) {
			flush = 1;
		}

		if (cl->buf->last_buf) {
			last = 1;
		}
	}

	*ll = NULL;

	if (size == 0) {
		if (last) {
			r->out = NULL;
			c->buffered |= ~NGX_HTTP_WRITE_BUFFERED;
			return IMGZIP_OK;
		}

		if (flush) {
			do {
				r->out = r->out->next;
			} while (r->out);
			c->buffered |= ~NGX_HTTP_WRITE_BUFFERED;
			return IMGZIP_OK;
		}

		log_print(LOG_LEVEL_ERROR, "the http output chain is empty");

		return IMGZIP_ERR;
	}

	chain = c->send_chain(c, r->out, 0);

	if (chain == (ngx_chain_t *) IMGZIP_ERR) {
		c->error = 1;
		return IMGZIP_ERR;
	}

	for (cl = r->out; cl && cl != chain; /* void */) {
		ln = cl;
		cl = cl->next;
		ngx_free_chain(r->pool, ln);
	}

	r->out = chain;

	if (chain) {
		c->buffered |= NGX_HTTP_WRITE_BUFFERED;
		return IMGZIP_AGAIN;
	}
	c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;
	return IMGZIP_OK;
}

