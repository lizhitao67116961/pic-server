/*
 *
 *  Created on: 2013-03-12
 *      Author: lizhitao
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_event.h"
#include "ngx_connection.h"
/*
 * When DIRECTIO is enabled FreeBSD, Solaris, and MacOSX read directly
 * to an application memory from a device if parameters are aligned
 * to device sector boundary (512 bytes).  They fallback to usual read
 * operation if the parameters are not aligned.
 * Linux allows DIRECTIO only if the parameters are aligned to a filesystem
 * sector boundary, otherwise it returns EINVAL.  The sector size is
 * usually 512 bytes, however, on XFS it may be 4096 bytes.
 */

#define NGX_NONE            1

static inline ngx_int_t ngx_output_chain_as_is(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf);
static ngx_int_t ngx_output_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in);
static ngx_int_t ngx_output_chain_get_buf(ngx_output_chain_ctx_t *ctx, off_t bsize);
static ngx_int_t ngx_output_chain_copy_buf(ngx_output_chain_ctx_t *ctx);

ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in) {
	off_t bsize;
	ngx_int_t rc, last;
	ngx_chain_t *cl, *out, **last_out;

	if (ctx->in == NULL && ctx->busy == NULL) {

		/*
		 * the short path for the case when the ctx->in and ctx->busy chains
		 * are empty, the incoming chain is empty too or has the single buf
		 * that does not require the copy
		 */

		if (in == NULL) {
			return ctx->output_filter(ctx->filter_ctx, in);
		}

		if (in->next == NULL && ngx_output_chain_as_is(ctx, in->buf)) {
			return ctx->output_filter(ctx->filter_ctx, in);
		}
	}

	/* add the incoming buf to the chain ctx->in */

	if (in) {
		if (ngx_output_chain_add_copy(ctx->pool, &ctx->in, in) == IMGZIP_ERR) {
			return IMGZIP_ERR;
		}
	}

	out = NULL;
	last_out = &out;
	last = NGX_NONE;

	for (;;) {

		while (ctx->in) {

			/*
			 * cycle while there are the ctx->in bufs
			 * and there are the free output bufs to copy in
			 */

			bsize = ngx_buf_size(ctx->in->buf);

			if (bsize == 0 && !ngx_buf_special(ctx->in->buf)) {

				ctx->in = ctx->in->next;

				continue;
			}

			if (ngx_output_chain_as_is(ctx, ctx->in->buf)) {

				/* move the chain link to the output chain */

				cl = ctx->in;
				ctx->in = cl->next;

				*last_out = cl;
				last_out = &cl->next;
				cl->next = NULL;

				continue;
			}

			if (ctx->buf == NULL) {

				if (ctx->free) {

					/* get the free buf */

					cl = ctx->free;
					ctx->buf = cl->buf;
					ctx->free = cl->next;

					ngx_free_chain(ctx->pool, cl);

				} else if (out || ctx->allocated == ctx->bufs.num) {

					break;

				} else if (ngx_output_chain_get_buf(ctx, bsize) != IMGZIP_OK) {
					return IMGZIP_ERR;
				}

			}

			rc = ngx_output_chain_copy_buf(ctx);

			if (rc == IMGZIP_ERR) {
				return rc;
			}

			if (rc == IMGZIP_AGAIN) {
				if (out) {
					break;
				}

				return rc;
			}

			/* delete the completed buf from the ctx->in chain */

			if (ngx_buf_size(ctx->in->buf) == 0) {
				ctx->in = ctx->in->next;
			}

			cl = ngx_alloc_chain_link(ctx->pool);
			if (cl == NULL) {
				return IMGZIP_ERR;
			}

			cl->buf = ctx->buf;
			cl->next = NULL;
			*last_out = cl;
			last_out = &cl->next;
			ctx->buf = NULL;
		}

		if (out == NULL && last != NGX_NONE) {

			if (ctx->in) {
				return IMGZIP_AGAIN;
			}

			return last;
		}

		last = ctx->output_filter(ctx->filter_ctx, out);

		if (last == IMGZIP_ERR || last == IMGZIP_DONE) {
			return last;
		}

		ngx_chain_update_chains(&ctx->free, &ctx->busy, &out, ctx->tag);
		last_out = &out;
	}
	return IMGZIP_ERR;
}

static ngx_int_t ngx_output_chain_as_is(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf) {
	ngx_uint_t sendfile;

	if (ngx_buf_special(buf)) {
		return 1;
	}

	sendfile = ctx->sendfile;

	if (!sendfile) {

		if (!ngx_buf_in_memory(buf)) {
			return 0;
		}

		buf->in_file = 0;
	}

	if (ctx->need_in_memory && !ngx_buf_in_memory(buf)) {
		return 0;
	}

	if (ctx->need_in_temp && (buf->memory || buf->mmap)) {
		return 0;
	}

	return 1;
}

static ngx_int_t ngx_output_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in) {
	ngx_chain_t *cl, **ll;

	ll = chain;

	for (cl = *chain; cl; cl = cl->next) {
		ll = &cl->next;
	}

	while (in) {

		cl = ngx_alloc_chain_link(pool);
		if (cl == NULL) {
			return IMGZIP_ERR;
		}

		cl->buf = in->buf;
		in = in->next;

		cl->next = NULL;
		*ll = cl;
		ll = &cl->next;
	}

	return IMGZIP_OK;
}

static ngx_int_t ngx_output_chain_get_buf(ngx_output_chain_ctx_t *ctx, off_t bsize) {
	size_t size;
	ngx_buf_t *b, *in;
	ngx_uint_t recycled;

	in = ctx->in->buf;
	size = ctx->bufs.size;
	recycled = 1;

	if (in->last_in_chain) {

		if (bsize < (off_t) size) {

			/*
			 * allocate a small temp buf for a small last buf
			 * or its small last part
			 */

			size = (size_t) bsize;
			recycled = 0;

		} else if (!ctx->directio && ctx->bufs.num == 1 && (bsize < (off_t) (size + size / 4))) {
			/*
			 * allocate a temp buf that equals to a last buf,
			 * if there is no directio, the last buf size is lesser
			 * than 1.25 of bufs.size and the temp buf is single
			 */

			size = (size_t) bsize;
			recycled = 0;
		}
	}

	b = ngx_calloc_buf(ctx->pool);
	if (b == NULL) {
		return IMGZIP_ERR;
	}

	if (ctx->directio) {

		/*
		 * allocate block aligned to a disk sector size to enable
		 * userland buffer direct usage conjunctly with directio
		 */

		b->start = ngx_pmemalign(ctx->pool, size, (size_t) ctx->alignment);
		if (b->start == NULL) {
			return IMGZIP_ERR;
		}

	} else {
		b->start = ngx_palloc(ctx->pool, size);
		if (b->start == NULL) {
			return IMGZIP_ERR;
		}
	}

	b->pos = b->start;
	b->last = b->start;
	b->end = b->last + size;
	b->temporary = 1;
	b->tag = ctx->tag;
	b->recycled = recycled;

	ctx->buf = b;
	ctx->allocated++;

	return IMGZIP_OK;
}

static ngx_int_t ngx_output_chain_copy_buf(ngx_output_chain_ctx_t *ctx) {
	off_t size;
	ngx_buf_t *src, *dst;
	ngx_uint_t sendfile;

	src = ctx->in->buf;
	dst = ctx->buf;

	size = ngx_buf_size(src);
	size = ngx_min(size, dst->end - dst->pos);

	sendfile = ctx->sendfile & !ctx->directio;

	memcpy(dst->pos, src->pos, (size_t) size);
	src->pos += (size_t) size;
	dst->last += (size_t) size;

	dst->in_file = 0;

	if (src->pos == src->last) {
		dst->flush = src->flush;
		dst->last_buf = src->last_buf;
		dst->last_in_chain = src->last_in_chain;
	}

	return IMGZIP_OK;
}

ngx_int_t ngx_chain_writer(void *data, ngx_chain_t *in) {
	ngx_chain_writer_ctx_t *ctx = data;

	off_t size;
	ngx_chain_t *cl;
	ngx_connection_t *c;

	c = ctx->connection;

	for (size = 0; in; in = in->next) {

		size += ngx_buf_size(in->buf);

		cl = ngx_alloc_chain_link(ctx->pool);
		if (cl == NULL) {
			return IMGZIP_ERR;
		}

		cl->buf = in->buf;
		cl->next = NULL;
		*ctx->last = cl;
		ctx->last = &cl->next;
	}

	for (cl = ctx->out; cl; cl = cl->next) {

		size += ngx_buf_size(cl->buf);
	}

	if (size == 0) {
		return IMGZIP_OK;
	}

	ctx->out = c->send_chain(c, ctx->out, ctx->limit);

	if (ctx->out == (ngx_chain_t *) IMGZIP_ERR) {
		return IMGZIP_ERR;
	}

	if (ctx->out == NULL) {
		ctx->last = &ctx->out;

		return IMGZIP_OK;

	}

	return IMGZIP_AGAIN;
}
