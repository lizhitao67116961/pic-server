/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_writev_chain.h"
#include "../server/ngx_connection.h"
#include <sys/uio.h>
#define NGX_IOVS  64
#define NGX_MAX_SIZE_T_VALUE  9223372036854775807LL
ngx_chain_t *
ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit) {
	u_char *prev;
	ssize_t n, size, sent;
	off_t send, prev_send;
	ngx_uint_t eintr, complete;
	ngx_err_t err;
	ngx_array_t vec;
	ngx_chain_t *cl;
	ngx_event_t *wev;
	struct iovec *iov, iovs[NGX_IOVS];

	wev = c->write;
	if(wev->timer_set){
		ngx_event_del_timer(wev);
	}
	ngx_event_add_timer(wev,6);

	if (!wev->ready) {
		return in;
	}

	/* the maximum limit size is the maximum size_t value - the page size */

	if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
		limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
	}

	send = 0;
	complete = 0;

	vec.elts = iovs;
	vec.size = sizeof(struct iovec);
	vec.nalloc = NGX_IOVS;
	vec.pool = c->pool;

	for (;;) {
		prev = NULL;
		iov = NULL;
		eintr = 0;
		prev_send = send;

		vec.nelts = 0;

		/* create the iovec and coalesce the neighbouring bufs */

		for (cl = in; cl && vec.nelts < NGX_IOVS && send < limit; cl = cl->next) {

			size = cl->buf->last - cl->buf->pos;

			if (send + size > limit) {
				size = (ssize_t) (limit - send);
			}

			if (prev == cl->buf->pos) {
				iov->iov_len += size;

			} else {
				iov = ngx_array_push(&vec);
				if (iov == NULL) {
					return (ngx_chain_t*)IMGZIP_ERR;
				}

				iov->iov_base = (void *) cl->buf->pos;
				iov->iov_len = size;
			}

			prev = cl->buf->pos + size;
			send += size;
		}

		n = writev(c->fd, vec.elts, vec.nelts);

		if (n == -1) {
			err = ngx_errno;

			switch (err) {
			case EAGAIN:
				break;

			case EINTR:
				eintr = 1;
				break;

			default:
				wev->error = 1;
				log_print(LOG_LEVEL_ERROR,"writev() failed");
				return (ngx_chain_t*)IMGZIP_ERR;
			}

		}

		sent = n > 0 ? n : 0;

		if (send - prev_send == sent) {
			complete = 1;
		}

		c->sent += sent;

		for (cl = in; cl; cl = cl->next) {

			if (ngx_buf_special(cl->buf)) {
				continue;
			}

			if (sent == 0) {
				break;
			}

			size = cl->buf->last - cl->buf->pos;

			if (sent >= size) {
				sent -= size;
				cl->buf->pos = cl->buf->last;

				continue;
			}

			cl->buf->pos += sent;

			break;
		}

		if (eintr) {
			continue;
		}

		if (!complete) {
			wev->ready = 0;
			return cl;
		}

		if (send >= limit || cl == NULL) {
			return cl;
		}

		in = cl;
	}
}
