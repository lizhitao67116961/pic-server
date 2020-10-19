/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_readv_chain.h"
#include "../server/ngx_connection.h"
#include <sys/uio.h>
#define NGX_IOVS  16
ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *chain) {
	u_char *prev;
	ssize_t n, size;
	ngx_err_t err;
	ngx_array_t vec;
	ngx_event_t *rev;
	struct iovec *iov, iovs[NGX_IOVS];

	prev = NULL;
	iov = NULL;
	size = 0;

	vec.elts = iovs;
	vec.nelts = 0;
	vec.size = sizeof(struct iovec);
	vec.nalloc = NGX_IOVS;
	vec.pool = c->pool;

	/* coalesce the neighbouring bufs */

	while (chain) {
		if (prev == chain->buf->last) {
			iov->iov_len += chain->buf->end - chain->buf->last;

		} else {
			iov = ngx_array_push(&vec);
			if (iov == NULL) {
				return IMGZIP_ERR;
			}

			iov->iov_base = (void *) chain->buf->last;
			iov->iov_len = chain->buf->end - chain->buf->last;
		}

		size += chain->buf->end - chain->buf->last;
		prev = chain->buf->end;
		chain = chain->next;
	}


	rev = c->read;

	do {
		n = readv(c->fd, (struct iovec *) vec.elts, vec.nelts);

		if (n == 0) {
			rev->ready = 0;
			rev->eof = 1;

			return n;

		} else if (n > 0) {


			return n;
		}

		err = errno;

		if (err == EAGAIN || err == EINTR) {
			n = IMGZIP_AGAIN;

		} else {
			log_print(LOG_LEVEL_DEBUG, "readv() failed");
			break;
		}

	} while (err == EINTR);

	rev->ready = 0;

	if (n == IMGZIP_ERR) {
		c->read->error = 1;
	}

	return n;
}

