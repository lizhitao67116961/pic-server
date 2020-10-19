/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_recv.h"
#include "../server/ngx_connection.h"

ssize_t ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size) {
	ssize_t n;
	ngx_err_t err;
	ngx_event_t *rev;

	rev = c->read;

	do {
		n = recv(c->fd, buf, size, 0);

		if (n == 0) {
			rev->ready = 0;
			rev->eof = 1;
			return n;

		} else if (n > 0) {

			return n;
		}

		err = errno;

		if (err == EAGAIN || err == EINTR) {
			log_print(LOG_LEVEL_DEBUG, "recv() not ready");
			n = IMGZIP_AGAIN;

		} else {
			n = IMGZIP_ERR;
			log_print(LOG_LEVEL_ERROR, "recv() failed");
			break;
		}

	} while (err == EINTR);

	rev->ready = 0;

	if (n == IMGZIP_ERR) {
		rev->error = 1;
	}

	return n;
}
