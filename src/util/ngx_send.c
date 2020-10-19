/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_send.h"
#include "../server/ngx_connection.h"
ssize_t ngx_unix_send(ngx_connection_t *c, u_char *buf, size_t size) {
	ssize_t n;
	ngx_err_t err;
	ngx_event_t *wev;

	wev = c->write;

	for (;;) {
		n = send(c->fd, buf, size, 0);

		if (n > 0) {
			if (n < (ssize_t) size) {
				wev->ready = 0;
			}

			c->sent += n;

			return n;
		}

		err = errno;

		if (n == 0) {
			log_print(LOG_LEVEL_ERROR, "send() returned zero");
			wev->ready = 0;
			return n;
		}

		if (err == EAGAIN || err == EINTR) {
			wev->ready = 0;

			log_print(LOG_LEVEL_ERROR, "send() not ready");

			if (err == EAGAIN) {
				return IMGZIP_AGAIN;
			}

		} else {
			wev->error = 1;
			log_print(LOG_LEVEL_ERROR, "send() failed");
			return IMGZIP_ERR;
		}
	}
	return IMGZIP_OK;
}
