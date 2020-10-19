/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_event_connect.h"
#include "ngx_connection.h"
#include "ngx_epoll_module.h"
#include "../util/ngx_send.h"
#include "../util/ngx_recv.h"
#include "../util/ngx_writev_chain.h"
#include "../util/ngx_readv_chain.h"
#include "ngx_http_upstream_round_robin.h"
#include <sys/socket.h>
#include <unistd.h>
ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc) {
	int rc;
	ngx_err_t err;
	int s;
	ngx_event_t *rev, *wev;
	ngx_connection_t *c;

	rc = ngx_http_upstream_get_round_robin_peer(pc);
	if (rc != IMGZIP_OK) {
		return rc;
	}

	s = socket(pc->sockaddr->sa_family, SOCK_STREAM, 0);

	if (s == -1) {
		log_print(LOG_LEVEL_ERROR, "create socket failed");
		return IMGZIP_ERR;
	}

	c = ngx_get_connection(s);

	if (c == NULL) {
		if (close(s) == -1) {
			log_print(LOG_LEVEL_ERROR, "close socket failed");
		}

		return IMGZIP_ERR;
	}

	if (pc->rcvbuf) {
		if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const void *) &pc->rcvbuf, sizeof(int)) == -1) {
			log_print(LOG_LEVEL_ERROR, "setsockopt(SO_RCVBUF) failed");
			goto failed;
		}
	}

	if (ngx_nonblocking(s) == -1) {
		log_print(LOG_LEVEL_ERROR, "ngx_nonblocking(s) failed");

		goto failed;
	}

	if (pc->local) {
		if (bind(s, pc->local->sockaddr, pc->local->socklen) == -1) {
			log_print(LOG_LEVEL_ERROR, "bind(%V) failed", &pc->local->name);

			goto failed;
		}
	}

	c->recv = ngx_unix_recv;
	c->send = ngx_unix_send;
	c->recv_chain = ngx_readv_chain;
	c->send_chain = ngx_writev_chain;

	c->sendfile = 1;

	c->log_error = pc->log_error;

	if (pc->sockaddr->sa_family != AF_INET) {
		c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
		c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

	}

	rev = c->read;
	wev = c->write;

	pc->connection = c;

	c->number = __sync_fetch_and_add(ngx_connection_counter, 1);

	if (ngx_epoll_add_connection(c) == IMGZIP_ERR) {
		goto failed;
	}

	rc = connect(s, pc->sockaddr, pc->socklen);

	if (rc == -1) {
		err = errno;

		if (err != EINPROGRESS) {

			log_print(LOG_LEVEL_ERROR, "connect() to %V failed", pc->name);

			return IMGZIP_DECLINED;
		}
	}

	if (rc == -1) {

		/* NGX_EINPROGRESS */

		return IMGZIP_AGAIN;
	}

	log_print(LOG_LEVEL_DEBUG, "connected");

	wev->ready = 1;

	return IMGZIP_OK;

	failed:

	ngx_free_connection(c);

	if (close(s) == -1) {
		log_print(LOG_LEVEL_ERROR, "close(s) failed");
	}

	return IMGZIP_ERR;
}

ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data) {
	return IMGZIP_OK;
}
