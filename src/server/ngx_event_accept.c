/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_event.h"
#include "../util/ngx_send.h"
#include "../util/ngx_recv.h"
#include "../util/ngx_writev_chain.h"
#include "../util/ngx_readv_chain.h"
#include "ngx_connection.h"
#include "ngx_epoll_module.h"
#include "ngx_cycle.h"
#include "ngx_socket.h"
#include <unistd.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
static ngx_int_t ngx_enable_accept_events(ngx_cycle_t *cycle);
static ngx_int_t ngx_disable_accept_events(ngx_cycle_t *cycle);
static void ngx_close_accepted_connection(ngx_connection_t *c);

void ngx_event_accept(ngx_event_t *ev) {
	socklen_t socklen;
	ngx_err_t err;
	int s;
	ngx_event_t *rev, *wev;
	ngx_listening_t *ls;
	ngx_connection_t *c, *lc;
	u_char sa[sizeof(struct sockaddr_un)];

	lc = ev->data;
	ls = lc->listening;
	ev->ready = 0;
	do {

		socklen = sizeof(struct sockaddr_un);

		s = accept(lc->fd, (struct sockaddr *) sa, &socklen);
		if (s == -1) {
			err = errno;

			if (err == EAGAIN) {
				log_print(LOG_LEVEL_DEBUG, "accept() not ready");
				return;
			}

			log_print(LOG_LEVEL_ERROR, "accept() failed");

			if (err == ECONNABORTED) {
				continue;
			}

			return;
		}
		log_print(LOG_LEVEL_DEBUG, "create %s,port:%d\n", inet_ntoa(((struct sockaddr_in*) sa)->sin_addr), ntohs(((struct sockaddr_in*) sa)->sin_port));

		ngx_accept_disabled = ngx_cycle->connection_n / 8 - ngx_cycle->free_connection_n;

		c = ngx_get_connection(s);

		if (c == NULL) {
			if (close(s) == -1) {
				log_print(LOG_LEVEL_DEBUG, "socket close failed");
			}

			return;
		}

		c->pool = ngx_create_pool(ls->pool_size);
		if (c->pool == NULL) {
			ngx_close_accepted_connection(c);
			return;
		}

		c->sockaddr = ngx_palloc(c->pool, socklen);
		if (c->sockaddr == NULL) {
			ngx_close_accepted_connection(c);
			return;
		}

		memcpy(c->sockaddr, sa, socklen);

		/* set a blocking mode for aio and non-blocking mode for others */

		if (ngx_nonblocking(s) == -1) {
			log_print(LOG_LEVEL_ERROR, "ngx_nonblocking() failed");
			ngx_close_accepted_connection(c);
			return;
		}

		c->recv = ngx_unix_recv;
		c->send = ngx_unix_send;
		c->recv_chain = ngx_readv_chain;
		c->send_chain = ngx_writev_chain;

		c->socklen = socklen;
		c->listening = ls;
		c->local_sockaddr = ls->sockaddr;

		c->unexpected_eof = 1;

		rev = c->read;
		wev = c->write;

		wev->ready = 1;

		rev->ready = 1;

		c->number = __sync_fetch_and_add(ngx_connection_counter, 1);

		c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
		if (c->addr_text.data == NULL) {
			ngx_close_accepted_connection(c);
			return;
		}

		c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->addr_text.data, ls->addr_text_max_len, 0);
		if (c->addr_text.len == 0) {
			ngx_close_accepted_connection(c);
			return;
		}

		if (ngx_epoll_add_connection(c) == IMGZIP_ERR) {
			ngx_close_accepted_connection(c);
			return;
		}

		ls->handler(c);
	} while (1);
}

ngx_int_t ngx_trylock_accept_mutex(ngx_cycle_t *cycle) {
	if (ngx_shmtx_trylock(&ngx_accept_mutex)) {

		if (ngx_accept_mutex_held) {
			return IMGZIP_OK;
		}

		if (ngx_enable_accept_events(cycle) == IMGZIP_ERR) {
			ngx_shmtx_unlock(&ngx_accept_mutex);
			return IMGZIP_ERR;
		}

		ngx_accept_mutex_held = 1;

		return IMGZIP_OK;
	}

	if (ngx_accept_mutex_held) {
		if (ngx_disable_accept_events(cycle) == IMGZIP_ERR) {
			return IMGZIP_ERR;
		}

		ngx_accept_mutex_held = 0;
	}

	return IMGZIP_OK;
}

static ngx_int_t ngx_enable_accept_events(ngx_cycle_t *cycle) {
	ngx_listening_t *ls;
	ngx_connection_t *c;

	ls = cycle->listening;

	c = ls->connection;

	if (ngx_epoll_add_event(c->read, EPOLLIN, 0) == IMGZIP_ERR) {
		return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}

static ngx_int_t ngx_disable_accept_events(ngx_cycle_t *cycle) {
	ngx_listening_t *ls;
	ngx_connection_t *c;

	ls = cycle->listening;

	c = ls->connection;

	if (!c->read->active) {
		return IMGZIP_OK;
	}

	if (ngx_epoll_del_event(c->read, EPOLLIN, 0) == IMGZIP_ERR) {
		return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}
static void ngx_close_accepted_connection(ngx_connection_t *c) {
	int fd;

	ngx_free_connection(c);

	fd = c->fd;
	c->fd = (int) -1;

	if (close(fd) == -1) {
		log_print(LOG_LEVEL_DEBUG, "close() failed");
	}

	if (c->pool) {
		ngx_destroy_pool(c->pool);
	}

}

