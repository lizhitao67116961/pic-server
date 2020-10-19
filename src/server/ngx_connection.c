/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_connection.h"
#include "../util/log.h"
#include "ngx_epoll_module.h"
#include "ngx_socket.h"
#include "ngx_cycle.h"
#include <unistd.h>
#include <netinet/in.h>
#include <sys/un.h>

static void ngx_drain_connections();
size_t ngx_sock_ntop(struct sockaddr *sa, u_char *text, size_t len, ngx_uint_t port) {
	u_char *p;
	struct sockaddr_in *sin;

	switch (sa->sa_family) {

	case AF_INET:

		sin = (struct sockaddr_in *) sa;
		p = (u_char *) &sin->sin_addr;

		if (port) {
			p = ngx_snprintf(text, len, "%ud.%ud.%ud.%ud:%d", p[0], p[1], p[2], p[3], ntohs(sin->sin_port));
		} else {
			p = ngx_snprintf(text, len, "%ud.%ud.%ud.%ud", p[0], p[1], p[2], p[3]);
		}

		return p - text;

	default:
		return 0;
	}
}
ngx_listening_t *
ngx_create_listening(ngx_cycle_t *cycle, struct sockaddr_in *sockaddr, socklen_t socklen) {
	size_t len;
	ngx_listening_t *ls;
	struct sockaddr *sa;
	u_char text[255];

	ls = ngx_pnalloc(cycle->pool, sizeof(ngx_listening_t));
	if (ls == NULL) {
		return NULL;
	}

	ngx_memzero(ls, sizeof(ngx_listening_t));

	sa = ngx_palloc(cycle->pool, socklen);
	if (sa == NULL) {
		return NULL;
	}

	memcpy(sa, sockaddr, socklen);

	ls->sockaddr = sa;
	ls->socklen = socklen;

	len = ngx_sock_ntop(sa, text, 255, sockaddr->sin_port);
	ls->addr_text.len = len;

	ls->addr_text.data = ngx_pnalloc(cycle->pool, len);
	if (ls->addr_text.data == NULL) {
		return NULL;
	}

	memcpy(ls->addr_text.data, text, len);

	ls->fd = (int) -1;

	ls->backlog = 511;
	ls->rcvbuf = 2048;
	ls->sndbuf = 4096;
	ls->addr_text_max_len=sizeof("255.255.255.255:65535");
	return ls;
}

ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle) {
	int reuseaddr;
	ngx_err_t err;
	int s;
	ngx_listening_t *ls;
	ls = cycle->listening;
	reuseaddr = 1;

	s = socket(ls->sockaddr->sa_family, SOCK_STREAM, 0);

	if (s == -1) {
		log_print(LOG_LEVEL_ERROR, " %V failed", &ls->addr_text);
		return IMGZIP_ERR;
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuseaddr, sizeof(int)) == -1) {
		log_print(LOG_LEVEL_ERROR, "setsockopt(SO_REUSEADDR) %V failed", &ls->addr_text);

		if (close(s) == -1) {
			log_print(LOG_LEVEL_ERROR, " %V failed", &ls->addr_text);
		}

		return IMGZIP_ERR;
	}

	if (ngx_nonblocking(s) == -1) {
		log_print(LOG_LEVEL_ERROR, " %V failed", &ls->addr_text);

		if (close(s) == -1) {
			log_print(LOG_LEVEL_ERROR, " %V failed", &ls->addr_text);
		}

		return IMGZIP_ERR;
	}

	log_print(LOG_LEVEL_DEBUG, "bind() %V #%d ", &ls->addr_text, s);

	if (bind(s, ls->sockaddr, ls->socklen) == -1) {
		err = errno;

		log_print(LOG_LEVEL_ERROR, "bind() to %V failed", &ls->addr_text);

		if (close(s) == -1) {
			log_print(LOG_LEVEL_ERROR, " %V failed", &ls->addr_text);
		}

		return IMGZIP_ERR;
	}

	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const void *) &ls->rcvbuf, sizeof(int)) == -1) {
		log_print(LOG_LEVEL_ERROR, "setsockopt(SO_RCVBUF, %d) %V failed, ignored", ls->rcvbuf, &ls->addr_text);
	}

	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const void *) &ls->sndbuf, sizeof(int)) == -1) {
		log_print(LOG_LEVEL_ERROR, "setsockopt(SO_SNDBUF, %d) %V failed, ignored", ls->sndbuf, &ls->addr_text);
	}

	if (listen(s, ls->backlog) == -1) {
		log_print(LOG_LEVEL_ERROR, "listen() to %V, backlog %d failed", &ls->addr_text, ls->backlog);

		if (close(s) == -1) {
			log_print(LOG_LEVEL_ERROR, " %V failed", &ls->addr_text);
		}

		return IMGZIP_ERR;
	}

	ls->listen = 1;

	ls->fd = s;

	return IMGZIP_OK;
}

void ngx_close_listening_sockets(ngx_cycle_t *cycle) {
	ngx_listening_t *ls;
	ngx_connection_t *c;

	ls = cycle->listening;

	c = ls->connection;

	if (c) {
		if (c->read->active) {

			ngx_epoll_del_event(c->read, EPOLLIN, 0);

		}

		ngx_free_connection(c);

		c->fd = (int) -1;
	}

	log_print(LOG_LEVEL_ERROR, "close listening %V #%d ", &ls->addr_text, ls->fd);

	if (close(ls->fd) == -1) {
		log_print(LOG_LEVEL_ERROR, " %V failed", &ls->addr_text);
	}

	ls->fd = (int) -1;

}

ngx_connection_t *
ngx_get_connection(int s) {
	ngx_uint_t instance;
	ngx_event_t *rev, *wev;
	ngx_connection_t *c;

	/* ngx_mutex_lock */

	c = ngx_cycle->free_connections;

	if (c == NULL) {
		ngx_drain_connections();
		c = ngx_cycle->free_connections;
	}

	if (c == NULL) {
		log_print(LOG_LEVEL_ERROR, "%d worker_connections are not enough", ngx_cycle->connection_n);

		/* ngx_mutex_unlock */

		return NULL;
	}

	ngx_cycle->free_connections = c->data;
	ngx_cycle->free_connection_n--;

	/* ngx_mutex_unlock */

	rev = c->read;
	wev = c->write;

	ngx_memzero(c, sizeof(ngx_connection_t));

	c->read = rev;
	c->write = wev;
	c->fd = s;

	instance = rev->instance;

	ngx_memzero(rev, sizeof(ngx_event_t));
	ngx_memzero(wev, sizeof(ngx_event_t));

	rev->instance = !instance;
	wev->instance = !instance;

	rev->index = NGX_INVALID_INDEX;
	wev->index = NGX_INVALID_INDEX;

	rev->data = c;
	wev->data = c;

	wev->write = 1;

	return c;
}

void ngx_free_connection(ngx_connection_t *c) {
	/* ngx_mutex_lock */

	c->data = ngx_cycle->free_connections;
	ngx_cycle->free_connections = c;
	ngx_cycle->free_connection_n++;

	/* ngx_mutex_unlock */

}

void ngx_close_connection(ngx_connection_t *c) {
	ngx_uint_t log_error;
	int fd;

	if (c->fd == -1) {
		log_print(LOG_LEVEL_ERROR, "connection already closed");
		return;
	}

	if (c->read->timer_set) {
		ngx_event_del_timer(c->read);
	}

	if (c->write->timer_set) {
		ngx_event_del_timer(c->write);
	}

	ngx_epoll_del_connection(c, NGX_CLOSE_EVENT);

	if (c->read->prev) {
		ngx_delete_posted_event(c->read);
	}

	if (c->write->prev) {
		ngx_delete_posted_event(c->write);
	}

	c->read->closed = 1;
	c->write->closed = 1;

	ngx_reusable_connection(c, 0);

	log_error = c->log_error;

	ngx_free_connection(c);

	fd = c->fd;
	c->fd = (int) -1;

	close(fd);
}

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable) {

	if (c->reusable) {
		ngx_queue_remove(&c->queue);
	}

	c->reusable = reusable;

	if (reusable) {
		/* need cast as ngx_cycle is volatile */

		ngx_queue_insert_head((ngx_queue_t *) &ngx_cycle->reusable_connections_queue, &c->queue);
	}
}

static void ngx_drain_connections() {
	ngx_int_t i;
	ngx_queue_t *q;
	ngx_connection_t *c;

	for (i = 0; i < 32; i++) {
		if (ngx_queue_empty(&ngx_cycle->reusable_connections_queue)) {
			break;
		}

		q = ngx_queue_last(&ngx_cycle->reusable_connections_queue);
		c = ngx_queue_data(q, ngx_connection_t, queue);

		c->close = 1;
		c->read->handler(c->read);
	}
}

