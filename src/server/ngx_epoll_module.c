/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_epoll_module.h"
#include "../util/log.h"
#include "ngx_cycle.h"
#include "ngx_event.h"
#include "ngx_connection.h"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
static int ep = -1;
static struct epoll_event *event_list = NULL;
static ngx_uint_t nevents = 10;

ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, uintptr_t timer) {

	if (ep == -1) {
		ep = epoll_create(cycle->connection_n / 2);

		if (ep == -1) {
			log_print(LOG_LEVEL_ERROR, "epoll_create() failed");
			return IMGZIP_ERR;
		}

	}

	event_list = ngx_alloc(sizeof(struct epoll_event) * nevents);
	if (event_list == NULL) {
		return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}

void ngx_epoll_done(ngx_cycle_t *cycle) {
	if (close(ep) == -1) {
		log_print(LOG_LEVEL_ERROR, "epoll close() failed");
	}

	ep = -1;

	free(event_list);

	event_list = NULL;
	nevents = 0;
}

ngx_int_t ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) {
	int op;
	uint32_t events, prev;
	ngx_event_t *e;
	ngx_connection_t *c;
	struct epoll_event ee;

	c = ev->data;

	events = (uint32_t) event;

	if (event == EPOLLIN) {
		e = c->write;
		prev = EPOLLOUT;

	} else {
		e = c->read;
		prev = EPOLLIN;
	}

	if (e->active) {
		op = EPOLL_CTL_MOD;
		events |= prev;

	} else {
		op = EPOLL_CTL_ADD;
	}

	ee.events = events | (uint32_t) flags;
	ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

	if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
		log_print(LOG_LEVEL_ERROR, "ngx_epoll_add_event(%d, %d) failed", op, c->fd);
		return IMGZIP_ERR;
	}

	ev->active = 1;

	return IMGZIP_OK;
}

ngx_int_t ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) {
	int op;
	uint32_t prev;
	ngx_event_t *e;
	ngx_connection_t *c;
	struct epoll_event ee;

	/*
	 * when the file descriptor is closed, the epoll automatically deletes
	 * it from its queue, so we do not need to delete explicity the event
	 * before the closing the file descriptor
	 */

	if (flags & NGX_CLOSE_EVENT) {
		ev->active = 0;
		return IMGZIP_OK;
	}

	c = ev->data;

	if (event == EPOLLIN) {
		e = c->write;
		prev = EPOLLOUT;

	} else {
		e = c->read;
		prev = EPOLLIN;
	}

	if (e->active) {
		op = EPOLL_CTL_MOD;
		ee.events = prev | (uint32_t) flags;
		ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

	} else {
		op = EPOLL_CTL_DEL;
		ee.events = 0;
		ee.data.ptr = NULL;
	}

	if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
		log_print(LOG_LEVEL_ERROR, "ngx_epoll_del_event(%d, %d) failed", op, c->fd);
		return IMGZIP_ERR;
	}

	ev->active = 0;

	return IMGZIP_OK;
}

ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c) {
	struct epoll_event ee;

	ee.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);
	log_print(LOG_LEVEL_DEBUG, "ngx_epoll_add_connection %d", c->fd);
	if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
		log_print(LOG_LEVEL_ERROR, "ngx_epoll_add_connection(EPOLL_CTL_ADD, %d) failed", c->fd);
		return IMGZIP_ERR;
	}

	c->read->active = 1;
	c->write->active = 1;

	return IMGZIP_OK;
}

ngx_int_t ngx_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags) {
	int op;
	struct epoll_event ee;

	/*
	 * when the file descriptor is closed the epoll automatically deletes
	 * it from its queue so we do not need to delete explicity the event
	 * before the closing the file descriptor
	 */

	if (flags & NGX_CLOSE_EVENT) {
		c->read->active = 0;
		c->write->active = 0;
		return IMGZIP_OK;
	}

	op = EPOLL_CTL_DEL;
	ee.events = 0;
	ee.data.ptr = NULL;

	if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
		log_print(LOG_LEVEL_ERROR, "ngx_epoll_del_connection(%d, %d) failed", op, c->fd);
		return IMGZIP_ERR;
	}

	c->read->active = 0;
	c->write->active = 0;

	return IMGZIP_OK;
}

ngx_int_t ngx_epoll_process_events(ngx_cycle_t *cycle, uintptr_t timer, ngx_int_t ngx_epoll_flag) {
	int events;
	uint32_t revents;
	ngx_int_t instance, i;
	ngx_err_t err;
	ngx_event_t *rev, *wev, **queue;
	ngx_connection_t *c;

	/* NGX_TIMER_INFINITE == INFTIM */
	events = epoll_wait(ep, event_list, (int) nevents, timer);

	err = (events == -1) ? errno : 0;

	ngx_time_update();

	if (err) {
		if (err == EINTR) {
			log_print(LOG_LEVEL_ERROR, "epoll_wait() EINTR");
			return IMGZIP_OK;
		}

		log_print(LOG_LEVEL_ERROR, "epoll_wait() failed");
		return IMGZIP_ERR;
	}

	if (events == 0) {
		if (timer != (uintptr_t) -1) {
			return IMGZIP_OK;
		}

		log_print(LOG_LEVEL_ERROR, "epoll_wait() returned no events without timeout");
		return IMGZIP_ERR;
	}

	for (i = 0; i < events; i++) {
		c = event_list[i].data.ptr;
		instance = (uintptr_t) c & 1;
		c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

		rev = c->read;

		if (c->fd == -1 || rev->instance != instance) {

			/*
			 * the stale event from a file descriptor
			 * that was just closed in this iteration
			 */
			log_print(LOG_LEVEL_DEBUG, "epoll: stale event %p", c);
			continue;
		}

		revents = event_list[i].events;

		if (revents & (EPOLLERR | EPOLLHUP)) {
			log_print(LOG_LEVEL_ERROR, "epoll_wait() error on fd:%d ev:%04XD", c->fd, revents);
		}

		if ((revents & (EPOLLERR | EPOLLHUP)) && (revents & (EPOLLIN | EPOLLOUT)) == 0) {
			/*
			 * if the error events were returned without EPOLLIN or EPOLLOUT,
			 * then add these flags to handle the events at least in one
			 * active handler
			 */

			revents |= EPOLLIN | EPOLLOUT;
		}

		if ((revents & EPOLLIN) && rev->active) {
			rev->ready = 1;
	//		if(ngx_epoll_flag == 1) {
				queue = (ngx_event_t **) (rev->accept ? &ngx_posted_accept_events : &ngx_posted_events);

				ngx_locked_post_event(rev, queue);
	//		}
	/*		else {

				rev->handler(rev);
			}*/
		}

		wev = c->write;

		if ((revents & EPOLLOUT) && wev->active) {
			wev->ready = 1;
	//		if(ngx_epoll_flag == 1){
				ngx_locked_post_event(wev, &ngx_posted_events);
	//		}
	/*		else {

				wev->handler(wev);
			}*/
		}

	}

	return IMGZIP_OK;
}

