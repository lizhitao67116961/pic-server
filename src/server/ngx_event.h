/*
 * Copyright (C) Igor Sysoev
 */
#include "../imgzip_config.h"
#include "../imgzip_core.h"


#ifndef _NGX_EVENT_H_INCLUDED_
#define _NGX_EVENT_H_INCLUDED_

#define NGX_INVALID_INDEX  0xd0d0d0d0

struct ngx_event_s {
	void *data;

	unsigned write :1;

	unsigned accept :1;

	/* used to detect the stale events in kqueue, rtsig, and epoll */
	unsigned instance :1;

	unsigned active :1;

	unsigned disabled :1;

	/* the ready event; in aio mode 0 means that no operation can be posted */
	unsigned ready :1;

	unsigned eof :1;
	unsigned error :1;

	unsigned timedout :1;
	unsigned timer_set :1;

	ngx_event_handler_pt handler;

	ngx_uint_t index;

	ngx_rbtree_node_t timer;

	unsigned closed :1;

	/* to test on worker exit */
	unsigned channel :1;
	unsigned resolver :1;

	/* the links of the posted queue */
	ngx_event_t *next;
	ngx_event_t **prev;

};

#include "../util/ngx_event_timer.h"
#include "ngx_event_posted.h"
extern ngx_int_t ngx_accept_disabled;
extern ngx_atomic_t *ngx_connection_counter;
extern ngx_shmtx_t ngx_accept_mutex;
extern ngx_uint_t ngx_accept_mutex_held;
extern ngx_atomic_t *ngx_accept_mutex_ptr;
void ngx_process_events_and_timers(ngx_cycle_t *cycle);
ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle);
ngx_int_t ngx_event_module_init(ngx_cycle_t *cycle);
ngx_int_t ngx_handle_write_event(ngx_event_t *wev);
ngx_int_t ngx_handle_read_event(ngx_event_t *rev);
#endif /* _NGX_EVENT_H_INCLUDED_ */
