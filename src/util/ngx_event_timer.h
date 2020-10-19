/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "../server/ngx_event.h"
#ifndef _NGX_EVENT_TIMER_H_INCLUDED_
#define _NGX_EVENT_TIMER_H_INCLUDED_

#define NGX_TIMER_INFINITE  (ngx_uint_t) -1

#define NGX_TIMER_LAZY_DELAY  300

ngx_int_t ngx_event_timer_init(void);
ngx_uint_t ngx_event_find_timer(void);
void ngx_event_expire_timers(void);

extern ngx_rbtree_t ngx_event_timer_rbtree;
static inline void ngx_event_del_timer(ngx_event_t *ev) {

	ngx_rbtree_delete(&ngx_event_timer_rbtree, &ev->timer);

	ev->timer_set = 0;
}

static inline void ngx_event_add_timer(ngx_event_t *ev, ngx_uint_t timer) {
	ngx_uint_t key;
	intptr_t diff;

	key = ngx_current_msec + timer;

	if (ev->timer_set) {

		/*
		 * Use a previous timer value if difference between it and a new
		 * value is less than NGX_TIMER_LAZY_DELAY milliseconds: this allows
		 * to minimize the rbtree operations for fast connections.
		 */

		diff = (intptr_t) (key - ev->timer.key);

		if (ngx_abs(diff) < NGX_TIMER_LAZY_DELAY) {
			return;
		}

		ngx_event_del_timer(ev);
	}

	ev->timer.key = key;

	ngx_rbtree_insert(&ngx_event_timer_rbtree, &ev->timer);

	ev->timer_set = 1;
}

#endif /* _NGX_EVENT_TIMER_H_INCLUDED_ */
