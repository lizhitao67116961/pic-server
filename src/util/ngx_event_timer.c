/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_event_timer.h"

ngx_rbtree_t ngx_event_timer_rbtree;
static ngx_rbtree_node_t ngx_event_timer_sentinel;

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

ngx_int_t ngx_event_timer_init(void) {
	ngx_rbtree_init(&ngx_event_timer_rbtree, &ngx_event_timer_sentinel, ngx_rbtree_insert_timer_value);

	return IMGZIP_OK;
}

ngx_uint_t ngx_event_find_timer(void) {
	ngx_uint_t timer;
	ngx_rbtree_node_t *node, *root, *sentinel;

	if (ngx_event_timer_rbtree.root == &ngx_event_timer_sentinel) {
		return NGX_TIMER_INFINITE;
	}

	root = ngx_event_timer_rbtree.root;
	sentinel = ngx_event_timer_rbtree.sentinel;

	node = ngx_rbtree_min(root, sentinel);

	timer = (ngx_int_t) node->key - (ngx_int_t) ngx_current_msec;

	return (ngx_uint_t) (timer > 0 ? timer : 0);
}

void ngx_event_expire_timers(void) {
	ngx_event_t *ev;
	ngx_rbtree_node_t *node, *root, *sentinel;

	sentinel = ngx_event_timer_rbtree.sentinel;

	for (;;) {

		root = ngx_event_timer_rbtree.root;

		if (root == sentinel) {
			return;
		}

		node = ngx_rbtree_min(root, sentinel);

		/* node->key <= ngx_current_time */

		if ((ngx_int_t) node->key - (ngx_int_t) ngx_current_msec <= 0) {
			ev = (ngx_event_t *) ((char *) node - offsetof(ngx_event_t, timer));

			ngx_rbtree_delete(&ngx_event_timer_rbtree, &ev->timer);

			ev->timer_set = 0;

			ev->timedout = 1;

			ev->handler(ev);

			continue;
		}

		break;
	}

}
