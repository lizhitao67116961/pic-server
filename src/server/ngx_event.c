#include "ngx_event.h"
#include "ngx_event_accept.h"
#include "ngx_epoll_module.h"
#include "ngx_connection.h"
#define DEFAULT_CONNECTIONS  512

static ngx_atomic_t connection_counter = 1;
ngx_atomic_t *ngx_connection_counter = &connection_counter;

ngx_atomic_t *ngx_accept_mutex_ptr;
ngx_shmtx_t ngx_accept_mutex;
ngx_uint_t ngx_accept_mutex_held;
uintptr_t ngx_accept_mutex_delay;
ngx_int_t ngx_accept_disabled;

void ngx_process_events_and_timers(ngx_cycle_t *cycle) {
	uintptr_t timer, delta;
	ngx_int_t ngx_epoll_flag = 0;
	timer = ngx_event_find_timer();
	if (ngx_accept_disabled > 0) {
		ngx_accept_disabled--;

	} else {
		if (ngx_trylock_accept_mutex(cycle) == IMGZIP_ERR) {
			return;
		}

		if (ngx_accept_mutex_held) {
			ngx_epoll_flag = 1;
		} else {
			if (timer == NGX_TIMER_INFINITE || timer > ngx_accept_mutex_delay) {
				timer = ngx_accept_mutex_delay;
			}
		}

	}

	delta = ngx_current_msec;

	ngx_epoll_process_events(cycle, timer, ngx_epoll_flag);

	delta = ngx_current_msec - delta;

	if (ngx_posted_accept_events) {
		ngx_event_process_posted(cycle, &ngx_posted_accept_events);
	}

	if (ngx_accept_mutex_held) {
		ngx_epoll_flag = 0;
		ngx_shmtx_unlock(&ngx_accept_mutex);
	}

	if (delta) {
		ngx_event_expire_timers();
	}

	ngx_event_process_posted(cycle, &ngx_posted_events);

}

ngx_int_t ngx_handle_read_event(ngx_event_t *rev) {

	/* kqueue, epoll */
	if (!rev->active && !rev->ready) {
		if (ngx_epoll_add_event(rev, EPOLLIN, EPOLLET) == IMGZIP_ERR)
		{
			log_print(LOG_LEVEL_ERROR, "ngx_handle_read_event() failed");
			return IMGZIP_ERR;
		}
	}

	return IMGZIP_OK;

}

ngx_int_t ngx_handle_write_event(ngx_event_t *wev) {

	/* kqueue, epoll */
	if (!wev->active && !wev->ready) {
		if (ngx_epoll_add_event(wev, EPOLLOUT, EPOLLET) == IMGZIP_ERR)
		{
			log_print(LOG_LEVEL_ERROR, "ngx_handle_write_event() failed");
			return IMGZIP_ERR;
		}
	}

	return IMGZIP_OK;
}

ngx_int_t ngx_event_module_init(ngx_cycle_t *cycle) {
	u_char *shared;
	size_t size, cl;
	ngx_shm_t shm;

	/* cl should be equal or bigger than cache line size */

	cl = 128;

	size = cl /* ngx_accept_mutex */
	+ cl /* ngx_connection_counter */
	+ cl; /* ngx_temp_number */

	shm.size = size;
	shm.name.len = sizeof("pic_shared_zone");
	shm.name.data = (u_char *) "pic_shared_zone";

	if (ngx_shm_alloc(&shm) != IMGZIP_OK) {
		return IMGZIP_ERR;
	}

	shared = shm.addr;

	ngx_accept_mutex_ptr = (ngx_atomic_t *) shared;
	ngx_accept_mutex.spin = (ngx_uint_t) -1;

	if (ngx_shmtx_create(&ngx_accept_mutex, shared) != IMGZIP_OK)
	{
		return IMGZIP_ERR;
	}

	ngx_connection_counter = (ngx_atomic_t *) (shared + 1 * cl);

	(void) ngx_atomic_cmp_set(ngx_connection_counter, 0, 1);

	return IMGZIP_OK;
}

ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle) {
	ngx_uint_t i;
	ngx_event_t *rev, *wev;
	ngx_listening_t *ls;
	ngx_connection_t *c, *next;

	ngx_accept_mutex_held = 0;
	ngx_accept_mutex_delay = 500;

	if (ngx_event_timer_init() == IMGZIP_ERR) {
		return IMGZIP_ERR;
	}
	ngx_epoll_init(cycle, 0);
	cycle->connections = ngx_alloc(sizeof(ngx_connection_t) * cycle->connection_n);
	if (cycle->connections == NULL) {
		return IMGZIP_ERR;
	}

	c = cycle->connections;

	cycle->read_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n);
	if (cycle->read_events == NULL) {
		return IMGZIP_ERR;
	}

	rev = cycle->read_events;
	for (i = 0; i < cycle->connection_n; i++) {
		rev[i].closed = 1;
		rev[i].instance = 1;

	}

	cycle->write_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n);
	if (cycle->write_events == NULL) {
		return IMGZIP_ERR;
	}

	wev = cycle->write_events;
	for (i = 0; i < cycle->connection_n; i++) {
		wev[i].closed = 1;

	}

	i = cycle->connection_n;
	next = NULL;

	do {
		i--;

		c[i].data = next;
		c[i].read = &cycle->read_events[i];
		c[i].write = &cycle->write_events[i];
		c[i].fd = (int) -1;

		next = &c[i];

	} while (i);

	cycle->free_connections = next;
	cycle->free_connection_n = cycle->connection_n;

	/* for each listening socket */
	ls = cycle->listening;
	c = ngx_get_connection(ls->fd);

	if (c == NULL) {
		return IMGZIP_ERR;
	}

	c->listening = ls;
	ls->connection = c;

	rev = c->read;

	rev->accept = 1;

	rev->handler = ngx_event_accept;

	return IMGZIP_OK;
}
