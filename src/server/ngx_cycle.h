/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_

typedef struct ngx_shm_zone_s ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt)(ngx_shm_zone_t *zone, void *data);
extern volatile ngx_cycle_t  *ngx_cycle;
struct ngx_shm_zone_s {
	void *data;
	ngx_shm_t shm;
	ngx_shm_zone_init_pt init;
	void *tag;
};

struct ngx_cycle_s {
	ngx_pool_t *pool;

	ngx_connection_t *free_connections;
	ngx_uint_t free_connection_n;

	ngx_queue_t reusable_connections_queue;

	ngx_listening_t *listening;
	ngx_list_t shared_memory;

	ngx_uint_t connection_n;

	ngx_connection_t *connections;
	ngx_event_t *read_events;
	ngx_event_t *write_events;

	ngx_uint_t pid;
};
ngx_cycle_t *ngx_init_cycle();
#endif /* _NGX_CYCLE_H_INCLUDED_ */
