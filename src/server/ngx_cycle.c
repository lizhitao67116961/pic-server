/*
 * ngx_cycle.c
 *
 *  Created on: 2011-12-21
 *      Author: root
 *      modified by lizt 2012-10-11
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_epoll_module.h"
#include "ngx_connection.h"
#include "ngx_http_upstream.h"
#include "ngx_http.h"
#include <unistd.h>
#include <netinet/in.h>
#define NGX_MAXHOSTNAMELEN  256
volatile ngx_cycle_t *ngx_cycle;

ngx_cycle_t *ngx_init_cycle() {
	ngx_uint_t i, n;
	ngx_pool_t *pool;
	ngx_cycle_t *cycle;
	ngx_shm_zone_t *shm_zone;
	ngx_list_part_t *part;
	ngx_listening_t *ls=NULL;
	ngx_time_t *tp;
	/* force localtime update with a new timezone */
	ngx_timezone_update();

	/* force localtime update with a new timezone */
	tp = ngx_timeofday();
	tp->sec = 0;

	ngx_time_update();
	pool = ngx_create_pool(16384);
	if (pool == NULL) {
		return NULL;
	}

	cycle = ngx_pcalloc(pool, sizeof(ngx_cycle_t));
	if (cycle == NULL) {
		ngx_destroy_pool(pool);
		return NULL;
	}

	cycle->pool = pool;
	n = 1;
	if (ngx_list_init(&cycle->shared_memory, pool, n, sizeof(ngx_shm_zone_t)) != IMGZIP_OK)
	{
		ngx_destroy_pool(pool);
		return NULL;
	}

	ngx_queue_init(&cycle->reusable_connections_queue);

	if (ngx_process == NGX_PROCESS_SIGNALLER) {
		return cycle;
	}

	/* create shared memory */

	part = &cycle->shared_memory.part;
	shm_zone = part->elts;

	for (i = 0; /* void */; i++) {

		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}
			part = part->next;
			shm_zone = part->elts;
			i = 0;
		}

		if (shm_zone[i].shm.size == 0) {
			log_print(LOG_LEVEL_ERROR, "zero size shared memory zone \"%V\"", &shm_zone[i].shm.name);
			goto failed;
		}

		if (ngx_shm_alloc(&shm_zone[i].shm) != IMGZIP_OK) {
			goto failed;
		}

		if (shm_zone[i].init(&shm_zone[i], NULL) != IMGZIP_OK) {
			goto failed;
		}

	}
	if (ngx_http_init_headers_in_hash(cycle->pool) != IMGZIP_OK) {
		goto failed;
	}
	if (ngx_http_upstream_init(cycle->pool) != IMGZIP_OK) {
		goto failed;
	}
	/* handle the listening sockets */
	struct sockaddr_in sa;
	socklen_t socklen = sizeof(struct sockaddr);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(imgzip_server_conf.listen_port); //该套接字对___PORT端口数据进行监听
	sa.sin_addr.s_addr = htonl(INADDR_ANY); //处理来自PC上的任何一块网卡数据
	if ((ls = ngx_create_listening(cycle, &sa, socklen)) == NULL) {
		goto failed;
	}

	ls->addr_ntop = 1;

	ls->handler = ngx_http_init_connection;

	ls->pool_size = 256;
	ls->post_accept_timeout = 5;

	cycle->listening = ls;
	if (ngx_open_listening_sockets(cycle) != IMGZIP_OK) {
		goto failed;
	}

	/* commit the new cycle configuration */
//	cycle->connection_n = 128;
	cycle->connection_n = imgzip_server_conf.worker_connectons;

	/* free the unnecessary shared memory */
	part = &cycle->shared_memory.part;
	shm_zone = part->elts;

	for (n = 0; /* void */; n++) {

		if (n >= part->nelts) {
			if (part->next == NULL) {
				break;
			}
			part = part->next;
			shm_zone = part->elts;
			n = 0;
		}

	}
	ngx_event_module_init(cycle);
	ngx_cycle = cycle;
	return cycle;

	failed:

	if (ls && ls->fd != -1) {
//	if (ls && ls->fd != -1 && ls->open) {
		close(ls->fd);
	}

	return NULL;
}


