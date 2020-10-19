/*
 * Copyright (C) Igor Sysoev
 */

#ifndef _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_http.h"
#include "ngx_http_upstream.h"
#include <unistd.h>
typedef struct {
	struct sockaddr *sockaddr;
	socklen_t socklen;
	ngx_str_t name;

	ngx_int_t current_weight;
	ngx_int_t weight;

	ngx_uint_t fails;
	time_t accessed;

	ngx_uint_t max_fails;
	time_t fail_timeout;

	ngx_uint_t down; /* unsigned  down:1; */

} ngx_http_upstream_rr_peer_t;

typedef struct ngx_http_upstream_rr_peers_s ngx_http_upstream_rr_peers_t;

struct ngx_http_upstream_rr_peers_s {
	ngx_uint_t single; /* unsigned  single:1; */
	ngx_uint_t number;
	ngx_str_t *name;
	ngx_http_upstream_rr_peer_t *next;
};

typedef struct {
	ngx_http_upstream_rr_peers_t *peers;
	ngx_uint_t current;
	uintptr_t data;
} ngx_http_upstream_rr_peer_data_t;

ngx_int_t ngx_http_upstream_init_round_robin();
ngx_int_t ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc);
void ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, ngx_uint_t state);
ngx_int_t ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r);

#endif /* _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
