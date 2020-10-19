
/*
 * ngx_http_memc_handler.h
 *
 *  Created on: 2013-4-2
 *      Author: lizhitao
 */

#ifndef NGX_HTTP_MEMC_HANDLER_H
#define NGX_HTTP_MEMC_HANDLER_H

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "../server/ngx_http.h"

typedef void (*memc_callback)(ngx_http_request_t *r, ngx_int_t rc);

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
	ngx_queue_t cache;
	ngx_queue_t free;
} ngx_http_memc_rr_peer_t;

typedef struct {
	size_t rest;
	ngx_http_request_t *request;
	ngx_str_t key;
	ngx_str_t cmd;
	ngx_str_t value;
	int parser_state;
	ngx_str_t memc_flags_vv;
	memc_callback callback;
	ngx_http_memc_rr_peer_t *rr_peer;
} ngx_http_memc_ctx_t;

ngx_int_t ngx_http_memc_get_handler(ngx_http_request_t *r, ngx_str_t *key, memc_callback callback);
ngx_int_t ngx_http_memc_set_handler(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value, memc_callback callback);
ngx_int_t ngx_http_memc_init();

void ngx_http_memc_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
#endif /* NGX_HTTP_MEMC_HANDLER_H */

