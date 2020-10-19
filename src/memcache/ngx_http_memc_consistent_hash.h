/*
 * ngx_http_memc_consistent_hash.h
 *
 *  Created on: 2013-4-25
 *      Author: lizhitao
 */
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#ifndef NGX_HTTP_MEMC_CONSISTENT_HASH_H_
#define NGX_HTTP_MEMC_CONSISTENT_HASH_H_
typedef ngx_uint_t (*ngx_http_memc_consistent_node_hash_fun)(void *node, int index);
typedef ngx_uint_t (*ngx_http_memc_consistent_key_hash_fun)(ngx_str_t *key);
typedef ngx_uint_t (*ngx_http_memc_consistent_check_node)(void* node);
ngx_int_t ngx_http_memc_consistent_hash_init(ngx_pool_t *pool, ngx_uint_t hash_size, ngx_http_memc_consistent_node_hash_fun hash_fun, void **nodes, ngx_uint_t node_size,
		ngx_uint_t replica_num);
ngx_int_t ngx_http_memc_consistent_hash_add(void *node);
ngx_int_t ngx_http_memc_consistent_hash_remove(void *node);
void *ngx_http_memc_consistent_hash_get(ngx_str_t *key, ngx_http_memc_consistent_key_hash_fun hash_fun, ngx_http_memc_consistent_check_node check_fun);
#endif /* NGX_HTTP_MEMC_CONSISTENT_HASH_H_ */
