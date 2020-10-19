/*
 * ngx_http_memc_consistent_hash.c
 *
 *  Created on: 2013-4-25
 *      Author: lizhitao
 */
#include "ngx_http_memc_consistent_hash.h"
typedef struct {
	ngx_http_memc_consistent_node_hash_fun hash_fun;
	ngx_uint_t hash_size;
	ngx_uint_t replica_num;
	void **nodes;
} consistent_hash_info;
static consistent_hash_info hash_info;
ngx_int_t ngx_http_memc_consistent_hash_init(ngx_pool_t *pool, ngx_uint_t hash_size, ngx_http_memc_consistent_node_hash_fun hash_fun, void **nodes, ngx_uint_t node_size,
		ngx_uint_t replica_num) {
	ngx_uint_t i;
	hash_info.hash_size = hash_size;
	hash_info.hash_fun = hash_fun;
	hash_info.replica_num = replica_num;
	hash_info.nodes = ngx_palloc(pool, sizeof(void*) * hash_size);
	if (hash_info.nodes == NULL) {
		return IMGZIP_ERR;
	}

	ngx_memzero(hash_info.nodes, sizeof(void*) * hash_size);

	for (i = 0; i < node_size; ++i) {
		hash_info.nodes[i] = nodes[i];
	}
	return IMGZIP_OK;
}

ngx_int_t ngx_http_memc_consistent_hash_add(void *node) {
	ngx_uint_t i;
	ngx_uint_t hash;
	for (i = 0; i < hash_info.replica_num; ++i) {
		hash = hash_info.hash_fun(node, i);
		hash_info.nodes[hash % hash_info.hash_size] = node;
	}
	return IMGZIP_OK;
}

ngx_int_t ngx_http_memc_consistent_hash_remove(void *node) {
	ngx_uint_t i;
	ngx_uint_t hash;
	for (i = 0; i < hash_info.replica_num; ++i) {
		hash = hash_info.hash_fun(node, i);
		hash_info.nodes[hash % hash_info.hash_size] = NULL;
	}
	return IMGZIP_OK;
}

void *ngx_http_memc_consistent_hash_get(ngx_str_t *key, ngx_http_memc_consistent_key_hash_fun hash_fun, ngx_http_memc_consistent_check_node check_fun) {
	ngx_uint_t hash;
	hash = hash_fun(key) % hash_info.hash_size;
	if (hash_info.nodes[hash] && check_fun(hash_info.nodes[hash]) == IMGZIP_OK) {
		return hash_info.nodes[hash];
	}
	return NULL;
}
