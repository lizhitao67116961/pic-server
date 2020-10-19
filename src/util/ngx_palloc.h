/*
 * Copyright (C) Igor Sysoev
 */
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_
/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)

typedef struct ngx_pool_large_s ngx_pool_large_t;

struct ngx_pool_large_s {
	ngx_pool_large_t *next;
	void *alloc;
};
typedef struct {
	u_char *last;
	u_char *end;
	ngx_pool_t *next;
	ngx_uint_t failed;
} ngx_pool_data_t;

struct ngx_pool_s {
	ngx_pool_data_t d;
	size_t max;
	ngx_pool_t *current;
	ngx_chain_t *chain;
	ngx_pool_large_t *large;
};

void *ngx_alloc(size_t size);
void *ngx_calloc(size_t size);

ngx_pool_t *ngx_create_pool(size_t size);
void ngx_destroy_pool(ngx_pool_t *pool);
void ngx_reset_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);
void *ngx_prealloc(ngx_pool_t *pool, void *p, size_t old_size, size_t new_size);
#endif /* _NGX_PALLOC_H_INCLUDED_ */
