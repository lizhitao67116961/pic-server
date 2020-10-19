/*
 * Copyright (C) Igor Sysoev
 */
#include <semaphore.h>
#include "../imgzip_config.h"

#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_

typedef unsigned long ngx_atomic_uint_t;
typedef volatile ngx_atomic_uint_t ngx_atomic_t;
typedef struct {
	ngx_atomic_t *lock;
	ngx_uint_t semaphore;
	sem_t sem;
	ngx_uint_t spin;
} ngx_shmtx_t;

ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr);
void ngx_shmtx_destory(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);

#endif /* _NGX_SHMTX_H_INCLUDED_ */
