/*
 * Copyright (C) Igor Sysoev
 */
#include "../imgzip_config.h"
#include "../imgzip_core.h"

#ifndef _NGX_SHMEM_H_INCLUDED_
#define _NGX_SHMEM_H_INCLUDED_


typedef struct {
	u_char *addr;
	size_t size;
	ngx_str_t name;
	ngx_uint_t exists; /* unsigned  exists:1;  */
} ngx_shm_t;

ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
void ngx_shm_free(ngx_shm_t *shm);

#endif /* _NGX_SHMEM_H_INCLUDED_ */