/*
 * Copyright (C) Igor Sysoev
 */

#ifndef _NGX_ALLOC_H_INCLUDED_
#define _NGX_ALLOC_H_INCLUDED_
#include "../imgzip_config.h"
#include <stdlib.h>

void *ngx_alloc(size_t size);
void *ngx_calloc(size_t size);

#define ngx_free          free

#define ngx_memalign(alignment, size)  ngx_alloc(size)

extern ngx_uint_t ngx_pagesize;
extern ngx_uint_t ngx_cacheline_size;

#endif /* _NGX_ALLOC_H_INCLUDED_ */
