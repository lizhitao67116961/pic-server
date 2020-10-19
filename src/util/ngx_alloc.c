/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_alloc.h"
#include "log.h"
#include <stdlib.h>
#include <unistd.h>
ngx_uint_t ngx_pagesize;
//TODO = getpagesize()
ngx_uint_t ngx_cacheline_size = 64;

void *ngx_alloc(size_t size) {
	void *p;

	p = malloc(size);
	if (p == NULL) {
		log_print(LOG_LEVEL_ERROR, "malloc(%uz) failed", size);
	}

	return p;
}

void *ngx_calloc(size_t size) {
	void *p;

	p = ngx_alloc(size);

	if (p) {
		ngx_memzero(p, size);
	}

	return p;
}

