/*
 * Copyright (C) Igor Sysoev
 */
#include "ngx_palloc.h"
#include "log.h"
#include <stddef.h>
static void *ngx_palloc_block(ngx_pool_t *pool, size_t size);
static void *ngx_palloc_large(ngx_pool_t *pool, size_t size);

ngx_pool_t *ngx_create_pool(size_t size) {
	ngx_pool_t *p;

	p = ngx_memalign(NGX_POOL_ALIGNMENT, size);
	if (p == NULL) {
		return NULL;
	}

	p->d.last = (u_char *) p + sizeof(ngx_pool_t);
	p->d.end = (u_char *) p + size;
	p->d.next = NULL;
	p->d.failed = 0;

	size = size - sizeof(ngx_pool_t);
	p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;

	p->current = p;
	p->chain = NULL;
	p->large = NULL;

	return p;
}

void ngx_destroy_pool(ngx_pool_t *pool) {
	ngx_pool_t *p, *n;
	ngx_pool_large_t *l;

	for (l = pool->large; l; l = l->next) {

		log_print(LOG_LEVEL_DEBUG, "free: %p", l->alloc);

		if (l->alloc) {
			ngx_free(l->alloc);
		}
	}

	for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
		ngx_free(p);

		if (n == NULL) {
			break;
		}
	}
}

void ngx_reset_pool(ngx_pool_t *pool) {
	ngx_pool_t *p;
	ngx_pool_large_t *l;

	for (l = pool->large; l; l = l->next) {
		if (l->alloc) {
			ngx_free(l->alloc);
		}
	}

	pool->large = NULL;

	for (p = pool; p; p = p->d.next) {
		p->d.last = (u_char *) p + sizeof(ngx_pool_t);
	}
}

void *ngx_palloc(ngx_pool_t *pool, size_t size) {
	u_char *m;
	ngx_pool_t *p;

	if (size <= pool->max) {

		p = pool->current;

		do {
			m = ngx_align_ptr(p->d.last, NGX_ALIGNMENT);

			if ((size_t) (p->d.end - m) >= size) {
				p->d.last = m + size;

				return m;
			}

			p = p->d.next;

		} while (p);

		return ngx_palloc_block(pool, size);
	}

	return ngx_palloc_large(pool, size);
}

void *ngx_pnalloc(ngx_pool_t *pool, size_t size) {
	u_char *m;
	ngx_pool_t *p;

	if (size <= pool->max) {

		p = pool->current;

		do {
			m = p->d.last;

			if ((size_t) (p->d.end - m) >= size) {
				p->d.last = m + size;

				return m;
			}

			p = p->d.next;

		} while (p);

		return ngx_palloc_block(pool, size);
	}

	return ngx_palloc_large(pool, size);
}

static void *ngx_palloc_block(ngx_pool_t *pool, size_t size) {
	u_char *m;
	size_t psize;
	ngx_pool_t *p, *new, *current;

	psize = (size_t) (pool->d.end - (u_char *) pool);

	m = ngx_memalign(NGX_POOL_ALIGNMENT, psize);
	if (m == NULL) {
		return NULL;
	}

	new = (ngx_pool_t *) m;

	new->d.end = m + psize;
	new->d.next = NULL;
	new->d.failed = 0;

	m += sizeof(ngx_pool_data_t);
	m = ngx_align_ptr(m, NGX_ALIGNMENT);
	new->d.last = m + size;

	current = pool->current;

	for (p = current; p->d.next; p = p->d.next) {
		if (p->d.failed++ > 4) {
			current = p->d.next;
		}
	}

	p->d.next = new;

	pool->current = current ? current : new;

	return m;
}

static void *ngx_palloc_large(ngx_pool_t *pool, size_t size) {
	void *p;
	ngx_uint_t n;
	ngx_pool_large_t *large;

	p = ngx_alloc(size);
	if (p == NULL) {
		return NULL;
	}

	n = 0;

	for (large = pool->large; large; large = large->next) {
		if (large->alloc == NULL) {
			large->alloc = p;
			return p;
		}

		if (n++ > 3) {
			break;
		}
	}

	large = ngx_palloc(pool, sizeof(ngx_pool_large_t));
	if (large == NULL) {
		ngx_free(p);
		return NULL;
	}

	large->alloc = p;
	large->next = pool->large;
	pool->large = large;

	return p;
}

void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment) {
	void *p;
	ngx_pool_large_t *large;

	p = ngx_memalign(alignment, size);
	if (p == NULL) {
		return NULL;
	}

	large = ngx_palloc(pool, sizeof(ngx_pool_large_t));
	if (large == NULL) {
		ngx_free(p);
		return NULL;
	}

	large->alloc = p;
	large->next = pool->large;
	pool->large = large;

	return p;
}

ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p) {
	ngx_pool_large_t *l;

	for (l = pool->large; l; l = l->next) {
		if (p == l->alloc) {
			log_print(LOG_LEVEL_DEBUG, "free: %p", l->alloc);
			ngx_free(l->alloc);
			l->alloc = NULL;

			return IMGZIP_OK;
		}
	}

	return IMGZIP_ERR;
}

void *ngx_pcalloc(ngx_pool_t *pool, size_t size) {
	void *p;

	p = ngx_palloc(pool, size);
	if (p) {
		ngx_memzero(p, size);
	}

	return p;
}

void *ngx_prealloc(ngx_pool_t *pool, void *p, size_t old_size, size_t new_size) {
	void *new;

	// 如果p为空，则相对于在pool中分配一块新空间并返回指向该空间的指针
	if (p == NULL) {
		return ngx_palloc(pool, new_size);
	}

	// 如果所需重新分配的空间大小为0，则判断旧空间地址是否在pool的最后，
	// 若是，则只需将pool的d.last指针移到旧空间地址的起始位置；
	// 否则，使用ngx_pfree方法是否pool中的旧空间；
	// 最后返回null。
	if (new_size == 0) {
		if ((u_char *) p + old_size == pool->d.last) {
			pool->d.last = p;
		} else {
			ngx_pfree(pool, p);
		}

		return NULL;
	}

	// 如果所需重新分配的空间处于pool的最后，并且pool剩余空间
	// 的大小大于所需分配空间的大小，则只需将pool的d.last指向
	// 新空间的末尾并返回原空间的地址即可。
	if ((u_char *) p + old_size == pool->d.last && (u_char *) p + new_size <= pool->d.end) {
		pool->d.last = (u_char *) p + new_size;
		return p;
	}

	// 如果以上条件均不符合，则需要通过ngx_palloc在pool内分配
	// 一个新的空间，并在将旧空间内的数据拷贝到新空间内之后，
	// 释放掉旧空间，返回新空间地址。
	new = ngx_palloc(pool, new_size);
	if (new == NULL) {
		return NULL;
	}

	memcpy(new, p, old_size);

	ngx_pfree(pool, p);

	return new;
}
