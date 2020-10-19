/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_shmtx.h"
#include "log.h"
#include <sched.h>
ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr) {
	mtx->lock = addr;

	if (mtx->spin == (ngx_uint_t) -1) {
		return IMGZIP_OK;
	}

	mtx->spin = 2048;

	if (sem_init(&mtx->sem, 1, 0) == -1) {
		log_print(LOG_LEVEL_DEBUG, "sem_init() failed");
	} else {
		mtx->semaphore = 1;
	}

	return IMGZIP_OK;
}

void ngx_shmtx_destory(ngx_shmtx_t *mtx) {

	if (mtx->semaphore) {
		if (sem_destroy(&mtx->sem) == -1) {
			log_print(LOG_LEVEL_DEBUG, "sem_destroy() failed");
		}
	}

}

ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx) {
	ngx_atomic_uint_t val;

	val = *mtx->lock;
	return ((val & 0x80000000) == 0 && ngx_atomic_cmp_set(mtx->lock, val, val | 0x80000000));
}

void ngx_shmtx_unlock(ngx_shmtx_t *mtx) {
	ngx_atomic_uint_t val, old, wait;

	if (mtx->spin != (ngx_uint_t) -1) {
		log_print(LOG_LEVEL_DEBUG, "shmtx unlock");
	}
	for (;;) {

		old = *mtx->lock;
		wait = old & 0x7fffffff;
		val = wait ? wait - 1 : 0;

		if (ngx_atomic_cmp_set(mtx->lock, old, val)) {
			break;
		}
	}

	if (wait == 0 || !mtx->semaphore) {
		return;
	}

	log_print(LOG_LEVEL_DEBUG, "shmtx wake %XA", old);

	if (sem_post(&mtx->sem) == -1) {
		log_print(LOG_LEVEL_ERROR, "sem_post() failed while wake shmtx");
	}

}

