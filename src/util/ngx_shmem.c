/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_shmem.h"
#include <sys/mman.h>
ngx_int_t ngx_shm_alloc(ngx_shm_t *shm) {
	shm->addr = (u_char *) mmap(NULL, shm->size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);

	if (shm->addr == MAP_FAILED) {
		log_print(LOG_LEVEL_ERROR, "mmap(MAP_ANON|MAP_SHARED, %uz) failed", shm->size);
		return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}

void ngx_shm_free(ngx_shm_t *shm) {
	if (munmap((void *) shm->addr, shm->size) == -1) {
		log_print(LOG_LEVEL_ERROR, "munmap(%p, %uz) failed", shm->addr, shm->size);
	}
}
