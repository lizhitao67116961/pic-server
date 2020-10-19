/*
 * imgzip_config.h
 *
 *  Created on: 2013-02-9
 *      Author: lizhitao
 */
#ifndef IMGZIP_CONFIG_H_
#define IMGZIP_CONFIG_H_
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#define IMGZIP_OK 0
#define IMGZIP_ERR -1
#define IMGZIP_AGAIN      -2
#define IMGZIP_BUSY       -3
#define IMGZIP_DONE       -4
#define IMGZIP_DECLINED   -5
#define IMGZIP_ABORT      -6
#define IMGZIP_NOT_FIND      -7

#define IMGZIP_SQLDEST_LEN 128

#define ngx_errno                  errno
#define NGX_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#define NGX_INT32_LEN   sizeof("-2147483648") - 1
#define NGX_INT64_LEN   sizeof("-9223372036854775808") - 1
#define ngx_memzero(buf, n)       (void) memset(buf, 0, n)
#define ngx_memset(buf, c, n)     (void) memset(buf, c, n)
#define ngx_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define ngx_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))
#define ngx_atomic_cmp_set(lock, old, set)                                    \
    __sync_bool_compare_and_swap(lock, old, set)

typedef intptr_t ngx_int_t;
typedef uintptr_t ngx_uint_t;

typedef int ngx_err_t;

#endif /* IMGZIP_CONFIG_H_ */
