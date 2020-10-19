/*
 * imgzip_core.h
 *
 *  Created on: 2013-02-22
 *      Author: lizhitao
 */

#ifndef IMGZIP_CORE_H_
#define IMGZIP_CORE_H_

typedef struct ngx_cycle_s ngx_cycle_t;
typedef struct ngx_pool_s ngx_pool_t;
typedef struct ngx_chain_s ngx_chain_t;
typedef struct ngx_array_s ngx_array_t;
typedef struct ngx_command_s ngx_command_t;
typedef struct ngx_event_s ngx_event_t;
typedef struct ngx_connection_s ngx_connection_t;
typedef struct ngx_listening_s ngx_listening_t;

typedef void (*ngx_event_handler_pt)(ngx_event_t *ev);
typedef void (*ngx_connection_handler_pt)(ngx_connection_t *c);
#define LF     (u_char) 10
#define CR     (u_char) 13
#define CRLF   "\x0d\x0a"
#include "util/log.h"
#include "util/ngx_alloc.h"
#include "util/ngx_palloc.h"
#include "util/ngx_rbtree.h"
#include "util/ngx_string.h"
#include "util/ngx_times.h"
#include "util/ngx_buf.h"
#include "util/ngx_queue.h"
#include "util/ngx_array.h"
#include "util/ngx_shmtx.h"
#include "util/ngx_list.h"
#include "util/ngx_shmem.h"
#include "util/ngx_hash.h"
#include "util/des_help.h"
#include "util/imgzip_conf.h"

#include "server/ngx_cycle.h"
#include "server/ngx_process_cycle.h"
#define ngx_abs(value)       (((value) >= 0) ? (value) : - (value))
#define ngx_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))
#define ngx_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))
#define ngx_path_separator(c)    ((c) == '/')
#define NGX_CLOSE_EVENT    1
struct timeval start,end;
#endif /* IMGZIP_CORE_H_ */
