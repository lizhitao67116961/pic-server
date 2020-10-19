/*
 * Copyright (C) Igor Sysoev
 */

#ifndef _NGX_EPOLL_MODULE_H_INCLUDED_
#define _NGX_EPOLL_MODULE_H_INCLUDED_
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include <sys/epoll.h>
ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, uintptr_t timer);
void ngx_epoll_done(ngx_cycle_t *cycle);
ngx_int_t ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
ngx_int_t ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c);
ngx_int_t ngx_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags);
ngx_int_t ngx_epoll_process_events(ngx_cycle_t *cycle, uintptr_t timer, ngx_int_t ngx_epoll_flag);
#endif
