/*
 * Copyright (C) Igor Sysoev
 */
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_event.h"

#ifndef _NGX_CHANNEL_H_INCLUDED_
#define _NGX_CHANNEL_H_INCLUDED_


typedef struct {
	ngx_uint_t command;
	pid_t pid;
	ngx_int_t slot;
	int fd;
} ngx_channel_t;

ngx_int_t ngx_write_channel(int s, ngx_channel_t *ch, size_t size);
ngx_int_t ngx_read_channel(int s, ngx_channel_t *ch, size_t size);
ngx_int_t ngx_add_channel_event(ngx_cycle_t *cycle, int fd, ngx_int_t event, ngx_event_handler_pt handler);
void ngx_close_channel(int *fd);

#endif /* _NGX_CHANNEL_H_INCLUDED_ */
