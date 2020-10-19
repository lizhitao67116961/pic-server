/*
 * Copyright (C) Igor Sysoev
 */

#ifndef _NGX_SOCKET_H_INCLUDED_
#define _NGX_SOCKET_H_INCLUDED_
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include <sys/socket.h>
typedef struct {
	struct sockaddr *sockaddr;
	socklen_t socklen;
	ngx_str_t name;
} ngx_addr_t;

int ngx_nonblocking(int s);
int ngx_blocking(int s);
int ngx_tcp_push(int s);
#endif /* _NGX_SOCKET_H_INCLUDED_ */
