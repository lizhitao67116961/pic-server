/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "../server/ngx_event.h"
#ifndef _NGX_READ_H_INCLUDED_
#define _NGX_READ_H_INCLUDED_
ssize_t ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size) ;
#endif
