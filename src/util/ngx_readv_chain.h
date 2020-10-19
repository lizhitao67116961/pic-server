/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "../server/ngx_event.h"
#ifndef _NGX_READV_CHAIN_H_INCLUDED_
#define _NGX_READV_CHAIN_H_INCLUDED_

ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *chain) ;
#endif
