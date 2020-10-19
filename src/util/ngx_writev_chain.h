/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "../server/ngx_event.h"
#ifndef _NGX_WRITEV_CHAIN_H_INCLUDED_
#define _NGX_WRITEV_CHAIN_H_INCLUDED_
#define NGX_MAX_SIZE_T_VALUE  9223372036854775807LL
ngx_chain_t *
ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit) ;
#endif
