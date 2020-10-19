/*
 *
 *  Created on: 2013-04-05
 *      Author: lizhitao
 */


#ifndef NGX_HTTP_MEMC_RESPONSE_H
#define NGX_HTTP_MEMC_RESPONSE_H

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "../server/ngx_http.h"
#include "../server/ngx_http_upstream.h"
#include "ngx_http_memc_handler.h"
#define NGX_HTTP_MEMC_END   (sizeof(CRLF "END" CRLF) - 1)
#define client_body_buffer_size 409600
#define read_timeout 1000
ngx_int_t ngx_http_memc_process_get_cmd_header(ngx_http_request_t *r);

ngx_int_t ngx_http_memc_get_cmd_filter_init(void *data);

ngx_int_t ngx_http_memc_get_cmd_filter(void *data, ssize_t bytes);

ngx_int_t ngx_http_memc_process_set_header(ngx_http_request_t *r);

ngx_int_t ngx_http_memc_empty_filter_init(void *data);

ngx_int_t ngx_http_memc_empty_filter(void *data, ssize_t bytes);

ngx_int_t ngx_http_memc_process_flush_all_cmd_header(ngx_http_request_t *r);

#endif /* NGX_HTTP_MEMC_RESPONSE_H */

