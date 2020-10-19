/*
 *
 *  Created on: 2013-05-17
 *      Author: lizhitao
 */


#ifndef NGX_HTTP_DRIZZLE_HANDLER_H
#define NGX_HTTP_DRIZZLE_HANDLER_H

#include "../imgzip_core.h"
#include "../imgzip_config.h"
#include "../server/ngx_http.h"
#include "../server/ngx_http_upstream.h"
#include "../server/ngx_http_image_entry.h"
#include "drizzle_client.h"

void ngx_http_drizzle_set_libdrizzle_ready(ngx_http_request_t *r);

ngx_int_t ngx_http_drizzle_handler(ngx_http_request_t *r, ngx_http_image_entry_t *entry, ngx_drizzle_callback drizzle_callback);

void ngx_http_drizzle_rev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);

void ngx_http_drizzle_wev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);

#endif /* NGX_HTTP_DRIZZLE_HANDLER_H */
