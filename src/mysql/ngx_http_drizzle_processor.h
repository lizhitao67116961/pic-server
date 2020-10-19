#ifndef NGX_HTTP_DRIZZLE_PROCESSOR_H
#define NGX_HTTP_DRIZZLE_PROCESSOR_H


#include "../imgzip_core.h"
#include "../imgzip_config.h"
#include "../server/ngx_http_upstream.h"
#include "drizzle_client.h"
#include "ngx_http_drizzle_processor.h"
#include "ngx_http_drizzle_module.h"
#include "ngx_http_drizzle_util.h"
#include "../server/ngx_http_image_entry.h"
#include "../server/ngx_http_request.h"
#include "../server/ngx_epoll_module.h"
#include "../util/ngx_event_timer.h"
#include "../server/ngx_http_upstream.h"

ngx_int_t ngx_http_drizzle_process_events(ngx_http_request_t *r);

void ngx_http_upstream_drizzle_done(ngx_http_request_t *r,
        ngx_http_upstream_t *u, drizzle_ctx *dh,
        ngx_int_t rc);

void ngx_http_upstream_drizzle_error(ngx_http_request_t *r,
					ngx_http_upstream_t *u, drizzle_ctx *dh);

void ngx_http_upstream_drizzle_post(ngx_http_request_t *r,
					ngx_http_upstream_t *u, drizzle_ctx *dh, ngx_int_t ret);
#endif /* NGX_HTTP_DRIZZLE_PROCESSOR_H */

