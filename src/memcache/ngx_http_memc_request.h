#ifndef NGX_HTTP_MEMC_REQUEST_H
#define NGX_HTTP_MEMC_REQUEST_H

#include "../imgzip_config.h"
#include "../server/ngx_http.h"

ngx_int_t ngx_http_memc_create_get_cmd_request(ngx_http_request_t *r);

ngx_int_t ngx_http_memc_create_storage_cmd_request(ngx_http_request_t *r);

#endif /* NGX_HTTP_MEMC_REQUEST_H */

