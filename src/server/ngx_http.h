/*
 *
 *  Created on: 2013-03-06
 *      Author: lizhitao
 */

#ifndef _NGX_HTTP_H_INCLUDED_
#define _NGX_HTTP_H_INCLUDED_

#include "../imgzip_config.h"
#include "../imgzip_core.h"

#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }

#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

typedef struct ngx_http_request_s ngx_http_request_t;
typedef struct ngx_http_upstream_s ngx_http_upstream_t;
typedef void (*ngx_http_client_body_handler_pt)(ngx_http_request_t *r);

typedef ngx_int_t (*ngx_http_header_handler_pt)(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
typedef u_char *(*ngx_http_log_handler_pt)(ngx_http_request_t *r, ngx_http_request_t *sr, u_char *buf, size_t len);
#include "ngx_http_request.h"
extern ngx_hash_t headers_in_hash;
extern ngx_uint_t ngx_http_max_module;
typedef struct {
	ngx_uint_t code;
	ngx_uint_t count;
	u_char *start;
	u_char *end;
} ngx_http_status_t;

#define ngx_http_get_module_ctx(r, index)  (r)->ctx[index]
#define ngx_http_set_ctx(r, c, index)      r->ctx[index] = c;

void ngx_http_init_connection(ngx_connection_t *c);
ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r, ngx_http_client_body_handler_pt post_handler);
ngx_int_t ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b);
ngx_int_t ngx_http_parse_complex_uri(ngx_http_request_t *r, ngx_uint_t merge_slashes);
ngx_int_t ngx_http_parse_status_line(ngx_http_request_t *r, ngx_buf_t *b, ngx_http_status_t *status);
ngx_int_t ngx_http_parse_unsafe_uri(ngx_http_request_t *r, ngx_str_t *uri, ngx_str_t *args, ngx_uint_t *flags);
ngx_int_t ngx_http_parse_header_line(ngx_http_request_t *r, ngx_buf_t *b, ngx_uint_t allow_underscores);
ngx_int_t ngx_http_parse_multi_header_lines(ngx_array_t *headers, ngx_str_t *name, ngx_str_t *value);
ngx_int_t ngx_http_arg(ngx_http_request_t *r, u_char *name, size_t len, ngx_str_t *value);
void ngx_http_split_args(ngx_http_request_t *r, ngx_str_t *uri, ngx_str_t *args);

void ngx_http_handler(ngx_http_request_t *r);
void ngx_http_run_posted_requests(ngx_connection_t *c);
ngx_int_t ngx_http_post_request(ngx_http_request_t *r, ngx_http_posted_request_t *pr);
void ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
void ngx_http_core_run_phases(ngx_http_request_t *r);
void ngx_http_empty_handler(ngx_event_t *wev);
void ngx_http_request_empty_handler(ngx_http_request_t *r);

#define ngx_http_ephemeral(r)  (void *) (&r->uri_start)

#define NGX_HTTP_LAST   1
#define NGX_HTTP_FLUSH  2

ngx_int_t ngx_http_send_special(ngx_http_request_t *r, ngx_uint_t flags);

ngx_int_t ngx_http_special_response_handler(ngx_http_request_t *r, ngx_int_t error);
ngx_int_t ngx_http_filter_finalize_request(ngx_http_request_t *r, ngx_int_t error);
void ngx_http_clean_header(ngx_http_request_t *r);

time_t ngx_http_parse_time(u_char *value, size_t len);
ngx_int_t ngx_http_init_headers_in_hash(ngx_pool_t *pool);
ngx_int_t ngx_http_discard_request_body(ngx_http_request_t *r);
void ngx_http_discarded_request_body_handler(ngx_http_request_t *r);
void ngx_http_block_reading(ngx_http_request_t *r);
void ngx_http_test_reading(ngx_http_request_t *r);
ngx_int_t ngx_http_header_filter(ngx_http_request_t *r);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in);
ngx_int_t ngx_http_image_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *in);
void ngx_http_rd_check_broken_connection(ngx_http_request_t *r);
void ngx_http_wr_check_broken_connection(ngx_http_request_t *r);
void ngx_http_check_broken_connection(ngx_http_request_t *r, ngx_event_t *ev);
ngx_int_t ngx_http_send_header(ngx_http_request_t *r);
ngx_uint_t ngx_http_access_log_init();
ngx_int_t ngx_http_log_handler(ngx_http_request_t *r);
extern ngx_str_t ngx_http_html_default_types[];

#endif /* _NGX_HTTP_H_INCLUDED_ */
