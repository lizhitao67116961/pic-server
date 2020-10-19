/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_http.h"
#include <sys/types.h>
#define CRLF   "\x0d\x0a"
static ngx_int_t ngx_http_send_special_response(ngx_http_request_t *r, ngx_uint_t err);
#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

static u_char ngx_http_error_tail[] = "<hr><center>PIC SERVER</center>" CRLF
"</body>" CRLF
"</html>" CRLF;

static char ngx_http_error_301_page[] = "<html>" CRLF
"<head><title>301 Moved Permanently</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>301 Moved Permanently</h1></center>" CRLF;

static char ngx_http_error_302_page[] = "<html>" CRLF
"<head><title>302 Found</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>302 Found</h1></center>" CRLF;

static char ngx_http_error_303_page[] = "<html>" CRLF
"<head><title>303 See Other</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>303 See Other</h1></center>" CRLF;

static char ngx_http_error_400_page[] = "<html>" CRLF
"<head><title>400 Bad Request</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF;

static char ngx_http_error_401_page[] = "<html>" CRLF
"<head><title>401 Authorization Required</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>401 Authorization Required</h1></center>" CRLF;

static char ngx_http_error_402_page[] = "<html>" CRLF
"<head><title>402 Payment Required</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>402 Payment Required</h1></center>" CRLF;

static char ngx_http_error_403_page[] = "<html>" CRLF
"<head><title>403 Forbidden</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>403 Forbidden</h1></center>" CRLF;

static char ngx_http_error_404_page[] = "<html>" CRLF
"<head><title>404 Not Found</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>404 Not Found</h1></center>" CRLF;

static char ngx_http_error_405_page[] = "<html>" CRLF
"<head><title>405 Not Allowed</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>405 Not Allowed</h1></center>" CRLF;

static char ngx_http_error_406_page[] = "<html>" CRLF
"<head><title>406 Not Acceptable</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>406 Not Acceptable</h1></center>" CRLF;

static char ngx_http_error_408_page[] = "<html>" CRLF
"<head><title>408 Request Time-out</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>408 Request Time-out</h1></center>" CRLF;

static char ngx_http_error_409_page[] = "<html>" CRLF
"<head><title>409 Conflict</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>409 Conflict</h1></center>" CRLF;

static char ngx_http_error_410_page[] = "<html>" CRLF
"<head><title>410 Gone</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>410 Gone</h1></center>" CRLF;

static char ngx_http_error_411_page[] = "<html>" CRLF
"<head><title>411 Length Required</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>411 Length Required</h1></center>" CRLF;

static char ngx_http_error_412_page[] = "<html>" CRLF
"<head><title>412 Precondition Failed</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>412 Precondition Failed</h1></center>" CRLF;

static char ngx_http_error_413_page[] = "<html>" CRLF
"<head><title>413 Request Entity Too Large</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>413 Request Entity Too Large</h1></center>" CRLF;

static char ngx_http_error_414_page[] = "<html>" CRLF
"<head><title>414 Request-URI Too Large</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>414 Request-URI Too Large</h1></center>" CRLF;

static char ngx_http_error_415_page[] = "<html>" CRLF
"<head><title>415 Unsupported Media Type</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>415 Unsupported Media Type</h1></center>" CRLF;

static char ngx_http_error_416_page[] = "<html>" CRLF
"<head><title>416 Requested Range Not Satisfiable</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>416 Requested Range Not Satisfiable</h1></center>" CRLF;

static char ngx_http_error_494_page[] = "<html>" CRLF
"<head><title>400 Request Header Or Cookie Too Large</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>Request Header Or Cookie Too Large</center>" CRLF;

static char ngx_http_error_495_page[] = "<html>" CRLF
"<head><title>400 The SSL certificate error</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The SSL certificate error</center>" CRLF;

static char ngx_http_error_496_page[] = "<html>" CRLF
"<head><title>400 No required SSL certificate was sent</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>No required SSL certificate was sent</center>" CRLF;

static char ngx_http_error_497_page[] = "<html>" CRLF
"<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The plain HTTP request was sent to HTTPS port</center>" CRLF;

static char ngx_http_error_500_page[] = "<html>" CRLF
"<head><title>500 Internal Server Error</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>500 Internal Server Error</h1></center>" CRLF;

static char ngx_http_error_501_page[] = "<html>" CRLF
"<head><title>501 Method Not Implemented</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>501 Method Not Implemented</h1></center>" CRLF;

static char ngx_http_error_502_page[] = "<html>" CRLF
"<head><title>502 Bad Gateway</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>502 Bad Gateway</h1></center>" CRLF;

static char ngx_http_error_503_page[] = "<html>" CRLF
"<head><title>503 Service Temporarily Unavailable</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>503 Service Temporarily Unavailable</h1></center>" CRLF;

static char ngx_http_error_504_page[] = "<html>" CRLF
"<head><title>504 Gateway Time-out</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>504 Gateway Time-out</h1></center>" CRLF;

static char ngx_http_error_507_page[] = "<html>" CRLF
"<head><title>507 Insufficient Storage</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>507 Insufficient Storage</h1></center>" CRLF;

static ngx_str_t ngx_http_error_pages[] = {

ngx_null_string, /* 201, 204 */

#define NGX_HTTP_LAST_LEVEL_200  202
#define NGX_HTTP_LEVEL_200       (NGX_HTTP_LAST_LEVEL_200 - 201)

		/* ngx_null_string, *//* 300 */ngx_string(ngx_http_error_301_page), ngx_string(ngx_http_error_302_page), ngx_string(ngx_http_error_303_page),

#define NGX_HTTP_LAST_LEVEL_300  304
#define NGX_HTTP_LEVEL_300       (NGX_HTTP_LAST_LEVEL_300 - 301)

		ngx_string(ngx_http_error_400_page), ngx_string(ngx_http_error_401_page), ngx_string(ngx_http_error_402_page), ngx_string(ngx_http_error_403_page),
				ngx_string(ngx_http_error_404_page), ngx_string(ngx_http_error_405_page), ngx_string(ngx_http_error_406_page), ngx_null_string, /* 407 */
		ngx_string(ngx_http_error_408_page), ngx_string(ngx_http_error_409_page), ngx_string(ngx_http_error_410_page), ngx_string(ngx_http_error_411_page),
				ngx_string(ngx_http_error_412_page), ngx_string(ngx_http_error_413_page), ngx_string(ngx_http_error_414_page), ngx_string(ngx_http_error_415_page),
				ngx_string(ngx_http_error_416_page),

#define NGX_HTTP_LAST_LEVEL_400  417
#define NGX_HTTP_LEVEL_400       (NGX_HTTP_LAST_LEVEL_400 - 400)

		ngx_string(ngx_http_error_494_page), /* 494, request header too large */
		ngx_string(ngx_http_error_495_page), /* 495, https certificate error */
		ngx_string(ngx_http_error_496_page), /* 496, https no certificate */
		ngx_string(ngx_http_error_497_page), /* 497, http to https */
		ngx_string(ngx_http_error_404_page), /* 498, canceled */
		ngx_null_string, /* 499, client has closed connection */

		ngx_string(ngx_http_error_500_page), ngx_string(ngx_http_error_501_page), ngx_string(ngx_http_error_502_page), ngx_string(ngx_http_error_503_page),
				ngx_string(ngx_http_error_504_page), ngx_null_string, /* 505 */
		ngx_null_string, /* 506 */
		ngx_string(ngx_http_error_507_page)

#define NGX_HTTP_LAST_LEVEL_500  508

		};

ngx_int_t ngx_http_special_response_handler(ngx_http_request_t *r, ngx_int_t error) {
	ngx_uint_t err;

	log_print(LOG_LEVEL_DEBUG, "http special response: %d, \"%V?%V\"", error, &r->uri, &r->args);

	r->err_status = error;

	if (r->keepalive) {
		switch (error) {
		case NGX_HTTP_BAD_REQUEST:
		case NGX_HTTP_REQUEST_ENTITY_TOO_LARGE:
		case NGX_HTTP_REQUEST_URI_TOO_LARGE:
		case NGX_HTTP_TO_HTTPS:
		case NGX_HTTPS_CERT_ERROR:
		case NGX_HTTPS_NO_CERT:
		case NGX_HTTP_INTERNAL_SERVER_ERROR:
			r->keepalive = 0;
			break;
		}
	}

	if (r->lingering_close) {
		switch (error) {
		case NGX_HTTP_BAD_REQUEST:
		case NGX_HTTP_TO_HTTPS:
		case NGX_HTTPS_CERT_ERROR:
		case NGX_HTTPS_NO_CERT:
			r->lingering_close = 0;
			break;
		}
	}

	r->headers_out.content_type.len = 0;

	r->expect_tested = 1;

	if (ngx_http_discard_request_body(r) != IMGZIP_OK) {
		error = NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (error == NGX_HTTP_CREATED) {
		/* 201 */
		err = 0;

	} else if (error == NGX_HTTP_NO_CONTENT) {
		/* 204 */
		err = 0;

	} else if (error >= NGX_HTTP_MOVED_PERMANENTLY && error < NGX_HTTP_LAST_LEVEL_300) {
		/* 3XX */
		err = error - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_LEVEL_200;

	} else if (error >= NGX_HTTP_BAD_REQUEST && error < NGX_HTTP_LAST_LEVEL_400) {
		/* 4XX */
		err = error - NGX_HTTP_BAD_REQUEST + NGX_HTTP_LEVEL_200 + NGX_HTTP_LEVEL_300;

	} else if (error >= NGX_HTTP_NGINX_CODES && error < NGX_HTTP_LAST_LEVEL_500) {
		/* 49X, 5XX */
		err = error - NGX_HTTP_NGINX_CODES + NGX_HTTP_LEVEL_200 + NGX_HTTP_LEVEL_300 + NGX_HTTP_LEVEL_400;
		switch (error) {
		case NGX_HTTP_TO_HTTPS:
		case NGX_HTTPS_CERT_ERROR:
		case NGX_HTTPS_NO_CERT:
		case NGX_HTTP_REQUEST_HEADER_TOO_LARGE:
			r->err_status = NGX_HTTP_BAD_REQUEST;
			break;
		}

	} else {
		/* unknown code, zero body */
		err = 0;
	}

	return ngx_http_send_special_response(r, err);
}

ngx_int_t ngx_http_filter_finalize_request(ngx_http_request_t *r, ngx_int_t error) {
	void *ctx;
	ngx_int_t rc;

	ngx_http_clean_header(r);

	ctx = NULL;

	/* clear the modules contexts */
	ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);

	r->filter_finalize = 1;

	rc = ngx_http_special_response_handler(r, error);

	/* IMGZIP_ERR resets any pending data */

	switch (rc) {

	case IMGZIP_OK:
	case IMGZIP_DONE:
		return IMGZIP_ERR;

	default:
		return rc;
	}
}

void ngx_http_clean_header(ngx_http_request_t *r) {
	ngx_memzero(&r->headers_out.status, sizeof(ngx_http_headers_out_t) - offsetof(ngx_http_headers_out_t, status));

	r->headers_out.headers.part.nelts = 0;
	r->headers_out.headers.part.next = NULL;
	r->headers_out.headers.last = &r->headers_out.headers.part;

	r->headers_out.content_length_n = -1;
	r->headers_out.last_modified_time = -1;
}

static ngx_int_t ngx_http_send_special_response(ngx_http_request_t *r, ngx_uint_t err) {
	u_char *tail;
	size_t len;
	ngx_int_t rc;
	ngx_buf_t *b;
	ngx_chain_t out[2];
	len = sizeof(ngx_http_error_tail) - 1;
	tail = ngx_http_error_tail;

	if (ngx_http_error_pages[err].len) {
		r->headers_out.content_length_n = ngx_http_error_pages[err].len + len;

		r->headers_out.content_type_len = sizeof("text/html") - 1;
		ngx_str_set(&r->headers_out.content_type, "text/html");
		r->headers_out.content_type_lowcase = NULL;

	} else {
		r->headers_out.content_length_n = 0;
	}

	if (r->headers_out.content_length) {
		r->headers_out.content_length->hash = 0;
		r->headers_out.content_length = NULL;
	}

	ngx_http_clear_accept_ranges(r);
	ngx_http_clear_last_modified(r);
	rc = ngx_http_send_header(r);

	if (rc == IMGZIP_ERR || r->header_only) {
		return rc;
	}

	if (ngx_http_error_pages[err].len == 0) {
		return ngx_http_send_special(r, NGX_HTTP_LAST);
	}
	b = ngx_calloc_buf(r->pool);
	if (b == NULL) {
		return IMGZIP_ERR;
	}

	b->memory = 1;
	b->pos = ngx_http_error_pages[err].data;
	b->last = ngx_http_error_pages[err].data + ngx_http_error_pages[err].len;

	out[0].buf = b;
	out[0].next = &out[1];

	b = ngx_calloc_buf(r->pool);
	if (b == NULL) {
		return IMGZIP_ERR;
	}

	b->memory = 1;

	b->pos = tail;
	b->last = tail + len;

	out[1].buf = b;
	out[1].next = NULL;

	b->last_buf = 1;

	b->last_in_chain = 1;

	return ngx_http_output_filter(r, &out[0]);
}

