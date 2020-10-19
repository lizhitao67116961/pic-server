/*
 *
 *  Created on: 2013-4-2
 *      Author: lizhitao
 */


#include "ngx_http_memc_request.h"
#include "ngx_http_memc_response.h"
ngx_int_t ngx_http_memc_create_storage_cmd_request(ngx_http_request_t *r) {
	size_t len;
	size_t bytes_len, exptime_len;
	ngx_buf_t *b;
	ngx_chain_t *cl;
	ngx_chain_t **ll;
	ngx_http_memc_ctx_t *ctx;
	ngx_str_t *key, *value;
	ctx = ngx_http_get_module_ctx(r,1);
	key = &ctx->key;

	value = &ctx->value;
	u_char bytes_buf[NGX_INT32_LEN];
	u_char exptime_buf[NGX_INT64_LEN];
	bytes_len = ngx_snprintf(bytes_buf, sizeof(bytes_buf), "%O", value->len) - bytes_buf;
	exptime_len = ngx_snprintf(exptime_buf, sizeof(exptime_buf), "%O", ngx_time()) - exptime_buf;
	len = sizeof("set ") + key->len + sizeof(" ") - 1 + exptime_len + sizeof(" 0 ") - 1 + bytes_len + sizeof(CRLF) - 1;

	b = ngx_create_temp_buf(r->pool, len);
	if (b == NULL) {
		return IMGZIP_ERR;
	}
	cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL) {
		return IMGZIP_ERR;
	}
	cl->buf = b;
	ll = &cl->next;
	r->upstream->request_bufs = cl;                                    //link to request
	b->last = ngx_cpymem(b->last, "set ", sizeof("set ") - 1);
	b->last = ngx_cpymem(b->last, key->data, key->len);
	*b->last++ = ' ';
	b->last = ngx_cpymem(b->last, exptime_buf, exptime_len);
	*b->last++ = ' ';
	*b->last++ = '0';
	*b->last++ = ' ';
	b->last = ngx_cpymem(b->last, bytes_buf, bytes_len);
	*b->last++ = CR;
	*b->last++ = LF;

	b = ngx_calloc_buf(r->pool);
	if (b == NULL) {
		return IMGZIP_ERR;
	}
	b->start = b->pos = value->data;
	b->last = b->end = value->data + value->len;
	b->memory = 1;
	cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL) {
		return IMGZIP_ERR;
	}
	*ll = cl;
	ll = &cl->next;
	cl->buf = b;

	b = ngx_calloc_buf(r->pool);
	if (b == NULL) {
		return IMGZIP_ERR;
	}
	b->start = b->pos = (u_char *) CRLF;
	b->last = b->end = b->start + sizeof(CRLF) - 1;
	b->memory = 1;
	cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL) {
		return IMGZIP_ERR;
	}
	cl->buf = b;
	cl->next = NULL;
	*ll = cl;

	return IMGZIP_OK;
}

ngx_int_t ngx_http_memc_create_get_cmd_request(ngx_http_request_t *r) {
	size_t len;
	ngx_buf_t *b;
	ngx_chain_t *cl;
	ngx_http_memc_ctx_t *ctx;
	ngx_str_t *key;
	ctx = ngx_http_get_module_ctx(r,1);
	key = &ctx->key;
	len = sizeof("get ") - 1 + key->len + sizeof(CRLF) - 1;

	b = ngx_create_temp_buf(r->pool, len);
	if (b == NULL) {
		return IMGZIP_ERR;
	}

	cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL) {
		return IMGZIP_ERR;
	}

	cl->buf = b;
	cl->next = NULL;

	r->upstream->request_bufs = cl;

	*b->last++ = 'g';
	*b->last++ = 'e';
	*b->last++ = 't';
	*b->last++ = ' ';

	b->last = ngx_cpymem(b->last, key->data, key->len);

	*b->last++ = CR;
	*b->last++ = LF;

	return IMGZIP_OK;
}
