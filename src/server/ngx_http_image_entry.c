/*
 *
 *  Created on: 2013-04-05
 *      Author: lizhitao
 */



#include "ngx_http_image_entry.h"
#include "../util/md5.h"
static char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
ngx_http_image_entry_t * ngx_http_image_entry_create(ngx_http_request_t *r) {
	ngx_http_image_entry_t *e;
	e = ngx_palloc(r->pool, sizeof(ngx_http_image_entry_t));
	if (e == NULL) {
		return NULL;
	}
	memset(e, 0, sizeof(ngx_http_image_entry_t));
	e->filename.data = ngx_palloc(r->pool, NGX_HTTP_IMAGE_FILENAME_MAX_SIZE);
	if (e->filename.data == NULL) {
		return NULL;
	}
	e->filename.len = 0;
	e->pic.data = ngx_palloc(r->pool, NGX_HTTP_IMAGE_MAX_SIZE);
	if (e->pic.data == NULL) {
		return NULL;
	}
	e->pic.len = 0;
	e->url.data = ngx_palloc(r->pool, NGX_HTTP_IMAGE_URL_MAX_SIZE);
	if (e->url.data == NULL) {
		return NULL;
	}
	e->url.len = 0;
	e->flag = 0;
	return e;
}
static ngx_uint_t inline h2d(u_char *c) {
	if (*c >= 'a' && *c <= 'f') {
		return *c - 'a' + 10;
	} else if (*c >= '0' && *c <= '9') {
		return *c - '0';
	}
	return 0;
}
void ngx_http_image_entry_get_store_info(ngx_http_image_entry_t *e) {
	u_char *c;
	md5_state_t state;
	md5_byte_t digest[16];
	int i, k = 0;
	int ext_len;
	md5_init(&state);
	md5_append(&state, e->url.data, e->url.len);
	md5_finish(&state, digest);
	for (i = 0; i < 16; ++i) {
		e->filename.data[k++] = hex_digits[*(digest + i) >> 4 & 0xf];
		e->filename.data[k++] = hex_digits[*(digest + i) & 0xf];
	}
	ext_len = 8 > e->ext.len ? e->ext.len : 8;
	strncpy((char*) e->filename.data + 32, (char*) e->ext.data, ext_len);
	e->filename.len = 32 + ext_len;
	e->db_id = 0;
	e->table_id = 0;
	c = e->filename.data;
	e->db_id = h2d(c) << 4;
	c++;
	e->db_id |= h2d(c);
	c++;
	e->table_id = h2d(c);
//	printf("e->db_id:%d     e->table_id:%d   filename:%s\n",e->db_id,e->table_id,e->filename.data);
}
