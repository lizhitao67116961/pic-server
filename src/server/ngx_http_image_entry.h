/*
 * ngx_http_image_entry.h
 *
 *  Created on: 2012-5-30
 *      Author: root
 */
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_http.h"
#ifndef NGX_HTTP_IMAGE_ENTRY_H_
#define NGX_HTTP_IMAGE_ENTRY_H_
#define NGX_HTTP_IMAGE_MAX_SIZE 2097152 //1024*1024*2
#define NGX_HTTP_IMAGE_FILENAME_MAX_SIZE 40
#define NGX_HTTP_IMAGE_URL_MAX_SIZE 200
typedef struct {
	ngx_str_t filename;
	char domain;
	time_t uptime;
	ngx_str_t pic;
	ngx_str_t url;
	ngx_uint_t db_id;
	ngx_uint_t table_id;
	ngx_str_t ext;
	ngx_uint_t width;
	ngx_uint_t height;
	ngx_uint_t cut_start_x;
	ngx_uint_t cut_start_y;
	ngx_uint_t cut_width;
	ngx_uint_t cut_height;
	ngx_uint_t zip_type;
	ngx_uint_t dpi;
	ngx_uint_t water_mark;
	ngx_str_t pic_id;
	ngx_uint_t standard_rui;
	ngx_uint_t operation;
	ngx_uint_t flag;
} ngx_http_image_entry_t;
void ngx_http_image_entry_get_store_info(ngx_http_image_entry_t *e);
ngx_http_image_entry_t * ngx_http_image_entry_create(ngx_http_request_t *r);
#endif /* NGX_HTTP_IMAGE_ENTRY_H_ */
