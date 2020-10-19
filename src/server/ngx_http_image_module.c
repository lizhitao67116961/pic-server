/*
 *
 *  Created on: 2013-03-20
 *      Author: lizhitao
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "../imgzip/imgzip.h"
#include "../memcache/ngx_http_memc_handler.h"
#include "../mysql/ngx_http_drizzle_handler.h"
#include "ngx_http.h"
#include "ngx_connection.h"
#include "ngx_http_upstream.h"
#include "ngx_http_image_entry.h"
#include "../mysql/drizzle_client.h"
#include <arpa/inet.h>
static void ngx_http_memc_get_callback(ngx_http_request_t *r, ngx_int_t rc);
//static void ngx_http_memc_set_callback(ngx_http_request_t *r, ngx_int_t rc);
static ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
static ngx_int_t ngx_http_image_get_content(ngx_http_request_t *r);
static void ngx_http_img_cleanup(void *data);
static void ngx_http_img_blob_cleanup(void *data);
static ngx_int_t ngx_http_img_paser_url(ngx_http_request_t *r, ngx_http_image_entry_t *entry);
static ngx_int_t ngx_http_image_biz_handler(ngx_http_request_t *r);
void ngx_http_image_send_not_find_img(ngx_http_request_t *r);
static ngx_int_t ngx_http_image_get_handler(ngx_http_request_t *r);
static void ngx_http_image_post_handler(ngx_http_request_t *r);
//static ngx_int_t ngx_http_image_delete_handler(ngx_http_request_t *r);
static void ngx_http_image_get_image_id(ngx_http_request_t *r, ngx_str_t *id);
static void ngx_http_image_create_image_id(ngx_str_t *id);
static int ngx_http_image_split(ngx_str_t *values, ngx_uint_t len, ngx_str_t *str, u_char c);
static ngx_int_t ngx_http_image_paser_header(ngx_http_image_entry_t *entry, ngx_str_t *path, ngx_str_t *size, ngx_str_t *cut);
static ngx_int_t ngx_http_image_post_content_handler(ngx_http_request_t *r, ngx_http_image_entry_t *entry);
//static ngx_int_t ngx_check_ip(ngx_http_request_t *r);
ngx_int_t ngx_http_image_content_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);
ngx_int_t ngx_http_drizzle_empty_callback(ngx_http_request_t *r, ngx_http_upstream_t *u){
	return IMGZIP_OK;
	;
}
#define IMG_RC_HEADER_ERR 1
#define IMG_RC_STORE_ERR 2
#define IMG_RC_SIZE_ERR 3
#define IMG_RC_PATH_MAX_SIZE 4
#define IMG_RC_READ_IMAGE_BLOB 5
#define IMG_RC_ZOOM_ERR 6
#define IMG_RC_MAX_SIZE 7
#define IMG_RC_DELETE_ERR 8
static ngx_uint_t create_image_id_max_len = 40;
static ngx_uint_t begin_time = 1262275200000;
static ngx_uint_t img_small_width = 240;
static ngx_uint_t img_small_height = 0;
static ngx_uint_t img_small_zoom_type = ZOOM_BY_HEIGHT;
static ngx_uint_t img_tiny_width = 80;
static ngx_uint_t img_tiny_height = 60;
static ngx_uint_t img_tiny_zoom_type = ZOOM_BY_SMALL_TOP;
static ngx_uint_t ext_max_len = 10;
static ngx_str_t img_small_url = ngx_string("/p1/small/");
static ngx_str_t img_tiny_url = ngx_string("/p1/tiny/");
static ngx_str_t img_big_url = ngx_string("/p1/big/");
static ngx_str_t biz_img_url = ngx_string("/biz/img/");

extern imgzip_http_server_conf_t imgzip_server_conf;
extern ngx_hash_t *hashtable;

//extern ngx_array_t *checkip;

ngx_int_t ngx_http_image_handler(ngx_http_request_t *r) {

	if (r->method == NGX_HTTP_GET) {
		ngx_strlow(r->uri.data, r->uri.data, r->uri.len);
		return ngx_http_image_get_handler(r);
	} else if (r->method == NGX_HTTP_POST) {
		ngx_http_read_client_request_body(r, ngx_http_image_post_handler);
		return IMGZIP_OK;
	} /*else if (r->method == NGX_HTTP_DELETE) {
		return ngx_http_image_delete_handler(r);
	}*/

	return NGX_HTTP_NOT_ALLOWED;
}

static void ngx_http_memc_get_callback(ngx_http_request_t *r, ngx_int_t rc) {
	ngx_http_upstream_t *u;
	ngx_chain_t out;
//	ngx_connection_t *c;
//	c = u->peer.connection;
	u = r->upstream;
	if (rc == IMGZIP_OK && u->headers_in.status_n == NGX_HTTP_OK) {
		r->headers_out.last_modified = u->headers_in.last_modified;
		out.buf = &u->buffer;
		out.next = NULL;
		r->headers_out.content_length_n = u->buffer.last - u->buffer.pos;
		r->headers_out.status = NGX_HTTP_OK;
		rc = ngx_http_send_header(r);

		if (rc == IMGZIP_ERR || rc > IMGZIP_OK || r->header_only) {
			ngx_http_finalize_request(r, rc);
			return;
		}
		ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
		return;
	}

//modified by lizt 2013-03-05
//	ngx_close_connection(c);
//end
	ngx_http_image_get_content(r);
}

/*static void ngx_http_memc_set_callback(ngx_http_request_t *r, ngx_int_t rc) {
	ngx_http_finalize_request(r, IMGZIP_DONE);
}*/
static void ngx_http_img_cleanup(void *data) {
	DestroyMagickWand((MagickWand *) data);
}

static void ngx_http_img_blob_cleanup(void *data) {
	free(data);
}
static ngx_int_t ngx_http_image_get_content(ngx_http_request_t *r) {
	ngx_int_t rc;
	ngx_http_image_entry_t *entry;

	entry = ngx_http_image_entry_create(r);
	entry->operation = 0;
	rc = ngx_http_img_paser_url(r, entry);
	if (rc == IMGZIP_DECLINED) {
		ngx_http_image_send_not_find_img(r);
		return IMGZIP_OK;
	}
	if (rc != IMGZIP_OK) {
		return IMGZIP_ERR;
	}
	ngx_http_image_entry_get_store_info(entry);
	gettimeofday(&start,NULL);
	rc = ngx_http_drizzle_handler(r, entry, ngx_http_image_content_handler);
	if (rc == IMGZIP_NOT_FIND) {
		ngx_http_image_send_not_find_img(r);
		return IMGZIP_OK;
	}
	if (rc == IMGZIP_AGAIN) {
		return IMGZIP_AGAIN;
	}
	if (rc != IMGZIP_OK) {
		return IMGZIP_ERR;
	}
	return IMGZIP_OK;
}

ngx_int_t ngx_http_image_content_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
//	ngx_connection_t       *c;
	ngx_http_image_entry_t *entry;
	MagickWand									*img;
	ngx_http_cleanup_t     *cln;
	ngx_buf_t              *b;
	ngx_chain_t            out;
	ngx_str_t              value;
	int 														i;

//	c = u->peer.connection;
	entry = u->peer.data;
	entry->pic.data = u->buffer.pos;
	entry->pic.len = u->buffer.last - u->buffer.pos;
	if (entry->pic.len == 0){
		ngx_http_image_send_not_find_img(r);
		return IMGZIP_OK;
	}
	if (entry->standard_rui == 0) {

			img = NewMagickWand();
			MagickSetCompressionQuality(img,90);
			i = MagickReadImageBlob(img, entry->pic.data, entry->pic.len);
			if (i == 0) {
				log_print(LOG_LEVEL_ERROR, "MagickReadImageBlob failed!");
				goto failed;
			}
			char *fmt = MagickGetImageFormat(img);
			if (strcmp(fmt, "GIF") == 0) {
				MagickWand *new = MagickCoalesceImages(img);
				if (new) {
					DestroyMagickWand(img);
					img = new;
				}
			}
			free(fmt);
			if (img == NULL) {
				log_print(LOG_LEVEL_ERROR, "MagickCoalesceImages failed!");
				goto failed;
			}

			if (imgZoom(img, entry->width, entry->height, entry->zip_type) == IMGZIP_ERR) {
				log_print(LOG_LEVEL_ERROR, "imgZoom failed!");
				goto failed;
			}

			if (entry->cut_width > 0 && entry->cut_height > 0) {
				if (imgCut(img, entry->cut_start_x, entry->cut_start_y, entry->cut_width, entry->cut_height) == IMGZIP_ERR) {
					log_print(LOG_LEVEL_ERROR, "imgCut failed!");
					i = IMG_RC_ZOOM_ERR;
					goto failed;
				}
			}
			if (entry->water_mark) {
				i = imgAddWater(img, entry->water_mark);
				if (i == IMGZIP_ERR) {
					log_print(LOG_LEVEL_ERROR, "imgAddWater failed!");
				}
			}
			cln = ngx_http_cleanup_add(r, 0);
			if (cln == NULL) {
				goto failed;
			}
			cln->handler = ngx_http_img_cleanup;
			cln->data = img;

			value.data = MagickWriteImageBlob(img, &value.len);
			if (value.data == NULL || value.len == 0) {
				log_print(LOG_LEVEL_ERROR, "MagickWriteImageBlob failed!");
				goto failed;
			}
			cln = ngx_http_cleanup_add(r, 0);
			if (cln == NULL) {
				goto failed;
			}
			cln->handler = ngx_http_img_blob_cleanup;
			cln->data = value.data;
	}
	else {
		value.data = entry->pic.data;
		value.len = entry->pic.len;
	}

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = value.len; //
	r->headers_out.last_modified_time = ngx_time(); //
	r->headers_out.status = NGX_HTTP_OK;
	r->allow_ranges = 1;

	i = ngx_http_send_header(r);

	if (i == IMGZIP_ERR || i > IMGZIP_OK || r->header_only) {
		ngx_http_finalize_request(r, i);
		return IMGZIP_OK;
	}

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		goto failed;
	}

	b->pos = (u_char *) value.data;
	b->last = (u_char *) value.data + value.len;
	b->memory = 1;
	b->last_buf = 1;

	out.buf = b;
	out.next = NULL;

//	if (c->read->timer_set){
//		ngx_event_del_timer(c->read);
//	}
//	if (c->write->timer_set){
//		ngx_event_del_timer(c->write);
//	}
//	ngx_close_connection(c);

	ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
	gettimeofday(&end,NULL);
	float time;
	time = end.tv_sec*1000000-start.tv_sec*1000000+end.tv_usec-start.tv_usec;
//	printf("time used: %f\n",time);
	return IMGZIP_OK;
	failed:
	printf("this is failed field\n");
//	ngx_close_connection(c);
	ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	return IMGZIP_OK;
}

static ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r) {

//	if (r->headers_out.content_type.len) {
//		return IMGZIP_OK;
//	}
//
//	r->headers_out.content_type.len = 10;
//	r->headers_out.content_type.data = (u_char*) "image/jpeg";
//
//	return IMGZIP_OK;


	if (r->headers_out.content_type.len) {
		return IMGZIP_OK;
	}
	ngx_uint_t k;
	ngx_str_t *rst;
//	r->headers_out.content_type.len = 10;
//	r->headers_out.content_type.data = (u_char*) "image/jpeg";
	k = ngx_hash_key_lc(r->exten.data,r->exten.len);
	rst = ngx_hash_find(hashtable,k,r->exten.data,r->exten.len);

	if(rst == NULL)
	{
		r->headers_out.content_type.len = 10;
		r->headers_out.content_type.data = (u_char*) "image/jpeg";
	}
	else
	{
		r->headers_out.content_type.data = rst->data;
		r->headers_out.content_type.len = rst->len;
	}

	return IMGZIP_OK;
}
static ngx_int_t ngx_http_img_paser_url(ngx_http_request_t *r, ngx_http_image_entry_t *entry) {
	int len = 0;
	ngx_int_t rc;
	u_char *p, *uri_offset = 0, *url_id_start, *url_id_end, *end_offset;
	ngx_str_t *uri;
	uri = &r->uri;
	p = r->uri.data;
	entry->standard_rui = 0;
	end_offset = r->uri.data + r->uri.len;
	if (uri->len > img_small_url.len && strncmp((char*) uri->data, (char*) img_small_url.data, img_small_url.len) == 0) {
		entry->width = img_small_width;
		entry->height = img_small_height;
		entry->zip_type = img_small_zoom_type;
		p += img_small_url.len;
	/*	if(imgzip_server_conf.little_access_mysql) {
			strncpy((char*) entry->url.data, (char*) img_big_url.data, img_big_url.len);
			entry->url.len = img_big_url.len;
			entry->standard_rui = 1;
		}
		else {*/
			strncpy((char*) entry->url.data, (char*) img_big_url.data, img_big_url.len);
			entry->url.len = img_big_url.len;
//		}
		goto p1_start;
	}
	if (uri->len > img_tiny_url.len && strncmp((char*) uri->data, (char*) img_tiny_url.data, img_tiny_url.len) == 0) {
		entry->width = img_tiny_width;
		entry->height = img_tiny_height;
		entry->zip_type = img_tiny_zoom_type;
		p += img_tiny_url.len;
		if (imgzip_server_conf.little_access_mysql) {
			strncpy((char*) entry->url.data, (char*) img_tiny_url.data, img_tiny_url.len);
			entry->url.len = img_tiny_url.len;
			entry->standard_rui = 1;
		}
		else {
			strncpy((char*) entry->url.data, (char*) img_big_url.data, img_big_url.len);
			entry->url.len = img_big_url.len;
		}
		goto p1_start;
	}
	p = end_offset - 1;
	for (; p >= uri->data; --p) {
		if (*p == '/') {
			break;
		}
	}
	if (*p++ != '/' || *p++ != 'n' || *p++ != '_') {
		return IMGZIP_DECLINED;
	}
	url_id_start = p;
	for (; p < end_offset; ++p) {
		if (*p == '_' || *p == '.') {
			break;
		} else if (*p > '9' || *p < '0') {
			return IMGZIP_DECLINED;
		}
	}
	url_id_end = p;
	if (*p == '.') {
		strncpy((char*) entry->url.data, (char*) uri->data, end_offset - uri->data);
		entry->url.len = end_offset - uri->data;
		entry->ext.data = entry->url.data + (p - uri->data);
		entry->ext.len = end_offset - p;
		entry->standard_rui = 1;
		return IMGZIP_OK;
	}
	strncpy((char*) entry->url.data, (char*) uri->data, p - uri->data);
	entry->url.len = p - uri->data;
	uri_offset = ++p;
	for (; p < end_offset; ++p) {
		if (*p == '_' || *p == '.') {
			break;
		} else if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))) {
			return IMGZIP_DECLINED;
		}
	}
	if (*p == '_') {
		entry->width = ngx_atoof(uri_offset, p - uri_offset);
		++p;
		uri_offset = p;
		for (; p < end_offset; ++p) {
			if (*p == '_' || *p == '.') {
				break;
			} else if (!(*p >= '0' && *p <= '9')) {
				return IMGZIP_DECLINED;
			}
		}
		if (*p == '.') {
			entry->height = ngx_atoof(uri_offset, p - uri_offset);
			entry->ext.data = entry->url.data + entry->url.len;
			entry->ext.len = end_offset - p;
			strncpy((char*) entry->url.data + entry->url.len, (char*) p, end_offset - p);
			entry->url.len = entry->url.len + (end_offset - p);
			return IMGZIP_OK;
		}
		return IMGZIP_DECLINED;
	} else if (*p == '.') {
		len = p - uri_offset;
		u_char img_info[len]; //
		rc = img_url_decode(url_id_start, url_id_end - url_id_start, uri_offset, p - uri_offset, img_info);
		if (rc != IMGZIP_OK) {
			return IMGZIP_DECLINED;
		}
		if (img_info[0] != 5) {
			return IMGZIP_DECLINED;
		}
		entry->zip_type = img_info[1];
		entry->water_mark = img_info[2];
		entry->dpi = img_info[3];
		entry->width = img_info[5] << 8 | img_info[4];
		entry->height = img_info[7] << 8 | img_info[6];
		if (len > 16) {
			entry->cut_start_x = img_info[9] << 8 | img_info[8];
			entry->cut_start_y = img_info[11] << 8 | img_info[10];
			entry->cut_width = img_info[13] << 8 | img_info[12];
			entry->cut_height = img_info[15] << 8 | img_info[14];
		}
		entry->ext.data = entry->url.data + entry->url.len;
		entry->ext.len = end_offset - p;
		strncpy((char*) entry->url.data + entry->url.len, (char*) p, end_offset - p);
		entry->url.len = entry->url.len + (end_offset - p);

		return IMGZIP_OK;
	}
	return IMGZIP_DECLINED;

	p1_start: ;
	strncpy((char*) entry->url.data + entry->url.len, (char*) p, end_offset - p);
	entry->url.len += end_offset - p;
	for (p = entry->url.data + entry->url.len - 1; p > entry->url.data; --p) {
		if (*p == '.') {
			break;
		}
	}
	if (*p == '.') {
		entry->ext.data = p;
		entry->ext.len = entry->url.data + entry->url.len - p;
	} else {
		return IMGZIP_DECLINED;
	}
	return IMGZIP_OK;
}
void ngx_http_image_send_not_find_img(ngx_http_request_t *r) {
	int len;
	int site_id;
	ngx_int_t rc;
	ngx_buf_t *b;
	ngx_chain_t out;
	ngx_table_elt_t *h;
	char *data;
	if (r->headers_in.host) {
		if (ngx_strstrn(r->headers_in.host->value.data, "kuche.com", sizeof("kuche.com") - 1)) {
			site_id = 1;
		} else if (ngx_strstrn(r->headers_in.host->value.data, "taofan.com", sizeof("taofan.com") - 1)) {
			site_id = 2;
		} else {
			site_id = 0;
		}
	} else {
		site_id = 0;
	}
	data = getNotFoundImage(site_id, &len);
	h = ngx_list_push(&r->headers_out.headers);
	if (h == NULL) {
		goto failed;
	}

	h->hash = 1;
	ngx_str_set(&h->key, "isdefault");
	ngx_str_set(&h->value, "1");
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.last_modified_time = ngx_time(); //
	r->headers_out.status = NGX_HTTP_OK;
	r->allow_ranges = 1;
	r->headers_out.content_length_n = len;
	rc = ngx_http_send_header(r);

	if (rc == IMGZIP_ERR || rc > IMGZIP_OK || r->header_only) {
		ngx_http_finalize_request(r, rc);
		return;
	}

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		goto failed;
	}
	b->pos = (u_char *) data;
	b->last = (u_char *) data + len;

	out.buf = b;
	out.next = NULL;

	ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
	return;
	failed: ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
}
static ngx_int_t ngx_http_image_biz_handler(ngx_http_request_t *r) {
	ngx_str_t pk;
	ngx_int_t rc;
	ngx_str_t id;
	rc = ngx_http_arg(r, (u_char*) "pk", 2, &pk);
	if (rc != IMGZIP_OK) {
		return NGX_HTTP_FORBIDDEN;
	}

	ngx_http_image_get_image_id(r, &id);
	if (id.len == 0) {
		return NGX_HTTP_FORBIDDEN;
	}
	rc = img_biz_url_decode(&pk, &id);
	if (rc != IMGZIP_OK) {
		return NGX_HTTP_FORBIDDEN;
	}
	ngx_http_image_get_content(r);
	return IMGZIP_OK;
}
static ngx_int_t ngx_http_image_get_handler(ngx_http_request_t *r) {
	ngx_int_t rc;
	rc = ngx_http_discard_request_body(r);

	if (rc != IMGZIP_OK) {
		return rc;
	}
	r->read_event_handler = ngx_http_rd_check_broken_connection;
	r->write_event_handler = ngx_http_wr_check_broken_connection;

	if (ngx_http_set_content_type(r) != IMGZIP_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (r->uri.len > biz_img_url.len && strncmp((char*) r->uri.data, (char*) biz_img_url.data, biz_img_url.len) == 0) {
		return ngx_http_image_biz_handler(r);
	}

/*	if (r->uri.len > img_tiny_url.len && strncmp((char*)r->uri.data, (char*)img_tiny_url.data, img_tiny_url.len) == 0) {
		rc = ngx_http_memc_get_handler(r, &r->uri, ngx_http_memc_get_callback);
		if (rc != IMGZIP_DONE) {
			return rc;
		}
		//modified by lizt 2013-03-05
//		if (r->upstream && r->upstream->peer.connection) {
//			printf("I have close it\n");
//			ngx_close_connection(r->upstream->peer.connection);
//		}
		//end
	}*/

	if (r->uri.len > img_tiny_url.len && strncmp((char*) r->uri.data, (char*) img_tiny_url.data, img_tiny_url.len) == 0) { //get时直接返回了
		 return ngx_http_memc_get_handler(r, &r->uri, ngx_http_memc_get_callback);
	}

	return ngx_http_image_get_content(r);
}

static void ngx_http_image_post_handler(ngx_http_request_t *r) {
	ngx_str_t pic_size[10];
	ngx_str_t pic_path[10];
	ngx_str_t pic_cut[10];
	ngx_http_image_entry_t *entry;
	ngx_uint_t version;
	ngx_uint_t upload_pic_num = 0;
	int *upload_pic_len;
	u_char *p;
	ngx_uint_t pic_size_len, pic_path_len, pic_cut_len, i;
	ngx_int_t rc;
	ngx_table_elt_t *h;

	entry = ngx_http_image_entry_create(r);
	entry->operation = 1;
	entry->pic_id.len = create_image_id_max_len;
	entry->pic_id.data = ngx_palloc(r->pool, create_image_id_max_len);
	size_t ext_len = 0;
	if (!r->headers_in.file_extensions) {
		rc = IMG_RC_HEADER_ERR;
		goto failed;
	}
	ext_len = r->headers_in.file_extensions->value.len + 1;
	if (ext_len > ext_max_len) {
		rc = IMG_RC_HEADER_ERR;
		goto failed;
	}
	if (r->headers_in.pic_size == NULL || r->headers_in.pic_path == NULL) {
		rc = IMG_RC_HEADER_ERR;
		goto failed;
	}
	if (r->headers_in.content_length_n < 2) {
		rc = IMG_RC_HEADER_ERR;
		goto failed;
	}
	ngx_http_image_create_image_id(&entry->pic_id);
	entry->uptime = ngx_time();
	entry->ext.data = ngx_pcalloc(r->pool, ext_max_len);
	*entry->ext.data = '.';
	strncpy((char*) entry->ext.data + 1, (char*) r->headers_in.file_extensions->value.data, r->headers_in.file_extensions->value.len);
	entry->ext.len = ext_len;
	ngx_strlow(entry->ext.data, entry->ext.data, entry->ext.len);
	if (r->headers_in.domain) {
		entry->domain = ngx_atoi(r->headers_in.domain->value.data, r->headers_in.domain->value.len);
	} else {
		entry->domain = 0;
	}

	ngx_strlow(r->headers_in.pic_path->value.data, r->headers_in.pic_path->value.data, r->headers_in.pic_path->value.len);
	if (r->headers_in.ismerge && r->headers_in.ismerge->value.len > 0 && *r->headers_in.ismerge->value.data == '1') {
		version = r->request_body->buf->pos[0];
//		printf("version1 is %d\n",version);
		upload_pic_num = r->request_body->buf->pos[1];
//		printf("upload_pic_num1 is %d\n",upload_pic_num);
//		upload_pic_num = r->request_body->buf->pos[1];
//		version = r->request_body->buf->pos[0] - 48;
//		printf("version2 is %d\n",version);
//		upload_pic_num = r->request_body->buf->pos[1] - 48;
		if (upload_pic_num == 0 || r->headers_in.content_length_n <= 2 + 4 * upload_pic_num) {
			rc = IMG_RC_HEADER_ERR;
			goto failed;
		}
		upload_pic_len = (int *) (r->request_body->buf->pos + 2);
		r->request_body->buf->pos += 2 + 4 * upload_pic_num;
		pic_size_len = ngx_http_image_split(pic_size, 10, &r->headers_in.pic_size->value, ',');
		pic_path_len = ngx_http_image_split(pic_path, 10, &r->headers_in.pic_path->value, ',');
		if (r->headers_in.pic_cut) {
			pic_cut_len = ngx_http_image_split(pic_cut, 10, &r->headers_in.pic_cut->value, ',');
		} else {
			pic_cut_len = 0;
		}
		if (pic_size_len == pic_path_len && (pic_size_len == pic_cut_len || pic_cut_len == 0)) {
			for (i = 0; i < pic_size_len; ++i) {
				entry->pic.data = r->request_body->buf->pos;
				if (r->request_body->buf->pos + upload_pic_len[i] <= r->request_body->buf->last) {
					entry->pic.len = upload_pic_len[i];
				} else {
					rc = IMG_RC_HEADER_ERR;
					goto failed;
				}
				rc = ngx_http_image_paser_header(entry, pic_path + i, pic_size + i, pic_cut_len ? pic_cut + i : NULL);
				if (rc != IMGZIP_OK) {
					goto failed;
				}
				rc = ngx_http_image_post_content_handler(r, entry);
				if (rc != IMGZIP_OK) {
					goto failed;
				}
				r->request_body->buf->pos += upload_pic_len[i];
			}
		} else {
			rc = IMG_RC_HEADER_ERR;
			goto failed;
		}
	} else {
		entry->pic.data = r->request_body->buf->pos;
		entry->pic.len = r->request_body->buf->last - r->request_body->buf->pos;
		rc = ngx_http_image_paser_header(entry, &r->headers_in.pic_path->value, &r->headers_in.pic_size->value, r->headers_in.pic_cut ? &r->headers_in.pic_cut->value : NULL);
		if (rc != IMGZIP_OK) {
			goto failed;
		}
		rc = ngx_http_image_post_content_handler(r, entry);
		if (rc == IMGZIP_AGAIN) {
			return ;
		}
		if (rc != IMGZIP_OK) {
			goto failed;
		}
	}
	return ;
	failed:
	h = ngx_list_push(&r->headers_out.headers);
	if (h == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	h->hash = 1;
	ngx_str_set(&h->key, "Status");
	h->value.data = ngx_palloc(r->pool, 3);
	if (h->value.data == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	p = ngx_sprintf(h->value.data, "%01d", rc);
	h->value.len = p - h->value.data;
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.last_modified_time = ngx_time(); //
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_type.len = sizeof("text/html") - 1;
	r->headers_out.content_type.data = (u_char*) "text/html";
	r->allow_ranges = 1;
	r->headers_out.content_length_n = 0;
	ngx_http_finalize_request(r, ngx_http_send_header(r));
}
/*static ngx_int_t ngx_http_image_delete_handler(ngx_http_request_t *r)
{
	int rc;
	ngx_buf_t *b;
	ngx_chain_t out;
	ngx_http_image_entry_t *entry;

	//TODO 判断客户端是否有权限删除某个指定图片
//	if(ngx_check_ip(r) == IMGZIP_OK)
//	{
			entry = ngx_http_image_entry_create(r);
			rc = ngx_http_img_paser_url(r, entry);
			if (rc == IMGZIP_DECLINED) {
				ngx_http_image_send_not_find_img(r);
				return IMGZIP_OK;
			}
			ngx_http_image_entry_get_store_info(entry);
	 	 rc = mysql_client_image_delete(entry);
	 	 if(rc != IMGZIP_OK)
	 	  {
		 	 return IMG_RC_DELETE_ERR;
       	   }
	 	 r->headers_out.status = NGX_HTTP_OK;
	 	 r->headers_out.last_modified_time = ngx_time();
	 	 r->allow_ranges = 1;
	 	 r->headers_out.content_type.len = sizeof("text/html") - 1;
	 	 r->headers_out.content_type.data = (u_char *) "text/html";
	 	 r->headers_out.content_length_n = sizeof("imgzip delete ok") - 1;
	 	 rc = ngx_http_send_header(r);
	 	 if (rc == IMGZIP_ERR || rc > IMGZIP_OK || r->header_only) {
		     ngx_http_finalize_request(r, rc);
		   return rc;
	 	 }
	 	 b = (ngx_buf_t*)ngx_palloc(r->pool, sizeof(ngx_buf_t));
	 	 if (b == NULL)
	 	 {
	 		 ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	 		 return IMGZIP_DECLINED;
	 	 }
	 	 b->pos = (u_char *) "imgzip delete ok";
	 	 b->last = b->pos + r->headers_out.content_length_n;
	 	 b->memory = 1;
	 	 b->last_buf = 1;
	 	 out.buf = b;
	 	 out.next = NULL;
	 	 ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
//	}
//	else
//	{
//		r->headers_out.status = NGX_HTTP_BAD_REQUEST;
//		r->headers_out.content_type.len = sizeof("text/html") - 1;
//		r->headers_out.content_type.data = (u_char *) "text/html";
//		r->allow_ranges = 1;
//		r->headers_out.last_modified_time = ngx_time();
//		return NGX_HTTP_NOT_ALLOWED;
//	}

	return rc;
}*/

static void ngx_http_image_get_image_id(ngx_http_request_t *r, ngx_str_t *id) {
	u_char *p;
	for (p = r->uri.data + r->uri.len; p >= r->uri.data; --p) {
		if (*p == '/') {
			break;
		}
	}
	if (*p++ == '/' && *p++ == 'n' && *p++ == '_') {
		id->data = p;
		while (*p >= '0' && *p <= '9') {
			++p;
		}
		id->len = p - id->data;
	} else {
		id->data = NULL;
		id->len = 0;
	}

}

static void ngx_http_image_create_image_id(ngx_str_t *id) {
	u_char height;
	unsigned long l;
	int p;
	ngx_time_t *tp = ngx_timeofday();
	u_char *offset = id->data;
	p = ngx_cycle->pid << 8;
	l = tp->sec * 1000 + tp->msec;
	l -= begin_time;
	height = l >> 56;
	l = l << 24;
	l |= p;
	l |= imgzip_server_conf.server_id;
	if (height > 0) {
		offset = ngx_sprintf(offset, "n_%ul", height);
		offset = ngx_sprintf(offset, "%ul", l);
	} else {
		offset = ngx_sprintf(offset, "n_%ul", l);
	}
	id->len = offset - id->data;
}

static int ngx_http_image_split(ngx_str_t *values, ngx_uint_t len, ngx_str_t *str, u_char c) {
	ngx_uint_t index = 0;
	u_char *offset, *p;
	offset = str->data;
	for (p = str->data; p < str->data + str->len && index < len; ++p) {
		if (*p == c) {
			if (p == offset) {
				offset++;
				continue;
			}
			values[index].data = offset;
			values[index].len = p - offset;
			++index;
			offset = p + 1;
		}
	}
	if (p > offset) {
		values[index].data = offset;
		values[index].len = p - offset;
		++index;
	}
	return index;
}
static ngx_int_t ngx_http_image_paser_header(ngx_http_image_entry_t *entry, ngx_str_t *path, ngx_str_t *size, ngx_str_t *cut) {
	ngx_str_t sizes[3];
	ngx_str_t cuts[4];
	ngx_int_t sizes_len, cuts_len;
	if (path->len > NGX_HTTP_IMAGE_URL_MAX_SIZE + entry->pic_id.len + entry->ext.len) {
		return IMG_RC_PATH_MAX_SIZE;
	}
	strncpy((char*) entry->url.data, (char*) path->data, path->len);
	entry->url.len = path->len;
	strncpy((char*) entry->url.data + entry->url.len, (char*) entry->pic_id.data, entry->pic_id.len);
	entry->url.len += entry->pic_id.len;
	strncpy((char*) entry->url.data + entry->url.len, (char*) entry->ext.data, entry->ext.len);
	entry->url.len += entry->ext.len;
	sizes_len = ngx_http_image_split(sizes, 3, size, '*');
	if (sizes_len == 2) {
		entry->width = ngx_atoi(sizes[0].data, sizes[0].len);
		entry->height = ngx_atoi(sizes[1].data, sizes[1].len);
		entry->zip_type = ZOOM_BY_BOTH;
	} else if (sizes_len == 3) {
		entry->width = ngx_atoi(sizes[0].data, sizes[0].len);
		entry->height = ngx_atoi(sizes[1].data, sizes[1].len);
		entry->zip_type = ngx_atoi(sizes[2].data, sizes[2].len);
	} else {
		return IMG_RC_HEADER_ERR;
	}
	if (cut) {
		cuts_len = ngx_http_image_split(cuts, 4, cut, '*');
		if (cuts_len == 4) {
			entry->cut_start_x = ngx_atoi(cuts[0].data, cuts[0].len);
			entry->cut_start_y = ngx_atoi(cuts[1].data, cuts[1].len);
			entry->cut_width = ngx_atoi(cuts[2].data, cuts[2].len);
			entry->cut_height = ngx_atoi(cuts[3].data, cuts[3].len);
		} else {
			entry->cut_start_x = 0;
			entry->cut_start_y = 0;
			entry->cut_width = 0;
			entry->cut_height = 0;
		}
	} else {
		entry->cut_start_x = 0;
		entry->cut_start_y = 0;
		entry->cut_width = 0;
		entry->cut_height = 0;
	}
	return IMGZIP_OK;
}
static ngx_int_t ngx_http_image_post_content_handler(ngx_http_request_t *r, ngx_http_image_entry_t *entry) {
	MagickWand *img;
	int i;
	ngx_int_t rc;

	ngx_http_image_entry_get_store_info(entry);
	entry->flag = 0;
	img = NewMagickWand();
	MagickSetCompressionQuality(img,90);
	i = MagickReadImageBlob(img, entry->pic.data, entry->pic.len);
	if (i == 0) {
		log_print(LOG_LEVEL_ERROR, "MagickReadImageBlob failed!");
		i = IMG_RC_READ_IMAGE_BLOB;
		goto failed;
	}
	char *fmt = MagickGetImageFormat(img);
	if (strcmp(fmt, "GIF") == 0) {
		MagickWand *new = MagickCoalesceImages(img);
		if (new) {
			DestroyMagickWand(img);
			img = new;
		}
	}
	free(fmt);
	if (img == NULL) {
		log_print(LOG_LEVEL_ERROR, "MagickCoalesceImages failed!");
		i = IMG_RC_ZOOM_ERR;
		goto failed;
	}
	if (imgZoom(img, entry->width, entry->height, entry->zip_type) == IMGZIP_ERR) {
		log_print(LOG_LEVEL_ERROR, "imgZoom failed!");
		i = IMG_RC_ZOOM_ERR;
		goto failed;
	}
	if (entry->cut_width > 0 && entry->cut_height > 0) {
		if (imgCut(img, entry->cut_start_x, entry->cut_start_y, entry->cut_width, entry->cut_height) == IMGZIP_ERR) {
			log_print(LOG_LEVEL_ERROR, "imgCut failed!");
			i = IMG_RC_ZOOM_ERR;
			goto failed;
		}
	}
	entry->pic.data = MagickWriteImageBlob(img, &entry->pic.len);
	if (entry->pic.data == NULL) {
		i = IMG_RC_ZOOM_ERR;
		goto failed;
	}
	if (entry->pic.len > 1024 * 1024 * 2) {
		free(entry->pic.data);
		DestroyMagickWand(img);
		return IMG_RC_MAX_SIZE;
	}

	rc = ngx_http_drizzle_handler(r, entry, ngx_http_drizzle_empty_callback);
//	free(entry->pic.data);
	DestroyMagickWand(img);
	if (rc == IMGZIP_AGAIN) {
		return IMGZIP_OK;
	}
	if (rc != IMGZIP_OK) {
		return IMG_RC_STORE_ERR;
	}
	return rc;
	failed: ;
	DestroyMagickWand(img);
	return i;
}

/*static ngx_int_t ngx_check_ip(ngx_http_request_t *r)
{
	struct sockaddr *addr;
	struct sockaddr_in *sockaddr;
	int i;
	char *p;
	ngx_connection_t *c;
	ngx_str_t *str,*ip;
	str = (ngx_str_t*)ngx_palloc(r->pool, sizeof(ngx_str_t));
	c = r->connection;
	addr = c->sockaddr;
	sockaddr = (struct sockaddr_in*)addr;
	p = inet_ntoa(sockaddr->sin_addr);
	str->data = (u_char*)p;
	str->len = strlen((char*)str->data) + 1;
	ip = (ngx_str_t*)checkip->elts;
	for(i = 0;i < checkip->nelts;i++)
	{
		ip = ip + 1;
		if(ip->len == str->len)
		{
			if(strcmp((char*)ip->data, (char*)str->data) == 0)
			{
				return IMGZIP_OK;
			}
		}
	}

	return IMGZIP_ERR;
}*/
