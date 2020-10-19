/*
 * drizzle_client.h
 *
 *  Created on: 2013-05-15
 *      Author: lizhitao
 */


#include "ngx_http_drizzle_processor.h"
#include "ngx_http_drizzle_util.h"
#include "ngx_http_drizzle_handler.h"
#define MYSQL_ER_NO_SUCH_TABLE 1146

ngx_str_t insert_str =	ngx_string("INSERT INTO T_Pic_%d  (filename,domain,uptime,url) VALUES (\"%s\",\"0\",\"CURRENT_TIMESTAMP\",\"%s\")");
//ngx_str_t query_str = ngx_string("SELECT pic,domain,uptime,url FROM DBWWW58COM_PIC_%d.T_Pic_%d WHERE filename=%s");
ngx_str_t query_str = ngx_string("SELECT pic FROM DBWWW58COM_PIC_%d.T_Pic_%d WHERE filename=\"%s\"");
ngx_str_t count_str = ngx_string("SELECT COUNT(*) FROM DBWWW58COM_PIC_%d.T_Pic_%d WHERE filename=\"%s\"");
ngx_str_t delete_str = ngx_string("DELETE FROM DBWWW58COM_PIC_%d.T_Pic_%d WHERE filename=\"%s\"");
ngx_str_t update_str =	ngx_string("UPDATE T_Pic_%d SET uptime=CURRENT_TIMESTAMP WHERE filename=\"%s\"");

static ngx_int_t ngx_http_upstream_drizzle_connect(ngx_http_request_t *r,
		ngx_connection_t *c, drizzle_ctx *df, drizzle_st *dc);

static ngx_int_t ngx_http_upstream_drizzle_send_query(ngx_http_request_t *r,
		ngx_connection_t *c, drizzle_ctx *df);

static ngx_int_t ngx_http_upstream_drizzle_recv_cols(ngx_http_request_t *r,
		ngx_connection_t *c, drizzle_ctx *df);

static ngx_int_t ngx_http_upstream_drizzle_recv_rows(ngx_http_request_t *r,
		ngx_connection_t *c, drizzle_ctx *df);

extern void ngx_http_image_send_not_find_img(ngx_http_request_t *r);
extern ngx_int_t ngx_http_drizzle_handler(ngx_http_request_t *r,
		ngx_http_image_entry_t *entry, ngx_drizzle_callback drizzle_callback);
extern ngx_int_t ngx_http_image_content_handler(ngx_http_request_t *r,
		ngx_http_upstream_t *u);
static void ngx_http_drizzle_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_http_drizzle_keepalive_close_handler(ngx_event_t *ev);
//extern void ngx_http_drizzle_empty_callback(ngx_http_request_t *r, ngx_http_upstream_t *u);

ngx_int_t ngx_http_drizzle_process_events(ngx_http_request_t *r) {
	ngx_http_upstream_t *u;
	ngx_connection_t *c;
	drizzle_ctx *df;
	drizzle_st *dc;
	ngx_int_t rc;
#if 0
	drizzle_return_t ret;
#endif

	u = r->upstream;
	c = u->peer.connection;

//	df = (drizzle_ctx*) r->ctx[2];
	df = ngx_http_get_module_ctx(r,2);

	dc = df->dc;

	switch (df->state) {
	case state_db_connect:
		rc = ngx_http_upstream_drizzle_connect(r, c, df, dc);
		break;

	case state_db_idle: /* from connection pool */
		printf("sending query to drizzle upstream\n");
		break;
	case state_db_send_query:
		rc = ngx_http_upstream_drizzle_send_query(r, c, df);
		break;

	case state_db_recv_cols:
		rc = ngx_http_upstream_drizzle_recv_cols(r, c, df);
		break;

	case state_db_recv_rows:
		rc = ngx_http_upstream_drizzle_recv_rows(r, c, df);
		break;

	default:
		log_print(LOG_LEVEL_ERROR, "unknown state: %d", (int) df->state);
		return IMGZIP_ERR;
	}

	if (rc == IMGZIP_AGAIN) {

		if (ngx_handle_write_event(c->write) != IMGZIP_OK) {
			return IMGZIP_ERR;
		}
		return IMGZIP_OK;
	}

	if (rc == IMGZIP_OK || rc == IMGZIP_DONE) {
		return IMGZIP_OK;
	}

	return rc;
}

static ngx_int_t ngx_http_upstream_drizzle_connect(ngx_http_request_t *r,
		ngx_connection_t *c, drizzle_ctx *df, drizzle_st *dc) {
	drizzle_return_t ret;

	ret = drizzle_connect(dc);

	if (ret == DRIZZLE_RETURN_IO_WAIT) {
#if 0
		if (ngx_handle_write_event(c->write)!=IMGZIP_OK) {
			return IMGZIP_ERR;
		}

		if(c->write->timer_set) {
			ngx_event_del_timer(c->write);
		}
		ngx_event_add_timer(c->write,CONNECT_TIMEOUT);
#endif
		return IMGZIP_AGAIN;
	}

	if (c->write->timer_set) {
		ngx_event_del_timer(c->write);
	}

	if (ret != DRIZZLE_RETURN_OK) {
		printf("drizzle connection error %d\n", ret);
		ngx_http_upstream_drizzle_error(r, r->upstream, df);
		return IMGZIP_ERR;
	}

	return ngx_http_upstream_drizzle_send_query(r, c, df);
}

static ngx_int_t ngx_http_upstream_drizzle_send_query(ngx_http_request_t *r,
		ngx_connection_t *c, drizzle_ctx *df) {
	ngx_http_upstream_t *u = r->upstream;
	drizzle_return_t ret;
	char des_sql[128];
	bzero(&des_sql,IMGZIP_SQLDEST_LEN);
//	drizzle_ctx *ctx;
	ngx_http_image_entry_t *entry;

//	host = (drizzle_ctx*) r->ctx[2];
//	ctx = ngx_http_get_module_ctx(r, 2);
	entry = u->peer.data;

	u_char *character;
//         ngx_int_t sql_len;
	switch (entry->operation) {
	case 0:
		entry->filename.data[entry->filename.len] = '\0';
		character = ngx_sprintf((u_char*) &des_sql, (char*) query_str.data,
				entry->db_id, entry->table_id, (char*) entry->filename.data);
		break;
	case 1:
		entry->filename.data[entry->filename.len] = '\0';
		entry->url.data[entry->filename.len] = '\0';
		character = ngx_sprintf((u_char*) &des_sql, (char*) insert_str.data,
				entry->db_id, entry->table_id, (char*) entry->filename.data, 0,
				(char*) entry->url.data);
//		printf("in sending %s\n", des_sql);
		log_print(LOG_LEVEL_DEBUG,"in sending %s\n", des_sql);
		break;
	default:
		entry->filename.data[entry->filename.len] = '\0';
		character = ngx_sprintf((u_char*) &des_sql, (char*) update_str.data,
				entry->db_id, entry->table_id, (char*) entry->filename.data);
		break;
	}
//	printf("drizzle query des_sql = %s\n", des_sql);
	df->drizzle_res = drizzle_query(df->dc, (char*) &des_sql, strlen(des_sql),&ret);

	if (ret == DRIZZLE_RETURN_IO_WAIT) {
		if (df->state != state_db_send_query) {
			df->state = state_db_send_query; //state at this time
			/* if (ngx_handle_write_event(c->write)!=IMGZIP_OK){
			 printf("ngx_query\n");
			 }*/
			if (c->write->timer_set) {
				ngx_event_del_timer(c->write);
			}

			ngx_event_add_timer(c->write, CONNECT_TIMEOUT);
		}

		return IMGZIP_AGAIN;
	}

	if (c->write->timer_set) {
		ngx_event_del_timer(c->write);
	}

	if (ret != DRIZZLE_RETURN_OK) {
		printf("drizzle query ret = %d\n", ret);
		ngx_http_upstream_drizzle_error(r, u, df);
		return IMGZIP_OK;
		//		 ngx_close_connection(c);
		//   ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		//   return IMGZIP_ERR;
	}

	if (entry->operation == 1) {
		return IMGZIP_OK;
	}
	/* ret == DRIZZLE_RETURN_OK */

	switch (entry->operation) {
	case 0:
		return ngx_http_upstream_drizzle_recv_cols(r, c, df);
		break;
	case 1:
		ngx_http_upstream_drizzle_post(r, u, df, 0);
		break;
	case 2:
		ngx_http_upstream_drizzle_done(r, u, df, 0);
		break;
	}
	return IMGZIP_OK;
}

static ngx_int_t ngx_http_upstream_drizzle_recv_cols(ngx_http_request_t *r,
		ngx_connection_t *c, drizzle_ctx *df) {
	drizzle_column_st *col = NULL;
	drizzle_return_t ret;

	for (;;) {
		col = drizzle_column_read(df->drizzle_res, &ret);

		if (ret == DRIZZLE_RETURN_IO_WAIT) {

			if (df->state != state_db_recv_cols) {
				df->state = state_db_recv_cols;
#if 0
				if (ngx_handle_read_event(c->read)==IMGZIP_ERR) {
					printf("ngx_handle_read_event\n");
				}
#endif
				if (c->read->timer_set) {
					ngx_event_del_timer(c->read);
				}

				ngx_event_add_timer(c->read, CONNECT_TIMEOUT);
			}

			return IMGZIP_AGAIN;
		}

		if (ret != DRIZZLE_RETURN_OK) {
			printf("col read ret is not DRIZZLE_RETURN_OK\n");
			ngx_http_upstream_drizzle_error(r, r->upstream, df);
			return IMGZIP_ERR;
		}

		if (col) {
			drizzle_column_free(col);
		} else { /* after the last column */

			if (c->read->timer_set) {
				ngx_event_del_timer(c->read); //have done a read event
			}
			return ngx_http_upstream_drizzle_recv_rows(r, c, df);
		}

	}

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_upstream_drizzle_recv_rows(ngx_http_request_t *r,
		ngx_connection_t *c, drizzle_ctx *df) {
	ngx_http_upstream_t *u = r->upstream;
	drizzle_return_t ret;
	size_t offset;
	size_t len;
	size_t total;
	drizzle_field_t field;
	ngx_http_image_entry_t *entry;

	entry = (ngx_http_image_entry_t*) u->peer.data;

	for (;;) {

		if (df->drizzle_row == 0) {
			df->drizzle_row = drizzle_row_read(df->drizzle_res, &ret); //just get the row number

			if (ret == DRIZZLE_RETURN_IO_WAIT) {
				df->drizzle_row = 0;
				goto io_wait;
			}

			if (ret != DRIZZLE_RETURN_OK) {
//				printf("drizzle read row return not ok\n");
				log_print(LOG_LEVEL_ERROR,"drizzle read row return not ok");
				ngx_http_upstream_drizzle_error(r, u, df);
				return IMGZIP_ERR;
			}

			/* ret == DRIZZLE_RETURN_OK */

			if (df->drizzle_row == 0) {
				/* after last row */
				drizzle_result_free(df->drizzle_res);

				if (c->read->timer_set) {
					ngx_event_del_timer(c->read);
				}

				//  ngx_event_add_timer(c->read, CONNECT_TIMEOUT);
				ngx_http_upstream_drizzle_done(r, u, df, IMGZIP_DONE);
				return IMGZIP_OK;
			}
		}

		/* df->drizzle_row != 0 */

		for (;;) {
			field = drizzle_field_read(df->drizzle_res, &offset, &len, &total,&ret);
			if (ret == DRIZZLE_RETURN_IO_WAIT) {
				goto io_wait;
			}

			if (ret == DRIZZLE_RETURN_ROW_END) {
				break;
			}

			if (total == 0 || ret != DRIZZLE_RETURN_OK) {
//            		 printf("now the fd is%d\n",df->dc->fd);
//				printf("row read ret is not DRIZZLE_RETURN_OK:%d\n", ret);
				log_print(LOG_LEVEL_ERROR,"row read ret is not DRIZZLE_RETURN_OK:%d\n", ret);
				drizzle_result_free(df->drizzle_res);
				ngx_http_upstream_drizzle_error(r, u, df);
				return IMGZIP_ERR;
			}

			if (u->buffer.start == NULL) {
				u->buffer.start = ngx_palloc(r->pool, total);
				if (u->buffer.start == NULL) {
					return IMGZIP_ERR;
				}

				u->buffer.pos = u->buffer.start;
				u->buffer.last = u->buffer.start;
				u->buffer.end = u->buffer.start + total;
			}

			memcpy(u->buffer.pos, field, len);
			u->buffer.last = u->buffer.pos + len;
			u->buffer.pos = u->buffer.last;
			//drizzle_field_free(field);
		}

		df->drizzle_row = 0;
		u->buffer.pos = u->buffer.start;
		drizzle_field_free(field);
	}

	return IMGZIP_OK;

	io_wait:

	if (df->state != state_db_recv_rows) {
		df->state = state_db_recv_rows;
#if 0
		if (ngx_handle_read_event(c->read)!=IMGZIP_OK) {
			printf("2ngx_handle_read_event\n");
		}
#endif
		if (c->read->timer_set) {
			ngx_event_del_timer(c->read);
		}

		ngx_event_add_timer(c->read, CONNECT_TIMEOUT);
	}

	return IMGZIP_AGAIN;
}

//最后完成所有操作进行回调处理
void ngx_http_upstream_drizzle_done(ngx_http_request_t *r,ngx_http_upstream_t *u, drizzle_ctx *df, ngx_int_t rc) {
	ngx_http_image_entry_t *entry;
//	ngx_connection_t *c;
	drizzle_ctx *ctx;
//	c = r->ctx[2];
	ctx = ngx_http_get_module_ctx(r, 2);

//add by lizt
	ngx_connection_t *c;
	ngx_queue_t *q;
	ngx_http_drizzle_keepalive_cache_t *item;
	if (u->peer.connection != NULL && (rc == NGX_HTTP_NOT_FOUND || rc == NGX_HTTP_OK || rc == IMGZIP_OK || rc == IMGZIP_DONE)) {
		c = u->peer.connection;
//        drizzle_buffer_free();
		if (ngx_queue_empty(&ctx->host->free)) {

			q = ngx_queue_last(&ctx->host->cache);
			ngx_queue_remove(q);

			item = ngx_queue_data(q, ngx_http_drizzle_keepalive_cache_t,queue);

			ngx_close_connection(item->connection);
         drizzle_quit(item->drizzle_db);
		} else {
			q = ngx_queue_head(&ctx->host->free);
			ngx_queue_remove(q);

			item = ngx_queue_data(q, ngx_http_drizzle_keepalive_cache_t,
					queue);
		}
		item->connection = c;
		item->host = ctx->host;
		c->data = item;
		ngx_queue_insert_head(&ctx->host->cache, q);

		item->drizzle_db = ctx->db;

		u->peer.connection = NULL;

		if (c->read->timer_set) {
			log_print(LOG_LEVEL_INFO, "ngx_http_upstream_drizzle_done---c->read->timer_set is %d",c->read->timer_set);
			ngx_event_del_timer(c->read);
		}
		if (c->write->timer_set) {
			log_print(LOG_LEVEL_INFO, "ngx_http_upstream_drizzle_done---c->read->timer_set is %d",c->write->timer_set);
			ngx_event_del_timer(c->write);
		}

		c->write->handler = ngx_http_drizzle_keepalive_dummy_handler;
		c->read->handler = ngx_http_drizzle_keepalive_close_handler;

		c->idle = 1;
//		ctx->rr_peer->fails = 0;
	} else if (ctx->host) {
//		ctx->rr_peer->fails++;
	}
	if (u->peer.connection) {

		log_print(LOG_LEVEL_DEBUG, "close http drizzle connection: %d", u->peer.connection->fd);

		ngx_close_connection(u->peer.connection);
		drizzle_quit(item->drizzle_db);
	}

	u->peer.connection = NULL;

//	drizzle_close(ctx->db);
//end

//	printf("ngx_http_upstream_drizzle_done is %d\n",(int)rc);
	log_print(LOG_LEVEL_DEBUG, "ngx_http_upstream_drizzle_done is %d\n",(int)rc);

	entry = u->peer.data;
//	c = u->peer.connection;

//modified by lizt 2013-03-05 暂时注释掉 表示没有图片返回
//	r->headers_out.content_length_n = u->buffer.last - u->buffer.start;
//	if (r->headers_out.content_length_n == 0) {
//		return ngx_http_upstream_drizzle_error(r, u, df);
//	}
//end

	/*	if (entry->operation == 0) {
	 entry->operation = 2;
	 df->state = state_db_send_query;
	 if (c->write->timer_set) {
	 ngx_event_del_timer(c->write);
	 }
	 ngx_event_add_timer(c->write, CONNECT_TIMEOUT);
	 rc = ngx_http_upstream_drizzle_send_query(r,c,df);
	 if (rc == IMGZIP_AGAIN){
	 return;
	 }
	 }*/

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.last_modified_time = ngx_time();
	r->headers_out.status = NGX_HTTP_OK;
	r->allow_ranges = 1;

	u->buffer.pos = u->buffer.start;
	u->buffer.last_buf = 1;
	u->buffer.memory = 1;

	df->drizzle_callback(r, u);
	/*		out.buf = &u->buffer;
	 out.next = NULL;

	 cln = ngx_http_cleanup_add(r, 0);
	 if (cln == NULL) {
	 perror("ngx_http_cleanup_add");
	 }
	 cln->handler = ngx_http_drizzle_cleanup;
	 cln->data = df;

	 ngx_close_connection(c);
	 ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
	 printf("drizzle_con_free_all: %d\n",df->dc->fd);*/
}

void ngx_http_upstream_drizzle_error(ngx_http_request_t *r,
		ngx_http_upstream_t *u, drizzle_ctx *dh) {
	ngx_http_image_entry_t *entry;
	ngx_connection_t *c;
	ngx_int_t rc;

	entry = u->peer.data;
	c = u->peer.connection;

//	ngx_close_connection(c);
	if (entry->flag == 1) {
		ngx_http_image_content_handler(r, u);
	} else {
		entry->flag = 1;
		rc = ngx_http_drizzle_handler(r, entry, ngx_http_image_content_handler);
	}
}

void ngx_http_upstream_drizzle_post(ngx_http_request_t *r,
		ngx_http_upstream_t *u, drizzle_ctx *df, ngx_int_t ret) {
	ngx_table_elt_t *h;
	ngx_buf_t *b;
	ngx_int_t rc;
	ngx_http_image_entry_t *entry;
	u_char *p, *content;
	ngx_chain_t out;
//	printf("ngx_http_upstream_drizzle_post\n");
	log_print(LOG_LEVEL_INFO,"ngx_http_upstream_drizzle_post");
	if (ret == 1) {
		goto failed;
	}
	entry = u->peer.data;
	h = ngx_list_push(&r->headers_out.headers);
	if (h == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	h->hash = 1;
	ngx_str_set(&h->key, "Status");
	ngx_str_set(&h->value, "0");

	r->headers_out.last_modified_time = ngx_time(); //
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_type.len = sizeof("text/html") - 1;
	r->headers_out.content_type.data = (u_char*) "text/html";
	r->allow_ranges = 1;
	r->headers_out.content_length_n = entry->pic_id.len + entry->ext.len;
	rc = ngx_http_send_header(r);

	if (rc == IMGZIP_ERR || rc > IMGZIP_OK || r->header_only) {
		ngx_http_finalize_request(r, rc);
		return;
	}
	content = ngx_pcalloc(r->pool, r->headers_out.content_length_n);
	if (content == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	strncpy((char*) content, (char*) entry->pic_id.data, entry->pic_id.len);
	strncpy((char*) content + entry->pic_id.len, (char*) entry->ext.data,
			entry->ext.len);
	b->pos = content;
	b->last = content + entry->pic_id.len + entry->ext.len;

	out.buf = b;
	out.next = NULL;
	ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
	return;
	failed: ;
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

static void ngx_http_drizzle_keepalive_dummy_handler(ngx_event_t *ev) {

}

static void ngx_http_drizzle_keepalive_close_handler(ngx_event_t *ev) {
	ngx_http_drizzle_keepalive_cache_t *item;
	int n;
	char buf[1];
	ngx_connection_t *c;

	c = ev->data;

	n = recv(c->fd, buf, 1, MSG_PEEK);

	if (n == -1 && errno == IMGZIP_ERR) {
		/* stale event */

		if (ngx_handle_read_event(c->read) != IMGZIP_OK) {
			goto close;
		}

		return;
	}

	close:

	item = c->data;

	ngx_queue_remove(&item->queue);
	ngx_close_connection(item->connection);
	ngx_queue_insert_head(&item->host->free, &item->queue);
}
