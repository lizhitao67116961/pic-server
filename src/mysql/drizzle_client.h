/*
 *
 *  Created on: 2013-05-17
 *      Author: lizhitao
 */
#ifndef DRIZZLE_CLIENT_H_
#define DRIZZLE_CLIENT_H_
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "../server/ngx_http.h"
#include "../server/ngx_http_upstream.h"
#include <libdrizzle-5.1/drizzle_client.h>
#include <poll.h>

typedef ngx_int_t (*ngx_drizzle_callback)(ngx_http_request_t *r, ngx_http_upstream_t *u);


typedef struct {
	ngx_str_t user_name;
	ngx_str_t pass_word;
	ngx_str_t address;
	ngx_uint_t port;
	ngx_str_t dbname;
	time_t dead_time;
	ngx_uint_t idle_timeout;
	ngx_uint_t min_range;
	ngx_uint_t max_range;
	ngx_uint_t connect_timeout;
	ngx_uint_t read_timeout;
	ngx_uint_t write_timeout;
	ngx_queue_t cache;
	ngx_queue_t free;
} img_drizzle_host;

typedef struct {
   ngx_queue_t                queue;
   ngx_connection_t        *connection;
   socklen_t                     socklen;
   struct sockaddr         sockaddr;
   drizzle_st                    *drizzle_db;
   img_drizzle_host        *host;
} ngx_http_drizzle_keepalive_cache_t;

typedef struct {
	drizzle_st     *db;
	drizzle_st *dc;
	drizzle_result_st *drizzle_res;
	drizzle_column_st *drizzle_col;
	uint64_t drizzle_row;
	ngx_int_t state;
	ngx_uint_t connect_timeout;
	ngx_uint_t read_timeout;
	ngx_uint_t write_timeout;
	img_drizzle_host *host;
//	ngx_queue_t queue;
//	ngx_queue_t head;
	ngx_drizzle_callback drizzle_callback;
}drizzle_ctx;


typedef struct {
	img_drizzle_host master;
	img_drizzle_host slave;
} drizzle_host_group;


ngx_int_t drizzle_client_init();
ngx_int_t drizzle_client_create_connect(img_drizzle_host *host);
//static ngx_int_t drizzle_client_create_sql_str(ngx_str_t *src_sql, ngx_str_t *des_sql, ngx_uint_t db_id, ngx_uint_t table_id);



#endif /* DRIZZLE_CLIENT_H_ */
