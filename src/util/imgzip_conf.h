/*
 * imgzip_conf.h
 *
 *  Created on: 2013-03-08
 *      Author: lizhitao
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include <libdrizzle-5.1/drizzle_client.h>
#ifndef IMGZIP_CONF_H_
#define IMGZIP_CONF_H_
typedef struct {
	ngx_uint_t img_max_width;
	ngx_uint_t img_max_height;
	ngx_uint_t add_water_min_size;
	int add_water_point_x;
	int add_water_point_y;
} imgzip_img_conf_t;

typedef struct imgzip_memc_conf_s imgzip_memc_conf_t;
struct imgzip_memc_conf_s {
	ngx_str_t memc_ip;
	ngx_uint_t port;
	ngx_uint_t memc_max_cached_size;
	ngx_uint_t memc_recv_buf;
	ngx_uint_t retry_time;
	ngx_uint_t memc_client_max_fails;
	ngx_uint_t read_timeout;
	imgzip_memc_conf_t *next;
};

struct imgzip_upstream_conf_s {
	ngx_str_t upstream_id;
	ngx_uint_t port;
	ngx_uint_t read_timeout;
	ngx_uint_t retry_time;
	ngx_uint_t client_max_fails;
	ngx_uint_t recv_buf;
	ngx_uint_t weight;
};
typedef struct imgzip_mysql_server_conf_s imgzip_mysql_server_conf_t;
struct imgzip_mysql_server_conf_s {
	ngx_str_t address;
	ngx_str_t back_address;
	ngx_str_t range;
	ngx_str_t user_name;
	ngx_str_t pass_word;
	ngx_uint_t min_pool_size;
	ngx_uint_t max_pool_size;
	ngx_uint_t idle_timeout;
	ngx_uint_t port;
	ngx_uint_t timeout;
	imgzip_mysql_server_conf_t *next;
};

typedef struct {
	ngx_uint_t listen_port;
	ngx_uint_t error_log_level;
	ngx_uint_t daemon;
	ngx_uint_t server_id;
	ngx_uint_t master_process;
	ngx_str_t resources_path;
	ngx_uint_t process_num;
	ngx_uint_t worker_connectons;
	ngx_str_t error_log_path;
	ngx_str_t access_log_path;
	ngx_uint_t mysql_db_max_range;
	ngx_uint_t little_access_mysql;
	imgzip_mysql_server_conf_t *mysql_conf;
	imgzip_memc_conf_t *memc_conf;
	imgzip_img_conf_t *img_conf;
} imgzip_http_server_conf_t;
extern imgzip_http_server_conf_t imgzip_server_conf;
ngx_int_t imgzip_conf_load(u_char *conf_path);
#endif /* IMGZIP_CONF_H_ */
