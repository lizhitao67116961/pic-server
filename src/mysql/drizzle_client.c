/*
 *
 *  Created on: 2013-5-23
 *      Author: lizhitao
 */
#include "drizzle_client.h"
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "../server/ngx_http_image_entry.h"
#include <libdrizzle-5.1/drizzle_client.h>
#include <time.h>


ngx_int_t sql_max_len = 128;
ngx_int_t *drizzle_db_range;
ngx_array_t drizzle_host_groups;
ngx_int_t update_limit = 60 * 60 * 24 * 7;


static inline int drizzle_client_paser_max_range(ngx_str_t *range) {
	int i = 0;
	for (i = 0; i < range->len; ++i) {
		if (range->data[i] == '-') {
			break;
		}
	}
	return ngx_atoi(range->data + i + 1, range->len - i - 1);
}

static inline void ngx_str_cpy(ngx_str_t *des, ngx_str_t * src) {
	des->data = src->data;
	des->len = src->len;
}

static inline int drizzle_client_paser_min_range(ngx_str_t *range) {
	int i = 0;
	for (i = 0; i < range->len; ++i) {
		if (range->data[i] == '-') {
			break;
		}
	}
	return ngx_atoi(range->data, i);
}

static void drizzle_client_conf_set(drizzle_host_group *group, imgzip_mysql_server_conf_t *drizzle_conf) {
	group->slave.min_range = group->master.min_range = drizzle_client_paser_min_range(&drizzle_conf->range);
	group->slave.max_range = group->master.max_range = drizzle_client_paser_max_range(&drizzle_conf->range);
	ngx_str_cpy(&group->master.address, &drizzle_conf->address);
	group->master.dbname.data= ngx_palloc(ngx_cycle->pool, 20);
	bzero(group->master.dbname.data,20);
	ngx_int_t db_index = (ngx_int_t)sprintf((char*)group->master.dbname.data, (char*)"DBWWW58COM_PIC_%d",(int)group->master.min_range);
	group->master.dbname.len = db_index;
	ngx_str_cpy(&group->slave.address, &drizzle_conf->back_address);
	group->slave.dbname = group->master.dbname;
	ngx_str_cpy(&group->master.user_name, &drizzle_conf->user_name);
	ngx_str_cpy(&group->master.pass_word, &drizzle_conf->pass_word);
	ngx_str_cpy(&group->slave.user_name, &drizzle_conf->user_name);
	ngx_str_cpy(&group->slave.pass_word, &drizzle_conf->pass_word);
	group->slave.port = group->master.port = drizzle_conf->port;
	group->slave.connect_timeout = group->master.connect_timeout = drizzle_conf->timeout;
	group->slave.write_timeout = group->master.write_timeout = drizzle_conf->timeout;
	group->slave.read_timeout = group->master.read_timeout = drizzle_conf->timeout;
	group->slave.idle_timeout = group->master.idle_timeout = drizzle_conf->idle_timeout;
}

/*static ngx_int_t drizzle_client_create_sql_str(ngx_str_t *src_sql, ngx_str_t *des_sql, ngx_uint_t db_id, ngx_uint_t table_id) {
	u_char *c = ngx_sprintf(des_sql->data, (char*) src_sql->data, db_id, table_id);
	des_sql->len = c - des_sql->data;
	return des_sql->len;
}*/
ngx_int_t drizzle_client_create_connect(img_drizzle_host *host) {
//	char des[32];
//	drizzle_st *dp;
//	drizzle_st *dc;
	drizzle_ctx *ctx;
	int ret;
#if 0
	sprintf(des, "DBWWW58COM_PIC_%d", (int)db_id);
#endif
	ctx = (drizzle_ctx*)malloc(sizeof(drizzle_ctx));
	if (ctx == NULL) {
		perror("drizzle_ctx malloc");
	}
//	drizzle_create_tcp()
//	ctx->db = NULL;
//	ctx->dc = NULL;
//	ctx->db = drizzle_create(ctx->db);
//	if(ctx->db == NULL){
//		perror("drizzle_create failed");
//	}
//
//	ctx->dc = drizzle_con_create(ctx->db, ctx->dc);
//	if(ctx->dc == NULL) {
//		perror("drizzle_con_create failed");
//	}
//	dp = ctx->db;
//	dc = ctx->dc;
//	memcpy(dc->user, host->user_name.data, host->user_name.len);
//	dc->user[host->user_name.len] ='\0';
//
//	memcpy(dc->password, host->pass_word.data, host->pass_word.len);
//	dc->password[host->pass_word.len] = '\0';
//#if 0
//	memcpy(dc->db, des, strlen(des));
//	dc->db[strlen((char*)des)] ='\0';
//#endif
//	drizzle_add_options(dp, DRIZZLE_NON_BLOCKING);
//	drizzle_con_add_options(dc, DRIZZLE_CON_MYSQL);
//
//  drizzle_con_set_tcp(dc, (char*)host->address.data, host->port);


	ctx->db = NULL;
	ctx->dc = NULL;
	in_port_t port = 3310;
  drizzle_st *con = drizzle_create_tcp((const char *)"192.168.120.7",port,(const char *)"pic58user",(const char *)"pic58user123456",(const char *)"DBWWW58COM_PIC_102",DRIZZLE_CON_OPTIONS_NON_BLOCKING);
  ret = drizzle_connect(con);
  ctx->db = con;
  ctx->dc = con;
//  drizzle_con_fd()
//  ret = drizzle_con_connect(dc);
  if (ret != DRIZZLE_RETURN_OK && ret != DRIZZLE_RETURN_IO_WAIT) {
	  printf("drizzle_con_connect first\n");
//    drizzle_con_free(dc);
//	  drizzle_result_free();
	  ret= drizzle_quit(con);
     return IMGZIP_ERR;
    }
  return IMGZIP_OK;
}

ngx_int_t drizzle_client_init() {
	ngx_http_drizzle_keepalive_cache_t *cached;
	int drizzle_host_len = 0;
	int i;
	imgzip_mysql_server_conf_t *drizzle_conf;
	drizzle_host_group *group;
	drizzle_db_range = ngx_palloc(ngx_cycle->pool, sizeof(ngx_uint_t) * imgzip_server_conf.mysql_db_max_range);
	if (drizzle_db_range == NULL) {
		return IMGZIP_ERR;
	}
	drizzle_conf = imgzip_server_conf.mysql_conf;
	while (drizzle_conf) {
		drizzle_host_len++;
		drizzle_conf = drizzle_conf->next;
	}
	if (ngx_array_init(&drizzle_host_groups, ngx_cycle->pool, drizzle_host_len, sizeof(drizzle_host_group)) != IMGZIP_OK) {
		return IMGZIP_ERR;
	}
	drizzle_host_len = 0;
	drizzle_conf = imgzip_server_conf.mysql_conf;
	while (drizzle_conf) {
		group = ngx_array_push(&drizzle_host_groups);
		drizzle_client_conf_set(group, drizzle_conf);

//		if (drizzle_client_create_connect(&group->slave) == IMGZIP_OK) {
//			group->slave.dead_time = 0;
//		} else {
//			group->slave.dead_time = ngx_time();
//		}
//		if (drizzle_client_create_connect(&group->master) == IMGZIP_OK) {
//			group->master.dead_time = 0;
//		} else {
//			group->slave.dead_time = 0;
//		}


		for (i = group->master.min_range; i <= group->master.max_range; ++i) {
			drizzle_db_range[i] = drizzle_host_len;
		}

	//数据库连接池
//		rr_peer = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_http_memc_rr_peer_t));
//  master
//		printf("drizzle_conf->max_pool_size is %d\n", (int)drizzle_conf->max_pool_size);
//		printf("drizzle_host_len is %d\n", (int)drizzle_host_len);
//		fflush(stdout);

		log_print(LOG_LEVEL_DEBUG,"drizzle_conf->max_pool_size is %d\n", (int)drizzle_conf->max_pool_size);
		log_print(LOG_LEVEL_DEBUG,"drizzle_host_len is %d\n", (int)drizzle_host_len);
		cached = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_http_drizzle_keepalive_cache_t) * drizzle_conf->max_pool_size);
		if (cached == NULL) {
			return IMGZIP_ERR;
		}

		ngx_queue_init(&((&group->master)->cache));
		ngx_queue_init(&((&group->master)->free));

		for (i = 0; i < drizzle_conf->max_pool_size; i++) {
			ngx_queue_insert_head(&((&group->master)->free), &cached[i].queue);
		}

//  slave
		cached = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_http_drizzle_keepalive_cache_t) * drizzle_conf->max_pool_size);
		if (cached == NULL) {
			return IMGZIP_ERR;
		}

		ngx_queue_init(&((&group->slave)->cache));
		ngx_queue_init(&((&group->slave)->free));

		for (i = 0; i < drizzle_conf->max_pool_size; i++) {
			ngx_queue_insert_head(&((&group->slave)->free), &cached[i].queue);
		}

		drizzle_host_len++;
		drizzle_conf = drizzle_conf->next;
	}
	return IMGZIP_OK;
}
