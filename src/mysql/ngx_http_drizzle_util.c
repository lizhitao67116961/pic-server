#include "ngx_http_drizzle_module.h"
#include "ngx_http_drizzle_util.h"
#include "ngx_http_drizzle_handler.h"
#include "ngx_http_drizzle_processor.h"
#include "drizzle_client.h"
#include "../imgzip_core.h"
#include "../imgzip_config.h"
#include "../server/ngx_http_request.h"
#include "../server/ngx_event.h"
#include "../server/ngx_epoll_module.h"

extern ngx_int_t *drizzle_db_range;
extern ngx_array_t drizzle_host_groups;

static void ngx_http_drizzle_cleanup(void *data) {
//	drizzle_ctx *ctx = data;

//	drizzle_con_free(ctx->dc);
//	drizzle_free(ctx->db);

//	drizzle_free(ctx->db);

//	drizzle_quit(ctx->db);
}

static ngx_int_t ngx_http_upstream_dbd_reinit(ngx_http_request_t *r,
		ngx_http_upstream_t *u);
ngx_int_t ngx_http_upstream_dbd_connect(ngx_http_request_t *r,
		ngx_http_upstream_t *u, ngx_http_image_entry_t *entry,
		ngx_drizzle_callback drizzle_callback);
static void ngx_http_upstream_dbd_cleanup(void *data);
static void ngx_http_upstream_dbd_wr_check_broken_connection(
		ngx_http_request_t *r);
static void ngx_http_upstream_dbd_rd_check_broken_connection(
		ngx_http_request_t *r);
static void ngx_http_upstream_dbd_check_broken_connection(ngx_http_request_t *r,
		ngx_event_t *ev);
static ngx_int_t ngx_http_get_drizzle_peer(ngx_http_request_t *r,
		ngx_http_image_entry_t *entry, img_drizzle_host *host,
		drizzle_ctx **ctx);

ngx_int_t ngx_http_upstream_drizzle_test_connect(ngx_connection_t *c) {
	int err;
	socklen_t len;
	err = 0;
	len = sizeof(int);

	if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
		err = ngx_errno;
	}

	if (err) {
		log_print(LOG_LEVEL_ERROR, "connect() failed");
		return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}

ngx_int_t ngx_http_upstream_dbd_init(ngx_http_request_t *r,
		ngx_http_image_entry_t *entry, ngx_drizzle_callback drizzle_callback) {
	ngx_connection_t *c;

	c = r->connection;

	//check connection with client
	if (c->read->timer_set) {
		ngx_event_del_timer(c->read);
	}

	if (!c->write->active) {
		if (ngx_epoll_add_event(c->write, EPOLLIN, EPOLLET) == IMGZIP_ERR) {
//			printf("dbd_init--->ngx_epoll_add_event error\n");
			log_print(LOG_LEVEL_INFO, "dbd_init--->ngx_epoll_add_event error");
			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return IMGZIP_ERR;
		}
	}

	return ngx_http_upstream_dbd_init_request(r, entry, drizzle_callback);
}

ngx_int_t ngx_http_upstream_dbd_init_request(ngx_http_request_t *r,
		ngx_http_image_entry_t *entry, ngx_drizzle_callback drizzle_callback) {

	ngx_http_upstream_t *u;

	u = r->upstream;

	/*  if (!u->store) {
	 u->read_event_handler =
	 ngx_http_upstream_dbd_rd_check_broken_connection;
	 u->write_event_handler =
	 ngx_http_upstream_dbd_wr_check_broken_connection;
	 }*/

	//we don't need any request-header to connnect with mysql
	if (u->create_request(r) != IMGZIP_OK) {
		return IMGZIP_ERR;
	}

	u->output.pool = r->pool;
	u->output.bufs.num = 1;
	u->output.bufs.size = 1;
	u->output.output_filter = ngx_chain_writer;
	u->output.filter_ctx = &u->writer;
	u->writer.pool = r->pool;

	return ngx_http_upstream_dbd_connect(r, u, entry, drizzle_callback);
}

ngx_int_t ngx_http_upstream_dbd_connect(ngx_http_request_t *r,
		ngx_http_upstream_t *u, ngx_http_image_entry_t *entry,
		ngx_drizzle_callback drizzle_callback) {
	ngx_int_t rc;
	drizzle_host_group *group;
	drizzle_ctx *ctx;
	ngx_http_cleanup_t *cln;

	ctx = ngx_palloc(r->pool, sizeof(drizzle_ctx));
	ctx->drizzle_callback = drizzle_callback;
	cln = ngx_http_cleanup_add(r, 0);
	if (cln == NULL) {
		perror("ngx_http_cleanup_add");
	}
	cln->handler = ngx_http_drizzle_cleanup;
	cln->data = ctx;

	group = (drizzle_host_group*) drizzle_host_groups.elts
			+ drizzle_db_range[entry->db_id];

	if (entry->flag == 0) {
		rc = ngx_http_get_drizzle_peer(r, entry, &group->master, &ctx);
		ctx->drizzle_row = 0;
//		r->ctx[2] = (void*) ctx;
		ngx_http_set_ctx(r,ctx,2);
	} else {
		rc = ngx_http_get_drizzle_peer(r, entry, &group->slave, &ctx);
		ctx->drizzle_row = 0;
//		r->ctx[2] = (void*) ctx;
		ngx_http_set_ctx(r,ctx,2);
	}

//add by lizt 20130226
	ngx_connection_t *c;
	c = u->peer.connection;

	c->data = r;
	c->write->handler = ngx_http_upstream_dbd_handler;
	c->read->handler = ngx_http_upstream_dbd_handler;

	r->upstream->write_event_handler = ngx_http_drizzle_wev_handler;
	r->upstream->read_event_handler = ngx_http_drizzle_rev_handler;

    if ((u->peer.connection) && (u->peer.connection->fd == 0)) {
        c = u->peer.connection;
        u->peer.connection = NULL;

        if (c->write->timer_set) {
            ngx_event_del_timer(c->write);
        }

        ngx_free_connection(c);
//        ngx_http_upstream_drizzle_finalize_request(r, u,
    }
//end

	ctx->state = state_db_connect;

	u->peer.data = (void*) entry;

	if (rc != IMGZIP_OK) {
		return rc;
	}

	u->request_sent = 0;

	ngx_http_drizzle_set_libdrizzle_ready(r);

	return ngx_http_drizzle_process_events(r);
}

static void ngx_http_upstream_dbd_rd_check_broken_connection(ngx_http_request_t *r) {
	ngx_http_upstream_dbd_check_broken_connection(r, r->connection->read);
}

static void ngx_http_upstream_dbd_wr_check_broken_connection(ngx_http_request_t *r) {
	ngx_http_upstream_dbd_check_broken_connection(r, r->connection->write);
}

static void ngx_http_upstream_dbd_check_broken_connection(ngx_http_request_t *r,ngx_event_t *ev) {
	int n;
	char buf[1];
	ngx_err_t err;
	ngx_int_t event;
	ngx_connection_t *c;
	ngx_http_upstream_t *u;

	c = r->connection;
	u = r->upstream;

	if (c->error) {
		event = ev->write ? EPOLLOUT : EPOLLIN;

		if (ngx_epoll_del_event(ev, event, NGX_CLOSE_EVENT) != IMGZIP_OK) {
			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		return;
	}

	n = recv(c->fd, buf, 1, MSG_PEEK);

	if (ev->write && (n >= 0 || err == EAGAIN)) {
		return;
	}

	if (n > 0) {
		return;
	}

	if (n == -1) {
		if (err == EAGAIN) {
			return;
		}
		ev->error = 1;
	} else { /* n == 0 */
		err = 0;
	}

	ev->eof = 1;
	c->error = 1;

	if (u->peer.connection == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
}

static void ngx_http_upstream_dbd_cleanup(void *data) {
	ngx_http_request_t *r = data;

	ngx_http_upstream_t *u;

	u = r->upstream;

	ngx_http_finalize_request(r, IMGZIP_OK);
}

void ngx_http_upstream_dbd_handler(ngx_event_t *ev) {
	ngx_connection_t *c;
	ngx_http_request_t *r;
	ngx_http_upstream_t *u;

	c = ev->data;
	r = c->data;

	u = r->upstream;

	if (ev->write) {
		u->write_event_handler(r, u);

	} else {
		u->read_event_handler(r, u);
	}

}

static ngx_int_t ngx_http_upstream_dbd_reinit(ngx_http_request_t *r,ngx_http_upstream_t *u) {
	ngx_chain_t *cl;

	if (u->reinit_request(r) != IMGZIP_OK) {
		return IMGZIP_ERR;
	}

	ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));

	if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
			sizeof(ngx_table_elt_t)) != IMGZIP_OK) {
		return IMGZIP_ERR;
	}

	/* reinit the request chain */

	for (cl = u->request_bufs; cl; cl = cl->next) {
		cl->buf->pos = cl->buf->start;
	}
	/* reinit the subrequest's ngx_output_chain() context */

	if (r->request_body && u->output.buf) {
		u->output.free = ngx_alloc_chain_link(r->pool);
		if (u->output.free == NULL) {
			return IMGZIP_OK;
		}

		u->output.free->buf = u->output.buf;
		u->output.free->next = NULL;

		u->output.buf->pos = u->output.buf->start;
		u->output.buf->last = u->output.buf->start;
	}

	u->output.buf = NULL;
	u->output.in = NULL;
	u->output.busy = NULL;

	/* reinit u->buffer */

	u->buffer.pos = u->buffer.start;

	u->buffer.last = u->buffer.pos;

	return IMGZIP_OK;
}

size_t ngx_http_drizzle_get_num_size(uint64_t i) {
	size_t n = 0;

	do {
		i = i / 10;
		n++;
	} while (i > 0);

	return n;
}

ngx_uint_t ngx_http_drizzle_queue_size(ngx_queue_t *queue) {
	ngx_queue_t *q;
	ngx_uint_t n = 0;

	for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q =
			ngx_queue_next(q)) {
		n++;
	}

	return n;
}

static ngx_int_t ngx_http_get_drizzle_peer(ngx_http_request_t *r,
		ngx_http_image_entry_t *entry, img_drizzle_host *host,
		drizzle_ctx **ctx) {
	int fd;
	ngx_connection_t *c;
//	drizzle_st       *dp;
//	drizzle_st   *dc;
	drizzle_return_t ret;

//	sprintf(des, "DBWWW58COM_PIC_%d", (int)entry->db_id);

	(*ctx)->db = NULL;
	(*ctx)->dc = NULL;

	/*	(*ctx)->db = drizzle_create((*ctx)->db);
	 if((*ctx)->db == NULL){
	 perror("drizzle_create failed");
	 }

	 (*ctx)->dc = drizzle_con_create((*ctx)->db, (*ctx)->dc);
	 if((*ctx)->dc == NULL) {
	 perror("drizzle_con_create failed");
	 }

	 dp = (*ctx)->db;
	 dc = (*ctx)->dc;

	 memcpy(dc->user, host->user_name.data, host->user_name.len);
	 dc->user[host->user_name.len] ='\0';

	 memcpy(dc->password, host->pass_word.data, host->pass_word.len);
	 dc->password[host->pass_word.len] = '\0';

	 #if 0
	 memcpy(dc->db, des, strlen(des));
	 dc->db[strlen((char*)des)] ='\0';
	 #endif

	 drizzle_add_options(dp, DRIZZLE_NON_BLOCKING);
	 drizzle_con_add_options(dc, DRIZZLE_CON_MYSQL);

	 drizzle_con_set_tcp(dc, (char*)host->address.data, host->port);

	 ret = drizzle_con_connect(dc);

	 if (ret != DRIZZLE_RETURN_OK && ret != DRIZZLE_RETURN_IO_WAIT) {
	 printf("drizzle_con_connect first\n");
	 drizzle_con_free(dc);
	 return IMGZIP_ERR;
	 }
	 fd = drizzle_con_fd(dc);*/

//	in_port_t port = 3310;
//	drizzle_st *con = drizzle_create_tcp((const char *)"192.168.120.7",port,(const char *)"pic58user",(const char *)"pic58user123456",(const char *)"DBWWW58COM_PIC_102",DRIZZLE_CON_OPTIONS_NON_BLOCKING);
//	drizzle_st *con = drizzle_create_tcp((const char *)"192.168.120.7",port,(const char *)"pic58user",(const char *)"pic58user123456",(const char *)"DBWWW58COM_PIC_102",0);
//	drizzle_st *con = drizzle_create_tcp((const char *)host->address.data,host.port,(const char *)host->user_name.data,(const char *)host->pass_word.data,(const char *)host->dbname.data,0);

//	ngx_http_upstream_t *upstream = r->upstream;
	ngx_peer_connection_t *pc = &r->upstream->peer;
	ngx_http_drizzle_keepalive_cache_t *item;
	ngx_queue_t *q;
	(*ctx)->host = host; //img_drizzle_host
	if (!ngx_queue_empty(&host->cache)) {
//		printf("从队列取pic数据\n");
		log_print(LOG_LEVEL_INFO,"ngx_http_get_drizzle_peer--从队列取pic数据");
		q = ngx_queue_head(&host->cache);
		ngx_queue_remove(q);

		item = ngx_queue_data(q, ngx_http_drizzle_keepalive_cache_t, queue);
		c = item->connection;

		ngx_queue_insert_head(&host->free, q);

		pc->connection = c;
		pc->cached = 1;

		(*ctx)->db = item->drizzle_db;
		(*ctx)->dc = item->drizzle_db;
		return IMGZIP_OK;
	}

	drizzle_st *con = drizzle_create_tcp((const char *) host->address.data,
			host->port, (const char*) host->user_name.data,
			(const char *) host->pass_word.data,
			(const char *) host->dbname.data, 0);
	(*ctx)->db = con;
	(*ctx)->dc = con;
	ret = drizzle_connect(con);
	fd = drizzle_fd(con);

	log_print(LOG_LEVEL_INFO,"ngx_http_get_drizzle_peer---drizzle_create_tcp!");
	if (fd == -1) {
//		printf("ngx_http_get_drizzle_peer--->drizzle_con_fd\n");
		log_print(LOG_LEVEL_ERROR,"ngx_http_get_drizzle_peer--->drizzle_connect() failed!");
		return IMGZIP_ERR;
	}

	c = ngx_get_connection(fd);
	if (c == NULL) {
		log_print(LOG_LEVEL_ERROR,"ngx_http_get_drizzle_peer--->ngx_get_connection");
		return IMGZIP_ERR;
	}

	if (ngx_nonblocking(fd) == IMGZIP_ERR) {
//		printf("ngx_nonblocking error\n");
		log_print(LOG_LEVEL_ERROR,"ngx_nonblocking error");
		return IMGZIP_ERR;
	}

	pc->connection = c;

	//modified by lizt 2013-03-05
//	c->data = r;
//	c->write->handler = ngx_http_upstream_dbd_handler;
//	c->read->handler = ngx_http_upstream_dbd_handler;
//
//	upstream->write_event_handler = ngx_http_drizzle_wev_handler;
//	upstream->read_event_handler = ngx_http_drizzle_rev_handler;
  //	end
#if 1
	if (ngx_epoll_add_connection(c) == IMGZIP_ERR) {
//		return IMGZIP_ERR;
		goto failed;
	}
#endif
	if (ret == DRIZZLE_RETURN_IO_WAIT) {
		(*ctx)->state = state_db_connect;
		if (c->write->timer_set) {
			ngx_event_del_timer(c->write);
		}
		ngx_event_add_timer(c->write, CONNECT_TIMEOUT);
		log_print(LOG_LEVEL_INFO,"ngx_http_get_drizzle_peer--->IMGZIP_AGAIN");
		return IMGZIP_AGAIN;
	}

	if (ret != DRIZZLE_RETURN_OK) {
		log_print(LOG_LEVEL_ERROR,"ngx_http_get_drizzle_peer--->drizzle_con_connect");
		return IMGZIP_ERR;
	}

	return IMGZIP_OK;

	failed:

	ngx_free_connection(c);
   drizzle_quit(con);
	return IMGZIP_ERR;
}

void ngx_http_upstream_drizzle_finalize_request(ngx_http_request_t *r,
		ngx_http_upstream_t *u, ngx_int_t rc) {

	if (u->cleanup) {
		*u->cleanup = NULL;
	}

	if (u->finalize_request) {
		u->finalize_request(r, rc);
	}

	if (u->header_sent && rc == IMGZIP_ERR) {
		rc = 0;
	}

	if (rc == IMGZIP_DECLINED) {
		return;
	}

	ngx_http_finalize_request(r, rc);
}
