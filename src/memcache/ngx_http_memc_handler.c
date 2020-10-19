/*
 * ngx_http_memc_handler.c
 *
 *  Created on: 2013-4-2
 *      Author: lizhitao
 */


#define DDEBUG 0

#include "ngx_http_memc_consistent_hash.h"
#include "ngx_http_memc_handler.h"
#include "ngx_http_memc_request.h"
#include "ngx_http_memc_response.h"
#include "../server/ngx_event_connect.h"
#include "../server/ngx_cycle.h"
#include "../server/ngx_epoll_module.h"
#include "../util/ngx_send.h"
#include "../util/ngx_recv.h"
#include "../util/ngx_writev_chain.h"
#include "../util/ngx_readv_chain.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <arpa/inet.h>
static ngx_int_t ngx_http_memc_reinit_request(ngx_http_request_t *r);
static void ngx_http_memc_abort_request(ngx_http_request_t *r);
static void ngx_http_memc_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_http_memc_init_request(ngx_http_request_t *r);
static void ngx_http_memc_connect(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_memc_handler(ngx_event_t *ev);
static void ngx_http_memc_send_request_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_memc_send_request(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_memc_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_memc_process_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_memc_reinit(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_memc_test_connect(ngx_connection_t *c,ngx_http_request_t *r);
static ngx_int_t ngx_memc_create_connect_peer(ngx_http_request_t *r, ngx_peer_connection_t *pc);
static void ngx_http_memc_keepalive_close_handler(ngx_event_t *ev);
static void ngx_http_memc_cleanup(void *data);
static ngx_uint_t ngx_http_memc_client_hash_fun(void *node, int index);
static ngx_uint_t ngx_http_memc_key_hash_fun(ngx_str_t *key);
static ngx_uint_t ngx_http_memc_check_node(void *node);

typedef struct {
	ngx_str_t ip;
	int port;
} ngx_http_memc_server_info_t;

typedef struct {
	ngx_queue_t queue;
	ngx_connection_t *connection;
	socklen_t socklen;
	struct sockaddr_storage sockaddr;
	ngx_http_memc_rr_peer_t *rr_peer;
} ngx_http_memc_keepalive_cache_t;

#define memc_max_cached_size 5
#define memc_recv_buf 40960
#define retry_time 60
#define memc_client_max_fails 5

ngx_int_t ngx_http_memc_init() {
	ngx_http_memc_keepalive_cache_t *cached;
	ngx_uint_t i = 0, memc_client_num = 0;
	socklen_t socklen;
	struct sockaddr_in *sa;
	ngx_http_memc_rr_peer_t **memc_rr_peer, *rr_peer;
	u_char *p;
	imgzip_memc_conf_t *memc_conf = imgzip_server_conf.memc_conf;
	while (memc_conf) {
		memc_client_num++;
		memc_conf = memc_conf->next;
	}
	memc_conf = imgzip_server_conf.memc_conf;
	memc_rr_peer = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_http_memc_rr_peer_t*) * memc_client_num);
	char ip[sizeof("255.255.255.255")];
	memc_client_num = 0;
	while (memc_conf) {
		memcpy(ip, memc_conf->memc_ip.data, memc_conf->memc_ip.len);
		ip[memc_conf->memc_ip.len] = '\0';
		rr_peer = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_http_memc_rr_peer_t));
		sa = ngx_pcalloc(ngx_cycle->pool, sizeof(struct sockaddr_in));
		if (sa == NULL) {
			return IMGZIP_ERR;
		}
		p = ngx_palloc(ngx_cycle->pool, sizeof("255.255.255.255:65535") - 1);
		if (p == NULL) {
			return IMGZIP_ERR;
		}
		socklen = sizeof(struct sockaddr);
		sa->sin_family = AF_INET;
		sa->sin_port = htons(memc_conf->port); //该套接字对___PORT端口数据进行监听

		if (inet_aton(ip, &sa->sin_addr) == 0) {
			struct hostent *he;

			he = gethostbyname(ip);
			if (he == NULL) {
				return IMGZIP_ERR;
			}
			memcpy(&sa->sin_addr, he->h_addr, sizeof(struct in_addr));
		}
		size_t len = ngx_sock_ntop((struct sockaddr *) sa, p, sizeof("255.255.255.255:65535") - 1, memc_conf->port);
		cached = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_http_memc_keepalive_cache_t) * memc_max_cached_size);
		if (cached == NULL) {
			return IMGZIP_ERR;
		}

		ngx_queue_init(&rr_peer->cache);
		ngx_queue_init(&rr_peer->free);

		for (i = 0; i < memc_max_cached_size; i++) {
			ngx_queue_insert_head(&rr_peer->free, &cached[i].queue);
		}
		rr_peer->sockaddr = (struct sockaddr *) sa;
		rr_peer->socklen = socklen;
		rr_peer->name.len = len;
		rr_peer->name.data = p;
		rr_peer->fails = 0;
		memc_rr_peer[memc_client_num] = rr_peer;
		++memc_client_num;
		memc_conf = memc_conf->next;
	}
	ngx_http_memc_consistent_hash_init(ngx_cycle->pool, memc_client_num, ngx_http_memc_client_hash_fun, (void**) memc_rr_peer, memc_client_num, 1);
	return IMGZIP_OK;
}

ngx_int_t ngx_http_memc_get_handler(ngx_http_request_t *r, ngx_str_t *key, memc_callback callback) {
	ngx_http_upstream_t *u;
	ngx_http_memc_ctx_t *ctx;
	log_print(LOG_LEVEL_DEBUG, "ngx_http_memc_get_handler");
	u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
	if (u == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if (u && u->cleanup) {
		ngx_http_memc_cleanup(r);
	}
	r->upstream = u;

	ctx = ngx_palloc(r->pool, sizeof(ngx_http_memc_ctx_t));
	if (ctx == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ctx->rr_peer = NULL;
	ctx->key.data = key->data;
	ctx->key.len = key->len;
	ctx->parser_state = IMGZIP_ERR;

	ctx->rest = NGX_HTTP_MEMC_END;
	ctx->request = r;
	ctx->callback = callback;
	ctx->cmd.data = (u_char*) "get";
	ctx->cmd.len = sizeof("get") - 1;

	ngx_http_set_ctx(r, ctx, 1);

	u->create_request = ngx_http_memc_create_get_cmd_request;
	u->process_header = ngx_http_memc_process_get_cmd_header;

	u->input_filter_init = ngx_http_memc_get_cmd_filter_init;
	u->input_filter = ngx_http_memc_get_cmd_filter;

	u->reinit_request = ngx_http_memc_reinit_request;
	u->abort_request = ngx_http_memc_abort_request;
	u->finalize_request = ngx_http_memc_finalize_request;

	u->input_filter_ctx = ctx;

	ngx_http_memc_init_request(r);

//	return IMGZIP_DONE;
	return IMGZIP_OK;
}

ngx_int_t ngx_http_memc_set_handler(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value, memc_callback callback) {
	ngx_http_upstream_t *u;
	ngx_http_memc_ctx_t *ctx;
	log_print(LOG_LEVEL_DEBUG, "ngx_http_memc_set_handler");
	u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
	if (u == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->upstream = u;
	r->count++;  //暂时注释掉看是不是这块内存问题
	ctx = ngx_palloc(r->pool, sizeof(ngx_http_memc_ctx_t));
	if (ctx == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ctx->rr_peer = NULL;
	ctx->key.data = key->data;
	ctx->key.len = key->len;
	ctx->parser_state = IMGZIP_ERR;
	ctx->value.data = value->data;
	ctx->value.len = value->len;
	ctx->rest = NGX_HTTP_MEMC_END;
	ctx->request = r;
	ctx->callback = callback;
	ctx->cmd.data = (u_char*) "set";
	ctx->cmd.len = sizeof("set") - 1;

	ngx_http_set_ctx(r, ctx, 1);

	u->create_request = ngx_http_memc_create_storage_cmd_request;
	u->process_header = ngx_http_memc_process_set_header;

	u->input_filter_init = ngx_http_memc_empty_filter_init;
	u->input_filter = ngx_http_memc_empty_filter;

	u->reinit_request = ngx_http_memc_reinit_request;
	u->abort_request = ngx_http_memc_abort_request;
	u->finalize_request = ngx_http_memc_finalize_request;

	u->input_filter_ctx = ctx;

	ngx_http_memc_init_request(r);

	return IMGZIP_DONE;
}
static ngx_int_t ngx_http_memc_reinit_request(ngx_http_request_t *r) {
	return IMGZIP_OK;
}

static void ngx_http_memc_abort_request(ngx_http_request_t *r) {
	return;
}

static void ngx_http_memc_init_request(ngx_http_request_t *r) {

	ngx_connection_t *c;
	ngx_http_upstream_t *u;
	ngx_http_cleanup_t *cln;
	c = r->connection;

	if (c->read->timer_set) {
		ngx_event_del_timer(c->read);
	}

	u = r->upstream;

	if (u->create_request(r) != IMGZIP_OK) { // 创建请求命令参数 get key\n\r
		ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	u->output.pool = r->pool;
	u->output.bufs.num = 1;
	u->output.bufs.size = client_body_buffer_size;
	u->output.output_filter = ngx_chain_writer;             //调用ngx_output_chain.c中ngx_chain_writer方法
	u->output.filter_ctx = &u->writer;
	u->writer.pool = r->pool;
	cln = ngx_http_cleanup_add(r, 0);
	if (cln == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	cln->handler = ngx_http_memc_cleanup;
	cln->data = r;
	u->cleanup = &cln->handler;
	ngx_http_memc_connect(r, u);

	return;

}

static void ngx_http_memc_connect(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_int_t rc;
	ngx_connection_t *c;

	rc = ngx_memc_create_connect_peer(r, &u->peer);

	log_print(LOG_LEVEL_DEBUG, "http memc connect: %i", rc);

	if (rc == IMGZIP_ERR) {
		ngx_http_memc_finalize_request(r, NGX_HTTP_BAD_GATEWAY);
		return;
	}

	if (rc == IMGZIP_DECLINED) {
		ngx_http_memc_finalize_request(r, NGX_HTTP_BAD_GATEWAY);
		return;
	}

	c = u->peer.connection;

	c->data = r;

	c->write->handler = ngx_http_memc_handler;
	c->read->handler = ngx_http_memc_handler;

	u->write_event_handler = ngx_http_memc_send_request_handler;
	u->read_event_handler = ngx_http_memc_process_handler;

	c->sendfile &= r->connection->sendfile;
	u->output.sendfile = c->sendfile;

	c->pool = r->pool;

	/* init or reinit the ngx_output_chain() and ngx_chain_writer() contexts */

	u->writer.out = NULL;
	u->writer.last = &u->writer.out;
	u->writer.connection = c;
	u->writer.limit = 0;

	if (u->request_sent) {
		if (ngx_http_memc_reinit(r, u) != IMGZIP_OK) {
			ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}

	u->request_sent = 0;

	if (rc == IMGZIP_AGAIN) {
		ngx_event_add_timer(c->write, CONNECT_TIMEOUT);
		return;
	}

	ngx_http_memc_send_request(r, u);
}
static ngx_int_t ngx_memc_create_connect_peer(ngx_http_request_t *r, ngx_peer_connection_t *pc) {
	int rc;
	ngx_err_t err;
	int s;
	ngx_event_t *rev, *wev;
	ngx_connection_t *c;
	ngx_queue_t *q;
	ngx_http_memc_keepalive_cache_t *item;
	ngx_http_memc_rr_peer_t *rr_peer;
	ngx_http_memc_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, 1);
	rr_peer = ngx_http_memc_consistent_hash_get(&ctx->key, ngx_http_memc_key_hash_fun, ngx_http_memc_check_node);
	if (rr_peer == NULL) {
		return IMGZIP_ERR;
	}
	ctx->rr_peer = rr_peer;
	pc->sockaddr = rr_peer->sockaddr;
	pc->socklen = rr_peer->socklen;
	pc->name = &rr_peer->name;
	pc->rcvbuf = memc_recv_buf;
	if (!ngx_queue_empty(&rr_peer->cache)) {

		q = ngx_queue_head(&rr_peer->cache);
		ngx_queue_remove(q);

		item = ngx_queue_data(q, ngx_http_memc_keepalive_cache_t, queue);
		c = item->connection;

		ngx_queue_insert_head(&rr_peer->free, q);

		pc->connection = c;
		pc->cached = 1;

		return IMGZIP_OK;
	}
	s = socket(pc->sockaddr->sa_family, SOCK_STREAM, 0);

	if (s == -1) {
		log_print(LOG_LEVEL_ERROR, "create socket failed");
		return IMGZIP_ERR;
	}

	c = ngx_get_connection(s);

	if (c == NULL) {
		if (close(s) == -1) {
			log_print(LOG_LEVEL_ERROR, "close socket failed");
		}

		return IMGZIP_ERR;
	}

	if (pc->rcvbuf) {
		if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const void *) &pc->rcvbuf, sizeof(int)) == -1) {
			log_print(LOG_LEVEL_ERROR, "setsockopt(SO_RCVBUF) failed");
			goto failed;
		}
	}

	if (ngx_nonblocking(s) == -1) {
		log_print(LOG_LEVEL_ERROR, "ngx_nonblocking(s) failed");

		goto failed;
	}

	if (pc->local) {
		if (bind(s, pc->local->sockaddr, pc->local->socklen) == -1) {
			log_print(LOG_LEVEL_ERROR, "bind(%V) failed", &pc->local->name);

			goto failed;
		}
	}

	c->recv = ngx_unix_recv;
	c->send = ngx_unix_send;
	c->recv_chain = ngx_readv_chain;
	c->send_chain = ngx_writev_chain;

	c->sendfile = 1;

	c->log_error = pc->log_error;

	if (pc->sockaddr->sa_family != AF_INET) {
		c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
		c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

	}

	rev = c->read;
	wev = c->write;

	pc->connection = c;

	c->number = __sync_fetch_and_add(ngx_connection_counter, 1);

	if (ngx_epoll_add_connection(c) == IMGZIP_ERR) {
		goto failed;
	}

//	struct sockaddr_in SA;
//	SA.sin_family = AF_INET;
//	SA.sin_port = ntohs(11211);
//	SA.sin_addr.s_addr = inet_addr("192.168.119.95");
//   rc = connect(s, (struct sockaddr *)&SA, sizeof(struct sockaddr));
//   printf("rc:%d\n",rc);

	rc = connect(s, pc->sockaddr, pc->socklen);

	if (rc == -1) {
		err = errno;

		if (err != EINPROGRESS) {

			log_print(LOG_LEVEL_ERROR, "connect() to %V failed", pc->name);

			goto failed;
		}
	}

	if (rc == -1) {

		return IMGZIP_AGAIN;
	}

	log_print(LOG_LEVEL_DEBUG, "connected");

	wev->ready = 1;

	return IMGZIP_OK;

	failed:

	ngx_free_connection(c);

	if (close(s) == -1) {
		log_print(LOG_LEVEL_ERROR, "close(s) failed");
	}
	rr_peer->fails++;
	return IMGZIP_ERR;
}

static void ngx_http_memc_handler(ngx_event_t *ev) {
	ngx_connection_t *c;
	ngx_http_request_t *r;
	ngx_http_upstream_t *u;

	c = ev->data;
	r = c->data;

	u = r->upstream;
	c = r->connection;

	if (ev->write) {
		u->write_event_handler(r, u);

	} else {
		u->read_event_handler(r, u);
	}

	ngx_http_run_posted_requests(c);
}

static void ngx_http_memc_send_request_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_connection_t *c;

	c = u->peer.connection;

	log_print(LOG_LEVEL_DEBUG, "http memc send request handler");

	if (c->write->timedout) {
		ngx_http_memc_finalize_request(r, NGX_HTTP_GATEWAY_TIME_OUT);
		return;
	}

	if (u->header_sent) {
		u->write_event_handler = ngx_http_memc_dummy_handler;

		(void) ngx_handle_write_event(c->write);

		return;
	}

	ngx_http_memc_send_request(r, u);
}

static void ngx_http_memc_send_request(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_int_t rc;
	ngx_connection_t *c;

	c = u->peer.connection;

	log_print(LOG_LEVEL_DEBUG, "http memc send request,u->request_sent is %i",u->request_sent);

	log_print(LOG_LEVEL_INFO, "ngx_http_memc_send_request");
	if (!u->request_sent && ngx_http_memc_test_connect(c,r) != IMGZIP_OK) {
//		if (!u->request_sent && ngx_http_memc_test_connect(c) != IMGZIP_OK) {
		ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	rc = ngx_output_chain(&u->output, u->request_sent ? NULL : u->request_bufs);  //发送memcached 的 get key命令 u->request_bufs 为comand数据

	u->request_sent = 1;

	if (rc == IMGZIP_ERR) {
		ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	if (rc == IMGZIP_AGAIN) {
		ngx_event_add_timer(c->write, SEND_TIMEOUT);

		if (ngx_handle_write_event(c->write) != IMGZIP_OK) {
			ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		return;
	}
	u->write_event_handler = ngx_http_memc_dummy_handler;
	if (c->write->timer_set) {
		ngx_event_del_timer(c->write);
	}

	if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
		if (ngx_tcp_push(c->fd) == IMGZIP_ERR) {
			log_print(LOG_LEVEL_ERROR, "ngx_tcp_push(c->fd) failed");
			ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
	}

	ngx_event_add_timer(c->read, read_timeout);

/** ------------------ **/
//	ngx_http_memc_process_handler(r, u);
//	return ;
/** ------------------ **/

	if (c->read->ready) {
		ngx_http_memc_process_handler(r, u);
		return;
	}

	if (ngx_handle_write_event(c->write) != IMGZIP_OK) {
		ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
}

static void ngx_http_memc_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
}
static void ngx_http_memc_keepalive_dummy_handler(ngx_event_t *ev) {

}
static ngx_int_t ngx_http_memc_test_connect(ngx_connection_t *c,ngx_http_request_t *r) {
	int err;
	socklen_t len;

	err = 0;
	len = sizeof(int);

	if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
		err = errno;
	}

	if (err) {
		ngx_http_memc_ctx_t *ctx;
		ctx = ngx_http_get_module_ctx(r, 1);
//		if(ctx->key.data){  //http://10.5.11.36:8093/p1/tiny/n_1636066112244248.jpg 此url页面报错 未收到数据
//			ctx->key.data[ctx->key.len] = '\0';
//			ctx->cmd.data[ctx->cmd.len] = '\0';
//			log_print(LOG_LEVEL_ERROR, "memc connect() failed!imgzip image is %s,cmd is %s",ctx->key.data,ctx->cmd.data);
//		} else
			log_print(LOG_LEVEL_ERROR, "memc connect() failed!");

		return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}
void ngx_http_memc_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
	ngx_http_upstream_t *u;
	ngx_connection_t *c;
	ngx_queue_t *q;
	ngx_http_memc_keepalive_cache_t *item;
	ngx_http_memc_ctx_t *ctx;
	log_print(LOG_LEVEL_DEBUG, "finalize http memc request: %i", rc);
	u = r->upstream;
	if (u->cleanup) {
		*u->cleanup = NULL;
		u->cleanup = NULL;
	}
	ctx = ngx_http_get_module_ctx(r, 1);
	if (u->peer.connection != NULL && (rc == NGX_HTTP_NOT_FOUND || rc == NGX_HTTP_OK || rc == IMGZIP_OK)) {
		c = u->peer.connection;

		if (ngx_queue_empty(&ctx->rr_peer->free)) {

			q = ngx_queue_last(&ctx->rr_peer->cache);
			ngx_queue_remove(q);

			item = ngx_queue_data(q, ngx_http_memc_keepalive_cache_t,queue);

			ngx_close_connection(item->connection);

		} else {
			q = ngx_queue_head(&ctx->rr_peer->free);
			ngx_queue_remove(q);

			item = ngx_queue_data(q, ngx_http_memc_keepalive_cache_t,
					queue);
		}
		item->connection = c;
		item->rr_peer = ctx->rr_peer;
		c->data = item;
		ngx_queue_insert_head(&ctx->rr_peer->cache, q);

		u->peer.connection = NULL;

		if (c->read->timer_set) {
			ngx_event_del_timer(c->read);
		}
		if (c->write->timer_set) {
			ngx_event_del_timer(c->write);
		}

		c->write->handler = ngx_http_memc_keepalive_dummy_handler;
		c->read->handler = ngx_http_memc_keepalive_close_handler;

		c->idle = 1;
		ctx->rr_peer->fails = 0;
	} else if (ctx->rr_peer) {
		ctx->rr_peer->fails++;
	}
	if (u->peer.connection) {

		log_print(LOG_LEVEL_DEBUG, "close http memc connection: %d", u->peer.connection->fd);

		ngx_close_connection(u->peer.connection);
	}

	u->peer.connection = NULL;
	if (rc != IMGZIP_DONE) {
		ctx = ngx_http_get_module_ctx(r, 1);
		ctx->callback(r, rc);
	}
}

static void ngx_http_memc_process_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ssize_t n;
	ngx_int_t rc;
	ngx_connection_t *c;

	c = u->peer.connection;

	log_print(LOG_LEVEL_DEBUG, "http memc process handler");

	if (c->read->timedout) {
		ngx_http_memc_finalize_request(r, NGX_HTTP_GATEWAY_TIME_OUT);
		return;
	}
	log_print(LOG_LEVEL_INFO, "ngx_http_memc_process_handler,u->request_sent is %i",u->request_sent);
	if (!u->request_sent && ngx_http_memc_test_connect(c,r) != IMGZIP_OK) {
//			if (!u->request_sent && ngx_http_memc_test_connect(c) != IMGZIP_OK) {
		ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	if (u->buffer.start == NULL) {
		u->buffer.start = ngx_palloc(r->pool, client_body_buffer_size);
		if (u->buffer.start == NULL) {
			ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		u->buffer.pos = u->buffer.start;
		u->buffer.last = u->buffer.start;
		u->buffer.end = u->buffer.start + client_body_buffer_size;
		u->buffer.temporary = 1;

		u->buffer.tag = u->output.tag;
	}

	for (;;) {

		n = c->recv(c, u->buffer.last, u->buffer.end - u->buffer.last);  //调用ngx_recv.c中ngx_unix_recv方法 ,读取图片(pic)数据

		if (n == IMGZIP_AGAIN) {

			if (ngx_handle_read_event(c->read) != IMGZIP_OK) {
				ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			return;
		}

		if (n == 0) {
			log_print(LOG_LEVEL_ERROR, "memc prematurely closed connection");
		}

		if (n == IMGZIP_ERR || n == 0) {
			ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		u->buffer.last += n;

		rc = u->process_header(r);     //调用ngx_http_memc_response.c中ngx_http_memc_process_get_cmd_header方法

		if (rc == IMGZIP_AGAIN) {

			if (u->buffer.pos == u->buffer.end) {
				log_print(LOG_LEVEL_ERROR, "memc sent too big header");
				ngx_http_memc_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			continue;
		}

		break;
	}

	if (rc != IMGZIP_OK) {
		rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
		ngx_http_memc_finalize_request(r, rc);
	}
}
static ngx_int_t ngx_http_memc_reinit(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_chain_t *cl;

	if (ngx_http_memc_reinit_request(r) != IMGZIP_OK) {
		return IMGZIP_ERR;
	}

	ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));

	if (ngx_list_init(&u->headers_in.headers, r->pool, 8, sizeof(ngx_table_elt_t)) != IMGZIP_OK) {
		return IMGZIP_ERR;
	}

	/* reinit the request chain */

	for (cl = u->request_bufs; cl; cl = cl->next) {
		cl->buf->pos = cl->buf->start;
	}

	/* reinit the subrequest's ngx_output_chain() context */

	u->output.buf = NULL;
	u->output.in = NULL;
	u->output.busy = NULL;

	/* reinit u->buffer */

	u->buffer.pos = u->buffer.start;

	u->buffer.last = u->buffer.pos;

	return IMGZIP_OK;
}

static void ngx_http_memc_keepalive_close_handler(ngx_event_t *ev) {
	ngx_http_memc_keepalive_cache_t *item;
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
	ngx_queue_insert_head(&item->rr_peer->free, &item->queue);
}
static void ngx_http_memc_cleanup(void *data) {
	ngx_http_request_t *r = data;

	ngx_http_upstream_t *u;

	log_print(LOG_LEVEL_DEBUG, "cleanup http upstream request: \"%V\"", &r->uri);

	u = r->upstream;

	ngx_http_memc_finalize_request(r, IMGZIP_DONE);
}
static ngx_uint_t ngx_http_memc_client_hash_fun(void *node, int index) {
	ngx_http_memc_rr_peer_t *rr_peer;
	ngx_uint_t hash1 = 5381;
	ngx_uint_t hash2 = hash1;
	int i = 0;
	rr_peer = node;
	u_char *str;
	str = rr_peer->name.data;
	for (i = 0; i < rr_peer->name.len; i++) {
		hash1 = ((hash1 << 5) + hash1) ^ *str;
		if (++i >= rr_peer->name.len) {
			break;
		}
		str += 1;
		hash2 = ((hash2 << 5) + hash2) ^ *str;
		str += 1;
	}
	hash2 = ((hash2 << 5) + hash2) ^ (index * index);
	return hash1 + (hash2 * 1566083941);
}
static ngx_uint_t ngx_http_memc_key_hash_fun(ngx_str_t *key) {

	ngx_uint_t hash1 = 5381;
	ngx_uint_t hash2 = 0;
	size_t len;
	int i = 0;
	u_char *str;
	str = key->data;
	len = key->len;

	for (i = 0; i < len; i++) {
		hash1 = ((hash1 << 5) + hash1) ^ *str;
		if (++i >= key->len) {
			break;
		}
		str += 1;
		hash2 = 31 * hash2 + *str;
		str += 1;
	}
	return hash1 + (hash2 * 1566083941);

}
static ngx_uint_t ngx_http_memc_check_node(void *node) {
	ngx_http_memc_rr_peer_t *rr_peer;
	rr_peer = node;
	if (rr_peer->fails >= memc_client_max_fails) {
		if (rr_peer->accessed + retry_time < ngx_time()) {
			rr_peer->accessed = ngx_time();
			rr_peer->fails = 0;
			return IMGZIP_OK;
		}
//		log_print(LOG_LEVEL_ERROR, "memcached client shutdown:%V", &rr_peer->name);
		return IMGZIP_ERR;
	}
	rr_peer->accessed = ngx_time();
	log_print(LOG_LEVEL_DEBUG, "select memcached client:%V", &rr_peer->name);
	return IMGZIP_OK;
}
