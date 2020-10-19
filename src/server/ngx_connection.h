/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"

#include "../util/ngx_event_timer.h"
#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>

typedef ssize_t (*ngx_recv_pt)(ngx_connection_t *c, u_char *buf, size_t size);
typedef ssize_t (*ngx_recv_chain_pt)(ngx_connection_t *c, ngx_chain_t *in);
typedef ssize_t (*ngx_send_pt)(ngx_connection_t *c, u_char *buf, size_t size);
typedef ngx_chain_t *(*ngx_send_chain_pt)(ngx_connection_t *c, ngx_chain_t *in, off_t limit);
struct ngx_listening_s {

	int fd;
	struct sockaddr *sockaddr;
	socklen_t socklen; /* size of sockaddr */
	size_t addr_text_max_len;
	ngx_str_t addr_text;

	int backlog;
	int rcvbuf;
	int sndbuf;

	/* handler of accepted connection */
	ngx_connection_handler_pt handler;

	void *servers; /* array of ngx_http_in_addr_t, for example */

	size_t pool_size;
	/* should be here because of the AcceptEx() preread */
	size_t post_accept_buffer_size;
	/* should be here because of the deferred accept */
	uintptr_t post_accept_timeout;

	ngx_connection_t *connection;

	unsigned remain :1;
	unsigned ignore :1;

	unsigned bound :1; /* already bound */
	unsigned inherited :1; /* inherited from previous process */
	unsigned listen :1;
	unsigned addr_ntop :1;
};

typedef enum {
	NGX_ERROR_ALERT = 0, NGX_ERROR_ERR, NGX_ERROR_INFO, NGX_ERROR_IGNORE_ECONNRESET, NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;

typedef enum {
	NGX_TCP_NODELAY_UNSET = 0, NGX_TCP_NODELAY_SET, NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;

typedef enum {
	NGX_TCP_NOPUSH_UNSET = 0, NGX_TCP_NOPUSH_SET, NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;

#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01

struct ngx_connection_s {
	void *data;
	ngx_event_t *read;
	ngx_event_t *write;

	int fd;

	ngx_recv_pt recv;
	ngx_send_pt send;
	ngx_recv_chain_pt recv_chain;
	ngx_send_chain_pt send_chain;

	ngx_listening_t *listening;

	off_t sent;

	ngx_pool_t *pool;

	struct sockaddr *sockaddr;
	socklen_t socklen;
	ngx_str_t addr_text;

	struct sockaddr *local_sockaddr;

	ngx_buf_t *buffer;

	ngx_queue_t queue;

	ngx_atomic_uint_t number;

	ngx_uint_t requests;

	unsigned log_error :3; /* ngx_connection_log_error_e */

	unsigned single_connection :1;
	unsigned unexpected_eof :1;
	unsigned timedout :1;
	unsigned error :1;
	unsigned destroyed :1;
	unsigned buffered :8;
	unsigned idle :1;
	unsigned reusable :1;
	unsigned close :1;

	unsigned sendfile :1;
	unsigned sndlowat :1;
	unsigned tcp_nodelay :2; /* ngx_connection_tcp_nodelay_e */
	unsigned tcp_nopush :2; /* ngx_connection_tcp_nopush_e */

};

#define NGX_INVALID_INDEX  0xd0d0d0d0
ngx_listening_t *ngx_create_listening(ngx_cycle_t *cycle, struct sockaddr_in *sockaddr, socklen_t socklen);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);

ngx_connection_t *ngx_get_connection(int s);
void ngx_free_connection(ngx_connection_t *c);
size_t ngx_sock_ntop(struct sockaddr *sa, u_char *text, size_t len, ngx_uint_t port);
void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
