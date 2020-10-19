/*
 * Copyright (C) Igor Sysoev
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_http_upstream_round_robin.h"
#include "ngx_http.h"
#include "ngx_event_connect.h"
#include "ngx_cycle.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <arpa/inet.h>
typedef struct {
	ngx_str_t ip;
	int port;
} ngx_http_upstream_server_info_t;
#define upstream_server_info_num 2

ngx_http_upstream_server_info_t upstream_server_info[upstream_server_info_num] = { { { sizeof("10.58.120.112") - 1, (u_char *) "10.58.120.112" }, 80 }, { { sizeof("10.58.120.112")
		- 1, (u_char *) "10.58.120.112" }, 80 } };
static ngx_http_upstream_rr_peer_data_t ngx_http_upstream_rr_peer_data = { NULL, 0, 0 };
ngx_int_t ngx_http_upstream_init_round_robin() {
	ngx_uint_t i, n;
	ngx_http_upstream_rr_peer_t *server;
	ngx_http_upstream_rr_peers_t *peers;

	n = upstream_server_info_num;
	peers = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_http_upstream_rr_peers_t));
	server = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_http_upstream_rr_peer_t) * n);
	if (peers == NULL || server == NULL) {
		return IMGZIP_ERR;
	}
	peers->next = server;
	peers->single = (n == 1);
	peers->number = n;
	for (i = 0; i < n; ++i) {
		struct sockaddr_in *sa = ngx_pcalloc(ngx_cycle->pool, sizeof(struct sockaddr_in));
		if (sa == NULL) {
			return IMGZIP_ERR;
		}
		u_char *p = ngx_palloc(ngx_cycle->pool, sizeof("255.255.255.255:65535") - 1);
		if (p == NULL) {
			return IMGZIP_ERR;
		}
		socklen_t socklen = sizeof(struct sockaddr);
		sa->sin_family = AF_INET;
		sa->sin_port = htons(upstream_server_info[i].port); //该套接字对___PORT端口数据进行监听
		size_t len = ngx_sock_ntop((struct sockaddr *) sa, p, 0, upstream_server_info[i].port);

		if (inet_aton((char*) upstream_server_info[i].ip.data, &sa->sin_addr) == 0) {
			struct hostent *he;

			he = gethostbyname((char*) upstream_server_info[i].ip.data);
			if (he == NULL) {
				return IMGZIP_ERR;
			}
			memcpy(&sa->sin_addr, he->h_addr, sizeof(struct in_addr));
		}

		peers->next[i].sockaddr = (struct sockaddr *) sa;
		peers->next[i].socklen = socklen;
		peers->next[i].name.len = len;
		peers->next[i].name.data = p;
		peers->next[i].weight = 10;
		peers->next[i].current_weight = 1;
		peers->next[i].max_fails = 2;
		peers->next[i].fail_timeout = 10;
	}
	ngx_http_upstream_rr_peer_data.peers = peers;
	ngx_http_upstream_rr_peer_data.current = 0;
	ngx_http_upstream_rr_peer_data.data = 0;
	return IMGZIP_OK;
}

ngx_int_t ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r) {

	r->upstream->peer.cached = 0;
	r->upstream->peer.connection = NULL;
	r->upstream->peer.tries = ngx_http_upstream_rr_peer_data.peers->number;
	return IMGZIP_OK;
}
ngx_int_t ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc) {

	time_t now;
	ngx_http_upstream_rr_peer_t *peer;

	now = ngx_time();
	if (ngx_http_upstream_rr_peer_data.peers->single) {
		peer = &ngx_http_upstream_rr_peer_data.peers->next[0];

	} else {

		for (;;) {

			peer = &ngx_http_upstream_rr_peer_data.peers->next[ngx_http_upstream_rr_peer_data.current];

			if (peer->max_fails == 0 || peer->fails < peer->max_fails) {
				break;
			}

			if (now - peer->accessed > peer->fail_timeout) {
				peer->fails = 0;
				break;
			}
			pc->tries--;

			ngx_http_upstream_rr_peer_data.current++;

			if (ngx_http_upstream_rr_peer_data.current >= ngx_http_upstream_rr_peer_data.peers->number) {
				ngx_http_upstream_rr_peer_data.current = 0;
			}

			if (pc->tries == 0) {
				log_print(LOG_LEVEL_ERROR, "round robin upstream stuck on %ui tries", ngx_http_upstream_rr_peer_data.peers->number);
				peer = &ngx_http_upstream_rr_peer_data.peers->next[ngx_http_upstream_rr_peer_data.current];
				break;
			}
		}
	}
	pc->sockaddr = peer->sockaddr;
	pc->socklen = peer->socklen;
	pc->name = &peer->name;

	return IMGZIP_OK;
}

void ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, ngx_uint_t state) {

	time_t now;
	ngx_http_upstream_rr_peer_t *peer;

	if (state == 0 && pc->tries == 0) {
		return;
	}
	if (ngx_http_upstream_rr_peer_data.peers->single) {
		return;
	}

	if (state & NGX_PEER_FAILED) {
		now = ngx_time();

		peer = &ngx_http_upstream_rr_peer_data.peers->next[ngx_http_upstream_rr_peer_data.current];

		peer->fails++;
		peer->accessed = now;

		if (peer->max_fails) {
			peer->current_weight -= peer->weight / peer->max_fails;
		}

		if (peer->current_weight < 0) {
			peer->current_weight = 0;
		}

	}

	ngx_http_upstream_rr_peer_data.current++;

	if (ngx_http_upstream_rr_peer_data.current >= ngx_http_upstream_rr_peer_data.peers->number) {
		ngx_http_upstream_rr_peer_data.current = 0;
	}

}

