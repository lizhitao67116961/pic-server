/*
 *
 *  Created on: 2013-05-17
 *      Author: lizhitao
 */


#include "ngx_http_drizzle_module.h"
#include "ngx_http_drizzle_handler.h"
#include "ngx_http_drizzle_processor.h"
#include "ngx_http_drizzle_util.h"
#include "../server/ngx_http_image_entry.h"

static ngx_int_t ngx_http_drizzle_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_drizzle_reinit_request(ngx_http_request_t *r);
static void ngx_http_drizzle_abort_request(ngx_http_request_t *r);
static void ngx_http_drizzle_finalize_request(ngx_http_request_t *r,
		ngx_int_t rc);
static ngx_int_t ngx_http_drizzle_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_drizzle_input_filter_init(void *data);
static ngx_int_t ngx_http_drizzle_input_filter(void *data, ssize_t bytes);

ngx_int_t ngx_http_drizzle_handler(ngx_http_request_t *r,ngx_http_image_entry_t *entry, ngx_drizzle_callback drizzle_callback) {
	ngx_http_upstream_t *u;

	u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
	if (u == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->upstream = u;

	u->create_request = ngx_http_drizzle_create_request; //we don't need request-header to connect with mysql
	u->reinit_request = ngx_http_drizzle_reinit_request;
	u->process_header = ngx_http_drizzle_process_header;
	u->abort_request = ngx_http_drizzle_abort_request;
	u->finalize_request = ngx_http_drizzle_finalize_request;

	u->input_filter_init = ngx_http_drizzle_input_filter_init;
	u->input_filter = ngx_http_drizzle_input_filter;

	return ngx_http_upstream_dbd_init(r, entry, drizzle_callback);;
}

void ngx_http_drizzle_wev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_connection_t *c;
	ngx_http_image_entry_t *entry;

	entry = u->peer.data;
	/* just to ensure u->reinit_request always gets called for
	 * upstream_next */
	u->request_sent = 1;

	c = u->peer.connection;

//modified by lizt 2013-03-05
/*	if (c->write->timedout) {
//		printf("c->write_timeout\n");
		log_print(LOG_LEVEL_ERROR,"c->write_timeout");
		ngx_close_connection(c); //if we don't close upstream connection, it will timeout again
		ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
		return;
	}*/

    if (c->write->timer_set) {
        ngx_event_del_timer(c->write);
    }
//end

	if (ngx_http_upstream_drizzle_test_connect(c) != IMGZIP_OK) {
//		printf("ngx_http_upstream_drizzle_test_connect\n");
		log_print(LOG_LEVEL_INFO,"ngx_http_upstream_drizzle_test_connect");
//		ngx_close_connection(c);
		ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
		return;
	}

	ngx_http_drizzle_set_libdrizzle_ready(r);

	(void) ngx_http_drizzle_process_events(r);
}

void ngx_http_drizzle_rev_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
	ngx_connection_t *c;

	/* just to ensure u->reinit_request always gets called for
	 * upstream_next */
	u->request_sent = 1;

	c = u->peer.connection;

  //modified by lizt 2013-03-05
	if (c->read->timedout) {
		printf("c->read_timeout\n");
		ngx_close_connection(c);
		ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
		return;
	}
  //end
	if (ngx_http_upstream_drizzle_test_connect(c) != IMGZIP_OK) {
//		printf("ngx_http_upstream_drizzle_test_connect\n");
		log_print(LOG_LEVEL_DEBUG,"ngx_http_upstream_drizzle_test_connect");
//		ngx_close_connection(c);
		ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
		return;
	}

	ngx_http_drizzle_set_libdrizzle_ready(r);

	(void) ngx_http_drizzle_process_events(r);
}

static ngx_int_t ngx_http_drizzle_create_request(ngx_http_request_t *r) {
	r->upstream->request_bufs = NULL;

	return IMGZIP_OK;
}

static ngx_int_t ngx_http_drizzle_reinit_request(ngx_http_request_t *r) {
	ngx_http_upstream_t *u;

	u = r->upstream;

	/* override the read/write event handler to our own */
	u->write_event_handler = ngx_http_drizzle_wev_handler;
	u->read_event_handler = ngx_http_drizzle_rev_handler;

	return IMGZIP_OK;
}

static void ngx_http_drizzle_abort_request(ngx_http_request_t *r) {
}

static void ngx_http_drizzle_finalize_request(ngx_http_request_t *r,
		ngx_int_t rc) {
}

static ngx_int_t ngx_http_drizzle_process_header(ngx_http_request_t *r) {

	return IMGZIP_ERR;
}

static ngx_int_t ngx_http_drizzle_input_filter_init(void *data) {
	ngx_http_request_t *r;
	r = (ngx_http_request_t*) data;
	return IMGZIP_ERR;
}

static ngx_int_t ngx_http_drizzle_input_filter(void *data, ssize_t bytes) {
	ngx_http_request_t *r;
	r = (ngx_http_request_t*) data;

	return IMGZIP_ERR;
}

void ngx_http_drizzle_set_libdrizzle_ready(ngx_http_request_t *r) {
	drizzle_ctx *dh;
//    drizzle_con_st                              *dc;
//    short                                        revents = 0;

	dh = (drizzle_ctx*) r->ctx[2];

//    dc = dh->dc;
//#if 0
//    (void) drizzle_con_wait(dh->db);
//#endif
//
//     revents |= POLLOUT;
//     revents |= POLLIN;
//     /* drizzle_con_set_revents() isn't declared external in libdrizzle-0.4.0, */
//     /* so we have to do its job all by ourselves... */
//
//     dc->options |= DRIZZLE_CON_IO_READY;
//     dc->revents = revents;
//     dc->events &= (short) ~revents;

//    dh->db->options |= DRIZZLE_CON_IO_READY;
	(void) drizzle_wait(dh->db);
}

