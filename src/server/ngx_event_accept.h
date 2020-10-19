/*
 * ngx_event_accept.h
 *
 *  Created on: 2011-12-21
 *      Author: root
 */
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_cycle.h"

#ifndef NGX_EVENT_ACCEPT_H_
#define NGX_EVENT_ACCEPT_H_
ngx_int_t ngx_trylock_accept_mutex(ngx_cycle_t *cycle);
void ngx_event_accept(ngx_event_t *ev);

#endif /* NGX_EVENT_ACCEPT_H_ */
