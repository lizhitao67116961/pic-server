/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_channel.h"
#include "ngx_cycle.h"
#include "ngx_connection.h"
#include "ngx_epoll_module.h"
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
ngx_int_t ngx_write_channel(int s, ngx_channel_t *ch, size_t size) {
	ssize_t n;
	ngx_err_t err;
	struct iovec iov[1];
	struct msghdr msg;

	union {
		struct cmsghdr cm;
		char space[CMSG_SPACE(sizeof(int))];
	} cmsg;

	if (ch->fd == -1) {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;

	} else {
		msg.msg_control = (caddr_t) &cmsg;
		msg.msg_controllen = sizeof(cmsg);

		cmsg.cm.cmsg_len = CMSG_LEN(sizeof(int));
		cmsg.cm.cmsg_level = SOL_SOCKET;
		cmsg.cm.cmsg_type = SCM_RIGHTS;

		/*
		 * We have to use ngx_memcpy() instead of simple
		 *   *(int *) CMSG_DATA(&cmsg.cm) = ch->fd;
		 * because some gcc 4.4 with -O2/3/s optimization issues the warning:
		 *   dereferencing type-punned pointer will break strict-aliasing rules
		 *
		 * Fortunately, gcc with -O1 compiles this ngx_memcpy()
		 * in the same simple assignment as in the code above
		 */

		memcpy(CMSG_DATA(&cmsg.cm), &ch->fd, sizeof(int));
	}

	msg.msg_flags = 0;

	iov[0].iov_base = (char *) ch;
	iov[0].iov_len = size;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	n = sendmsg(s, &msg, 0);

	if (n == -1) {
		err = ngx_errno;
		if (err == EAGAIN) {
			return IMGZIP_AGAIN;
		}

		log_print(LOG_LEVEL_ERROR, "sendmsg() failed");
		return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}

ngx_int_t ngx_read_channel(int s, ngx_channel_t *ch, size_t size) {
	ssize_t n;
	ngx_err_t err;
	struct iovec iov[1];
	struct msghdr msg;

	union {
		struct cmsghdr cm;
		char space[CMSG_SPACE(sizeof(int))];
	} cmsg;

	iov[0].iov_base = (char *) ch;
	iov[0].iov_len = size;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	msg.msg_control = (caddr_t) &cmsg;
	msg.msg_controllen = sizeof(cmsg);

	n = recvmsg(s, &msg, 0);

	if (n == -1) {
		err = ngx_errno;
		if (err == EAGAIN) {
			return IMGZIP_AGAIN;
		}

		log_print(LOG_LEVEL_ERROR, "recvmsg() failed");
		return IMGZIP_ERR;
	}

	if (n == 0) {
		log_print(LOG_LEVEL_ERROR, "recvmsg() returned zero");
		return IMGZIP_ERR;
	}

	if ((size_t) n < sizeof(ngx_channel_t)) {
		log_print(LOG_LEVEL_ERROR, "recvmsg() returned not enough data: %uz", n);
		return IMGZIP_ERR;
	}

	if (ch->command == NGX_CMD_OPEN_CHANNEL) {

		if (cmsg.cm.cmsg_len < (socklen_t) CMSG_LEN(sizeof(int))) {
			log_print(LOG_LEVEL_ERROR, "recvmsg() returned too small ancillary data");
			return IMGZIP_ERR;
		}

		if (cmsg.cm.cmsg_level != SOL_SOCKET || cmsg.cm.cmsg_type != SCM_RIGHTS)
		{
			log_print(LOG_LEVEL_ERROR, "recvmsg() returned invalid ancillary data ", "level %d or type %d", cmsg.cm.cmsg_level, cmsg.cm.cmsg_type);
			return IMGZIP_ERR;
		}

		/* ch->fd = *(int *) CMSG_DATA(&cmsg.cm); */

		memcpy(&ch->fd, CMSG_DATA(&cmsg.cm), sizeof(int));
	}

	if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
		log_print(LOG_LEVEL_ERROR, "recvmsg() truncated data");
	}

	return n;
}

ngx_int_t ngx_add_channel_event(ngx_cycle_t *cycle, int fd, ngx_int_t event, ngx_event_handler_pt handler) {
	ngx_event_t *ev, *rev, *wev;
	ngx_connection_t *c;

	c = ngx_get_connection(fd);

	if (c == NULL) {
		return IMGZIP_ERR;
	}

	c->pool = cycle->pool;

	rev = c->read;
	wev = c->write;

	rev->channel = 1;
	wev->channel = 1;

	ev = (event == EPOLLIN) ? rev : wev;

	ev->handler = handler;

	if (ngx_epoll_add_event(ev, event, 0) == IMGZIP_ERR) {
		ngx_free_connection(c);
		return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}

void ngx_close_channel(int *fd) {
	if (close(fd[0]) == -1) {
		log_print(LOG_LEVEL_ERROR, "close() channel failed");
	}

	if (close(fd[1]) == -1) {
		log_print(LOG_LEVEL_ERROR, "close() channel failed");
	}
}
