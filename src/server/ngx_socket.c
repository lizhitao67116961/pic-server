#include "ngx_socket.h"
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
int ngx_nonblocking(int s) {
	int nb;

	nb = 1;

	return ioctl(s, FIONBIO, &nb);
}

int ngx_blocking(int s) {
	int nb;

	nb = 0;

	return ioctl(s, FIONBIO, &nb);
}

int ngx_tcp_push(int s) {
	int cork;

	cork = 0;

	return setsockopt(s, IPPROTO_TCP, TCP_CORK, (const void *) &cork, sizeof(int));
}
