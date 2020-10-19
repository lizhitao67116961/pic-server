/*
 * log.h
 *
 *  Created on: 2013-02-20
 *      Author: lizhitao
 */
#include "../imgzip_config.h"
#include "../imgzip_core.h"
static char *LOG_LEVEL_NAME[10] = { "DEBUG", "INFO", "WARNING", "ERROR" };
static FILE *fp;

void log_init() {
	fp = fopen((char*) imgzip_server_conf.error_log_path.data, "a");
}
void log_print(int level, const char *fmt, ...) {
	if(level>=imgzip_server_conf.error_log_level) {
		char buf[64];
		u_char msg[1024];
		u_char *msg_last;
		va_list ap;
		va_start(ap, fmt);
		msg_last=ngx_vslprintf(msg, msg+1024, fmt, ap);
		msg_last[0]='\0';
		va_end(ap);
		time_t s=time(0);
		strftime(buf, sizeof(buf), "%F %H:%M:%S", localtime(&s));
		if (!fp)
		return;
		fprintf(fp,"%s:%s-%s:errcode:%d,pid:%d\r\n",buf, LOG_LEVEL_NAME[level], msg, errno,getpid());
		fflush(fp);
	}
}

void stderr_print(const char *fmt, ...) {
	char buf[64];
	u_char msg[1024];
	u_char *msg_last;
	va_list ap;
	va_start(ap, fmt);
	msg_last=ngx_vslprintf(msg, msg+1024, fmt, ap);
	msg_last[0]='\0';
	va_end(ap);
	time_t s=time(0);
	strftime(buf, sizeof(buf), "%F %H:%M:%S", localtime(&s));
	printf("%s:%s:errcode:%d\r\n",buf, msg, errno);
}
