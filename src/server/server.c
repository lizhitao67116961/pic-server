/*
 * server.c
 *
 *  Created on: 2011-12-7
 *      Author: root
 */
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_process.h"
#include "ngx_process_cycle.h"
static ngx_int_t ngx_get_options(int argc, char * const *argv);

static ngx_uint_t ngx_show_help;
static ngx_uint_t ngx_show_version;
static char *ngx_signal;

int main(int argc, char * const *argv) {
	ngx_cycle_t *cycle;
	int len;
	ngx_time_init();
	len = strlen(argv[0]) +1;
	u_char conf_data[len]; //
	strcpy((char*) conf_data, argv[0]);
	if (imgzip_conf_load(conf_data) != IMGZIP_OK) {
		return 1;
	}
	log_init();
	if (ngx_get_options(argc, argv) != IMGZIP_OK) {
		return 1;
	}
	cycle = ngx_init_cycle();
	if (cycle == NULL) {
		return 1;
	}

	if (ngx_init_signals() != IMGZIP_OK) {
		return 1;
	}

	if (imgzip_server_conf.daemon) {
		ngx_pid_t pid = fork();

		switch (pid) {

		case -1:
			printf("main fork() failed ");
			return NGX_INVALID_PID;
		case 0:
			if (setsid() == -1) {
				log_print(LOG_LEVEL_ERROR, "setsid() failed");
				return 1;
			}
			break;
		default:
			return 0;
			break;
		}
	}

	ngx_master_process_cycle(cycle);

	return 0;
}

static ngx_int_t ngx_get_options(int argc, char * const *argv) {
	u_char *p;
	ngx_int_t i;

	for (i = 1; i < argc; i++) {

		p = (u_char *) argv[i];

		if (*p++ != '-') {
			printf("invalid option: \"%s\"\r\n", argv[i]);
			return IMGZIP_ERR;
		}

		while (*p) {

			switch (*p++) {

			case '?':
			case 'h':
				ngx_show_version = 1;
				ngx_show_help = 1;
				break;

			case 's':
				if (*p) {
					ngx_signal = (char *) p;

				} else if (argv[++i]) {
					ngx_signal = argv[i];

				} else {
					printf("option \"-s\" requires parameter\r\n");
					return IMGZIP_ERR;
				}

				if (strcmp(ngx_signal, "stop") == 0 || strcmp(ngx_signal, "quit") == 0 || strcmp(ngx_signal, "reopen") == 0 || strcmp(ngx_signal, "reload") == 0) {
					ngx_process = NGX_PROCESS_SIGNALLER;
					goto next;
				}

				printf("invalid option: \"-s %s\"\r\n", ngx_signal);
				return IMGZIP_ERR;

			default:
				printf("invalid option: \"%c\"\r\n", *(p - 1));
				return IMGZIP_ERR;
			}
		}

		next:

		continue;
	}

	return IMGZIP_OK;
}

