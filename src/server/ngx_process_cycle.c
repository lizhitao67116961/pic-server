/*
 *
 *  Created on: 2013-03-07
 *      Author: lizhitao
 */

#include "ngx_process_cycle.h"
#include "ngx_channel.h"
#include "ngx_process.h"
#include "ngx_event.h"
#include "ngx_cycle.h"
#include "ngx_connection.h"
#include "ngx_epoll_module.h"
#include "../imgzip/imgzip.h"
#include "../memcache/ngx_http_memc_handler.h"
#include "ngx_http_upstream_round_robin.h"
#include <sched.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include "../mysql/drizzle_client.h"
static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n, ngx_int_t type);
static void ngx_pass_open_channel(ngx_cycle_t *cycle, ngx_channel_t *ch);
static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo);
static ngx_uint_t ngx_reap_children(ngx_cycle_t *cycle);
static void ngx_master_process_exit(ngx_cycle_t *cycle);
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_worker_process_init(ngx_cycle_t *cycle);
static void ngx_worker_process_exit(ngx_cycle_t *cycle);
static void ngx_channel_handler(ngx_event_t *ev);
#define ngx_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))
ngx_uint_t ngx_process;
pid_t ngx_pid;
ngx_uint_t ngx_threaded;

sig_atomic_t ngx_reap;
sig_atomic_t ngx_sigio;
sig_atomic_t ngx_sigalrm;
sig_atomic_t ngx_terminate;
sig_atomic_t ngx_quit;
sig_atomic_t ngx_debug_quit;
ngx_uint_t ngx_exiting;
sig_atomic_t ngx_reconfigure;
sig_atomic_t ngx_reopen;

sig_atomic_t ngx_change_binary;
pid_t ngx_new_binary;
ngx_uint_t ngx_inherited;
ngx_uint_t ngx_daemonized;

sig_atomic_t ngx_noaccept;
ngx_uint_t ngx_noaccepting;
ngx_uint_t ngx_restart;

static u_char master_process[] = "master process";

void ngx_master_process_cycle(ngx_cycle_t *cycle) {
	char *title;
	u_char *p;
	size_t size;
	ngx_uint_t sigio;
	sigset_t set;
	struct itimerval itv;
	ngx_uint_t live;
	ngx_uint_t delay;
	ngx_listening_t *ls;

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigaddset(&set, SIGALRM);
	sigaddset(&set, SIGIO);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGWINCH);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGUSR2);

	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
		log_print(LOG_LEVEL_DEBUG, "sigprocmask() failed");
	}

	sigemptyset(&set);

	size = sizeof(master_process);

	title = ngx_pnalloc(cycle->pool, size);

	p = ngx_cpymem(title, master_process, sizeof(master_process) - 1);

//	ngx_setproctitle(title);

	ngx_start_worker_processes(cycle, imgzip_server_conf.process_num, NGX_PROCESS_RESPAWN);

	ngx_new_binary = 0;
	delay = 0;
	sigio = 0;
	live = 1;

	for (;;) {
		if (delay) {
			if (ngx_sigalrm) {
				sigio = 0;
				delay *= 2;
				ngx_sigalrm = 0;
			}

			log_print(LOG_LEVEL_DEBUG, "termination cycle: %d", delay);

			itv.it_interval.tv_sec = 0;
			itv.it_interval.tv_usec = 0;
			itv.it_value.tv_sec = delay / 1000;
			itv.it_value.tv_usec = (delay % 1000) * 1000;

			if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
				log_print(LOG_LEVEL_DEBUG, "setitimer() failed");
			}
		}

		log_print(LOG_LEVEL_DEBUG, "sigsuspend");

		sigsuspend(&set);

		ngx_time_update();

		if (ngx_reap) {
			ngx_reap = 0;
			log_print(LOG_LEVEL_DEBUG, "reap children");

			live = ngx_reap_children(cycle);
		}

		if (!live && (ngx_terminate || ngx_quit)) {
			ngx_master_process_exit(cycle);
		}

		if (ngx_terminate) {
			if (delay == 0) {
				delay = 50;
			}

			if (sigio) {
				sigio--;
				continue;
			}

			sigio = imgzip_server_conf.process_num /* cache processes */;

			if (delay > 1000) {
				ngx_signal_worker_processes(cycle, SIGKILL);
			} else {
				ngx_signal_worker_processes(cycle, ngx_signal_value(NGX_TERMINATE_SIGNAL));
			}

			continue;
		}

		if (ngx_quit) {
			ngx_signal_worker_processes(cycle, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));

			ls = cycle->listening;

			if (close(ls->fd) == -1) {
			}

			cycle->listening = NULL;

			continue;
		}

		if (ngx_restart) {
			ngx_restart = 0;
			ngx_start_worker_processes(cycle, imgzip_server_conf.process_num, NGX_PROCESS_RESPAWN);
			live = 1;
		}

		if (ngx_noaccept) {
			ngx_noaccept = 0;
			ngx_noaccepting = 1;
			ngx_signal_worker_processes(cycle, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
		}
	}
}

static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n, ngx_int_t type) {
	ngx_int_t i;
	ngx_channel_t ch;

	ch.command = NGX_CMD_OPEN_CHANNEL;

	for (i = 0; i < n; i++) {
		ngx_spawn_process(cycle, ngx_worker_process_cycle, NULL, "worker process", type);
		ch.pid = ngx_processes[ngx_process_slot].pid;
		ch.slot = ngx_process_slot;
		ch.fd = ngx_processes[ngx_process_slot].channel[0];

		ngx_pass_open_channel(cycle, &ch);
	}
}

static void ngx_pass_open_channel(ngx_cycle_t *cycle, ngx_channel_t *ch) {
	ngx_int_t i;

	for (i = 0; i < ngx_last_process; i++) {

		if (i == ngx_process_slot || ngx_processes[i].pid == -1 || ngx_processes[i].channel[0] == -1) {
			continue;
		}

		ngx_write_channel(ngx_processes[i].channel[0], ch, sizeof(ngx_channel_t));
	}
}

static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo) {
	ngx_int_t i;
	ngx_err_t err;
	ngx_channel_t ch;

	switch (signo) {

	case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
		ch.command = NGX_CMD_QUIT;
		break;

	case ngx_signal_value(NGX_TERMINATE_SIGNAL):
		ch.command = NGX_CMD_TERMINATE;
		break;

	case ngx_signal_value(NGX_REOPEN_SIGNAL):
		ch.command = NGX_CMD_REOPEN;
		break;

	default:
		ch.command = 0;
		break;
	}

	ch.fd = -1;

	for (i = 0; i < ngx_last_process; i++) {

		if (ngx_processes[i].detached || ngx_processes[i].pid == -1) {
			continue;
		}

		if (ngx_processes[i].just_spawn) {
			ngx_processes[i].just_spawn = 0;
			continue;
		}

		if (ngx_processes[i].exiting && signo == ngx_signal_value(NGX_SHUTDOWN_SIGNAL)) {
			continue;
		}

		if (ch.command) {
			if (ngx_write_channel(ngx_processes[i].channel[0], &ch, sizeof(ngx_channel_t)) == IMGZIP_OK) {
				if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
					ngx_processes[i].exiting = 1;
				}

				continue;
			}
		}

		if (kill(ngx_processes[i].pid, signo) == -1) {
			err = ngx_errno;
			log_print(LOG_LEVEL_ERROR, "kill(%P, %d) failed", ngx_processes[i].pid, signo);

			if (err == ESRCH) {
				ngx_processes[i].exited = 1;
				ngx_processes[i].exiting = 0;
				ngx_reap = 1;
			}

			continue;
		}

		if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
			ngx_processes[i].exiting = 1;
		}
	}
}

static ngx_uint_t ngx_reap_children(ngx_cycle_t *cycle) {
	ngx_int_t i, n;
	ngx_uint_t live;
	ngx_channel_t ch;

	ch.command = NGX_CMD_CLOSE_CHANNEL;
	ch.fd = -1;

	live = 0;
	for (i = 0; i < ngx_last_process; i++) {

		if (ngx_processes[i].pid == -1) {
			continue;
		}

		if (ngx_processes[i].exited) {

			if (!ngx_processes[i].detached) {
				ngx_close_channel(ngx_processes[i].channel);

				ngx_processes[i].channel[0] = -1;
				ngx_processes[i].channel[1] = -1;

				ch.pid = ngx_processes[i].pid;
				ch.slot = i;

				for (n = 0; n < ngx_last_process; n++) {
					if (ngx_processes[n].exited || ngx_processes[n].pid == -1 || ngx_processes[n].channel[0] == -1) {
						continue;
					}

					ngx_write_channel(ngx_processes[n].channel[0], &ch, sizeof(ngx_channel_t));
				}
			}

			if (ngx_processes[i].respawn && !ngx_processes[i].exiting && !ngx_terminate && !ngx_quit) {
				if (ngx_spawn_process(cycle, ngx_processes[i].proc, ngx_processes[i].data, ngx_processes[i].name, i) == NGX_INVALID_PID) {
					log_print(LOG_LEVEL_ERROR, "could not respawn %s", ngx_processes[i].name);
					continue;
				}

				ch.command = NGX_CMD_OPEN_CHANNEL;
				ch.pid = ngx_processes[ngx_process_slot].pid;
				ch.slot = ngx_process_slot;
				ch.fd = ngx_processes[ngx_process_slot].channel[0];

				ngx_pass_open_channel(cycle, &ch);

				live = 1;

				continue;
			}

		} else if (ngx_processes[i].exiting || !ngx_processes[i].detached) {
			live = 1;
		}
	}

	return live;
}

static void ngx_master_process_exit(ngx_cycle_t *cycle) {

	log_print(LOG_LEVEL_ERROR, "exit");

	ngx_close_listening_sockets(cycle);

	ngx_destroy_pool(cycle->pool);

	exit(0);
}

static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data) {
	ngx_uint_t i;
	ngx_connection_t *c;

	ngx_process = NGX_PROCESS_WORKER;

	ngx_worker_process_init(cycle);

//	ngx_setproctitle("worker process");

	for (;;) {

		if (ngx_exiting) {

			c = cycle->connections;

			for (i = 0; i < cycle->connection_n; i++) {

				/* THREAD: lock */

				if (c[i].fd != -1 && c[i].idle) {
					c[i].close = 1;
					c[i].read->handler(c[i].read);
				}
			}

			if (ngx_event_timer_rbtree.root == ngx_event_timer_rbtree.sentinel) {
				log_print(LOG_LEVEL_ERROR, "exiting");

				ngx_worker_process_exit(cycle);
			}
		}

		ngx_process_events_and_timers(cycle);

		if (ngx_terminate) {
			log_print(LOG_LEVEL_ERROR, "exiting");

			ngx_worker_process_exit(cycle);
		}

		if (ngx_quit) {
			ngx_quit = 0;
			log_print(LOG_LEVEL_ERROR, "gracefully shutting down");
//			ngx_setproctitle("worker process is shutting down");

			if (!ngx_exiting) {
				ngx_close_listening_sockets(cycle);
				ngx_exiting = 1;
			}
		}

//		if (ngx_reopen) {
//			ngx_reopen = 0;
//			ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
//			ngx_reopen_files(cycle, -1);
//		}
	}
}

static void ngx_worker_process_init(ngx_cycle_t *cycle) {
	sigset_t set;
	ngx_int_t n;
	struct rlimit rlmt;
	cycle->pid = getpid();
	/* allow coredump after setuid() in Linux 2.4.x */

	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
		log_print(LOG_LEVEL_ERROR, "prctl(PR_SET_DUMPABLE) failed");
	}
	rlmt.rlim_cur = (rlim_t) 500 * 1024 * 1024;
	rlmt.rlim_max = (rlim_t) 500 * 1024 * 1024;

	if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
		log_print(LOG_LEVEL_ERROR, "setrlimit(RLIMIT_CORE, 500M) failed");
	}
	int rc = imgZoomInit(&imgzip_server_conf.resources_path);
	if (rc == IMGZIP_ERR) {
		log_print(LOG_LEVEL_ERROR, "init imgZoomInit failed");
		exit(1);
	}
	rc = ngx_http_memc_init();
	if (rc == IMGZIP_ERR) {
		log_print(LOG_LEVEL_ERROR, "init memcacheInit failed");
		exit(1);
	}
	rc = ngx_http_upstream_init_round_robin();
	if (rc == IMGZIP_ERR) {
		log_print(LOG_LEVEL_ERROR, "init ngx_http_upstream_init_round_robin failed");
		exit(1);
	}
	rc = ngx_http_access_log_init();
	if (rc == IMGZIP_ERR) {
		log_print(LOG_LEVEL_ERROR, "init ngx_http_access_log_init failed");
		exit(1);
	}
	rc = drizzle_client_init();
	if (rc == IMGZIP_ERR) {
		log_print(LOG_LEVEL_ERROR, "init drizzle_client_init failed");
		exit(1);
	}
	sigemptyset(&set);

	if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
		log_print(LOG_LEVEL_ERROR, "sigprocmask() failed");
	}

	/*
	 * disable deleting previous events for the listening sockets because
	 * in the worker processes there are no events at all at this point
	 */
	ngx_event_process_init(cycle);
	for (n = 0; n < ngx_last_process; n++) {

		if (ngx_processes[n].pid == -1) {
			continue;
		}

		if (n == ngx_process_slot) {
			continue;
		}

		if (ngx_processes[n].channel[1] == -1) {
			continue;
		}

		if (close(ngx_processes[n].channel[1]) == -1) {
			log_print(LOG_LEVEL_ERROR, "close() channel failed");
		}
	}

	if (close(ngx_processes[ngx_process_slot].channel[0]) == -1) {
		log_print(LOG_LEVEL_ERROR, "close() channel failed");
	}

	if (ngx_add_channel_event(cycle, ngx_channel, EPOLLIN, ngx_channel_handler) == IMGZIP_ERR) {
		/* fatal */
		exit(2);
	}
}

static void ngx_worker_process_exit(ngx_cycle_t *cycle) {
	ngx_uint_t i;
	ngx_connection_t *c;

	if (ngx_exiting) {
		c = cycle->connections;
		for (i = 0; i < cycle->connection_n; i++) {
			if (c[i].fd != -1 && c[i].read && !c[i].read->accept && !c[i].read->channel && !c[i].read->resolver) {
				log_print(LOG_LEVEL_ERROR, "open socket #%d left in connection %ui", c[i].fd, i);
				ngx_debug_quit = 1;
			}
		}

		if (ngx_debug_quit) {
			log_print(LOG_LEVEL_ERROR, "aborting");
		}
	}

	/*
	 * Copy ngx_cycle->log related data to the special static exit cycle,
	 * log, and log file structures enough to allow a signal handler to log.
	 * The handler may be called when standard ngx_cycle->log allocated from
	 * ngx_cycle->pool is already destroyed.
	 */

	ngx_destroy_pool(cycle->pool);

	exit(0);
}

static void ngx_channel_handler(ngx_event_t *ev) {
	ngx_int_t n;
	ngx_channel_t ch;
	ngx_connection_t *c;

	if (ev->timedout) {
		ev->timedout = 0;
		return;
	}

	c = ev->data;

	for (;;) {

		n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t));

		log_print(LOG_LEVEL_DEBUG, "channel: %i", n);

		if (n == IMGZIP_ERR) {

			ngx_epoll_del_connection(c, 0);

			ngx_close_connection(c);
			return;
		}

		if (n == IMGZIP_AGAIN) {
			return;
		}

		log_print(LOG_LEVEL_DEBUG, "channel command: %d", ch.command);

		switch (ch.command) {

		case NGX_CMD_QUIT:
			ngx_quit = 1;
			break;

		case NGX_CMD_TERMINATE:
			ngx_terminate = 1;
			break;

		case NGX_CMD_REOPEN:
			ngx_reopen = 1;
			break;

		case NGX_CMD_OPEN_CHANNEL:

			log_print(LOG_LEVEL_DEBUG, "get channel s:%i pid:%P fd:%d", ch.slot, ch.pid, ch.fd);

			ngx_processes[ch.slot].pid = ch.pid;
			ngx_processes[ch.slot].channel[0] = ch.fd;
			break;

		case NGX_CMD_CLOSE_CHANNEL:

			log_print(LOG_LEVEL_DEBUG, "close channel s:%i pid:%P our:%P fd:%d", ch.slot, ch.pid, ngx_processes[ch.slot].pid, ngx_processes[ch.slot].channel[0]);

			if (close(ngx_processes[ch.slot].channel[0]) == -1) {
				log_print(LOG_LEVEL_ERROR, "close() channel failed");
			}

			ngx_processes[ch.slot].channel[0] = -1;
			break;
		}
	}
}

