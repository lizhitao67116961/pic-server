/*
 *
 *  Created on: 2013-03-22
 *      Author: lizhitao
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include "ngx_process.h"
#include "ngx_event.h"
#include "ngx_channel.h"
#include "ngx_socket.h"
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/wait.h>
typedef struct {
	int signo;
	char *signame;
	char *name;
	void (*handler)(int signo);
} ngx_signal_t;

static void ngx_execute_proc(ngx_cycle_t *cycle, void *data);
static void ngx_signal_handler(int signo);
static void ngx_process_get_status(void);

ngx_int_t ngx_process_slot;
int ngx_channel;
ngx_int_t ngx_last_process;
ngx_process_t ngx_processes[NGX_MAX_PROCESSES];

ngx_signal_t signals[] = { { ngx_signal_value(NGX_RECONFIGURE_SIGNAL), "SIG" ngx_value(NGX_RECONFIGURE_SIGNAL), "reload", ngx_signal_handler },

{ ngx_signal_value(NGX_REOPEN_SIGNAL), "SIG" ngx_value(NGX_REOPEN_SIGNAL), "reopen", ngx_signal_handler },

{ ngx_signal_value(NGX_NOACCEPT_SIGNAL), "SIG" ngx_value(NGX_NOACCEPT_SIGNAL), "", ngx_signal_handler },

{ ngx_signal_value(NGX_TERMINATE_SIGNAL), "SIG" ngx_value(NGX_TERMINATE_SIGNAL), "stop", ngx_signal_handler },

{ ngx_signal_value(NGX_SHUTDOWN_SIGNAL), "SIG" ngx_value(NGX_SHUTDOWN_SIGNAL), "quit", ngx_signal_handler },

{ ngx_signal_value(NGX_CHANGEBIN_SIGNAL), "SIG" ngx_value(NGX_CHANGEBIN_SIGNAL), "", ngx_signal_handler },

{ SIGALRM, "SIGALRM", "", ngx_signal_handler },

{ SIGINT, "SIGINT", "", ngx_signal_handler },

{ SIGIO, "SIGIO", "", ngx_signal_handler },

{ SIGCHLD, "SIGCHLD", "", ngx_signal_handler },

{ SIGSYS, "SIGSYS, SIG_IGN", "", SIG_IGN },

{ SIGPIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },

{ 0, NULL, "", NULL } };

ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle, ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn) {
	u_long on;
	ngx_pid_t pid;
	ngx_int_t s;

	if (respawn >= 0) {
		s = respawn;

	} else {
		for (s = 0; s < ngx_last_process; s++) {
			if (ngx_processes[s].pid == -1) {
				break;
			}
		}

		if (s == NGX_MAX_PROCESSES) {
			log_print(LOG_LEVEL_ERROR, "no more than %d processes can be spawned", NGX_MAX_PROCESSES);
			return NGX_INVALID_PID;
		}
	}

	if (respawn != NGX_PROCESS_DETACHED) {

		/* Solaris 9 still has no AF_LOCAL */

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, ngx_processes[s].channel) == -1) {
			log_print(LOG_LEVEL_ERROR, "socketpair() failed while spawning \"%s\"", name);
			return NGX_INVALID_PID;
		}

		if (ngx_nonblocking(ngx_processes[s].channel[0]) == -1) {
			log_print(LOG_LEVEL_ERROR, " failed while spawning \"%s\"", name);
			ngx_close_channel(ngx_processes[s].channel);
			return NGX_INVALID_PID;
		}

		if (ngx_nonblocking(ngx_processes[s].channel[1]) == -1) {
			log_print(LOG_LEVEL_ERROR, " failed while spawning \"%s\"", name);
			ngx_close_channel(ngx_processes[s].channel);
			return NGX_INVALID_PID;
		}

		on = 1;
		if (ioctl(ngx_processes[s].channel[0], FIOASYNC, &on) == -1) {
			log_print(LOG_LEVEL_ERROR, "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
			ngx_close_channel(ngx_processes[s].channel);
			return NGX_INVALID_PID;
		}

		if (fcntl(ngx_processes[s].channel[0], F_SETOWN, ngx_pid) == -1) {
			log_print(LOG_LEVEL_ERROR, "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
			ngx_close_channel(ngx_processes[s].channel);
			return NGX_INVALID_PID;
		}

		if (fcntl(ngx_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
			log_print(LOG_LEVEL_ERROR, "fcntl(FD_CLOEXEC) failed while spawning \"%s\"", name);
			ngx_close_channel(ngx_processes[s].channel);
			return NGX_INVALID_PID;
		}

		if (fcntl(ngx_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
			log_print(LOG_LEVEL_ERROR, "fcntl(FD_CLOEXEC) failed while spawning \"%s\"", name);
			ngx_close_channel(ngx_processes[s].channel);
			return NGX_INVALID_PID;
		}

		ngx_channel = ngx_processes[s].channel[1];

	} else {
		ngx_processes[s].channel[0] = -1;
		ngx_processes[s].channel[1] = -1;
	}

	ngx_process_slot = s;
	if (imgzip_server_conf.master_process) {
		pid = fork();

		switch (pid) {

		case -1:
			log_print(LOG_LEVEL_ERROR, "fork() failed while spawning \"%s\"", name);
			ngx_close_channel(ngx_processes[s].channel);
			return NGX_INVALID_PID;

		case 0:
			ngx_pid = ngx_getpid();
			proc(cycle, data);
			break;

		default:
			break;
		}
	} else {
		ngx_pid = ngx_getpid();
		proc(cycle, data);
	}
	log_print(LOG_LEVEL_DEBUG, "start %s %d", name, pid);

	ngx_processes[s].pid = pid;
	ngx_processes[s].exited = 0;

	if (respawn >= 0) {
		return pid;
	}

	ngx_processes[s].proc = proc;
	ngx_processes[s].data = data;
	ngx_processes[s].name = name;
	ngx_processes[s].exiting = 0;

	switch (respawn) {

	case NGX_PROCESS_NORESPAWN:
		ngx_processes[s].respawn = 0;
		ngx_processes[s].just_spawn = 0;
		ngx_processes[s].detached = 0;
		break;

	case NGX_PROCESS_JUST_SPAWN:
		ngx_processes[s].respawn = 0;
		ngx_processes[s].just_spawn = 1;
		ngx_processes[s].detached = 0;
		break;

	case NGX_PROCESS_RESPAWN:
		ngx_processes[s].respawn = 1;
		ngx_processes[s].just_spawn = 0;
		ngx_processes[s].detached = 0;
		break;

	case NGX_PROCESS_JUST_RESPAWN:
		ngx_processes[s].respawn = 1;
		ngx_processes[s].just_spawn = 1;
		ngx_processes[s].detached = 0;
		break;

	case NGX_PROCESS_DETACHED:
		ngx_processes[s].respawn = 0;
		ngx_processes[s].just_spawn = 0;
		ngx_processes[s].detached = 1;
		break;
	}

	if (s == ngx_last_process) {
		ngx_last_process++;
	}

	return pid;
}

ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx) {
	return ngx_spawn_process(cycle, ngx_execute_proc, ctx, ctx->name, NGX_PROCESS_DETACHED);
}

static void ngx_execute_proc(ngx_cycle_t *cycle, void *data) {
	ngx_exec_ctx_t *ctx = data;

	if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
		log_print(LOG_LEVEL_ERROR, "execve() failed while executing %s \"%s\"", ctx->name, ctx->path);
	}

	exit(1);
}

ngx_int_t ngx_init_signals(void) {
	ngx_signal_t *sig;
	struct sigaction sa;

	for (sig = signals; sig->signo != 0; sig++) {
		ngx_memzero(&sa, sizeof(struct sigaction));
		sa.sa_handler = sig->handler;
		sigemptyset(&sa.sa_mask);
		if (sigaction(sig->signo, &sa, NULL) == -1) {
			log_print(LOG_LEVEL_ERROR, "sigaction(%s) failed", sig->signame);
			return IMGZIP_ERR;
		}
	}

	return IMGZIP_OK;
}

void ngx_signal_handler(int signo) {
	char *action;
	ngx_int_t ignore;
	ngx_err_t err;
	ngx_signal_t *sig;

	ignore = 0;

	err = ngx_errno;

	for (sig = signals; sig->signo != 0; sig++) {
		if (sig->signo == signo) {
			break;
		}
	}

	ngx_time_sigsafe_update();

	action = "";

	switch (ngx_process) {

	case NGX_PROCESS_MASTER:
	case NGX_PROCESS_SINGLE:
		switch (signo) {

		case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
			ngx_quit = 1;
			action = ", shutting down";
			break;

		case ngx_signal_value(NGX_TERMINATE_SIGNAL):
		case SIGINT:
			ngx_terminate = 1;
			action = ", exiting";
			break;

		case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
			if (ngx_daemonized) {
				ngx_noaccept = 1;
				action = ", stop accepting connections";
			}
			break;

		case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
			ngx_reconfigure = 1;
			action = ", reconfiguring";
			break;

		case ngx_signal_value(NGX_REOPEN_SIGNAL):
			ngx_reopen = 1;
			action = ", reopening logs";
			break;

		case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
			if (getppid() > 1 || ngx_new_binary > 0) {

				/*
				 * Ignore the signal in the new binary if its parent is
				 * not the init process, i.e. the old binary's process
				 * is still running.  Or ignore the signal in the old binary's
				 * process if the new binary's process is already running.
				 */

				action = ", ignoring";
				ignore = 1;
				break;
			}

			ngx_change_binary = 1;
			action = ", changing binary";
			break;

		case SIGALRM:
			ngx_sigalrm = 1;
			break;

		case SIGIO:
			ngx_sigio = 1;
			break;

		case SIGCHLD:
			ngx_reap = 1;
			break;
		}

		break;

	case NGX_PROCESS_WORKER:
	case NGX_PROCESS_HELPER:
		switch (signo) {

		case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
			if (!ngx_daemonized) {
				break;
			}
			ngx_debug_quit = 1;
		case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
			ngx_quit = 1;
			action = ", shutting down";
			break;

		case ngx_signal_value(NGX_TERMINATE_SIGNAL):
		case SIGINT:
			ngx_terminate = 1;
			action = ", exiting";
			break;

		case ngx_signal_value(NGX_REOPEN_SIGNAL):
			ngx_reopen = 1;
			action = ", reopening logs";
			break;

		case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
		case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
		case SIGIO:
			action = ", ignoring";
			break;
		}

		break;
	}

	log_print(LOG_LEVEL_ERROR, "signal %d (%s) received%s", signo, sig->signame, action);

	if (ignore) {
		log_print(LOG_LEVEL_ERROR, "the changing binary signal is ignored: you should shutdown or terminate before either old or new binary's process");
	}

	if (signo == SIGCHLD) {
		ngx_process_get_status();
	}

	errno = err;
}

static void ngx_process_get_status(void) {
	int status;
	char *process;
	ngx_pid_t pid;
	ngx_err_t err;
	ngx_int_t i;
	ngx_uint_t one;

	one = 0;

	for (;;) {
		pid = waitpid(-1, &status, WNOHANG);

		if (pid == 0) {
			return;
		}

		if (pid == -1) {
			err = ngx_errno;

			if (err == EINTR) {
				continue;
			}

			if (err == ECHILD && one) {
				return;
			}

			log_print(LOG_LEVEL_ERROR, "waitpid() failed");
			return;
		}

		if (ngx_accept_mutex_ptr) {
			ngx_atomic_cmp_set(ngx_accept_mutex_ptr, pid, 0);
		}

		one = 1;
		process = "unknown process";

		for (i = 0; i < ngx_last_process; i++) {
			if (ngx_processes[i].pid == pid) {
				ngx_processes[i].status = status;
				ngx_processes[i].exited = 1;
				process = ngx_processes[i].name;
				break;
			}
		}

		if (WTERMSIG(status)) {
			log_print(LOG_LEVEL_ERROR, "%s %d exited on signal %d%s", process, pid, WTERMSIG(status), WCOREDUMP(status) ? " (core dumped)" : "");

		} else {
			log_print(LOG_LEVEL_ERROR, "%s %d exited with code %d", process, pid, WEXITSTATUS(status));
		}

		if (WEXITSTATUS(status) == 2 && ngx_processes[i].respawn) {
			log_print(LOG_LEVEL_ERROR, "%s %P exited with fatal code %d and cannot be respawned", process, pid, WEXITSTATUS(status));
			ngx_processes[i].respawn = 0;
		}
	}
}

