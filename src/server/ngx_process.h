/*
 *
 *  Created on: 2013-03-22
 *      Author: lizhitao
 */

#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_
#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include <signal.h>
#define NGX_SHUTDOWN_SIGNAL      QUIT
#define NGX_TERMINATE_SIGNAL     TERM
#define NGX_NOACCEPT_SIGNAL      WINCH
#define NGX_RECONFIGURE_SIGNAL   HUP


#define NGX_REOPEN_SIGNAL        USR1
#define NGX_CHANGEBIN_SIGNAL     USR2
#define ngx_signal_helper(n)     SIG##n
#define ngx_signal_value(n)      ngx_signal_helper(n)
#define ngx_value_helper(n)   #n
#define ngx_value(n)          ngx_value_helper(n)
typedef pid_t ngx_pid_t;

#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt)(ngx_cycle_t *cycle, void *data);

typedef struct {
	ngx_pid_t pid;
	int status;
	int channel[2];

	ngx_spawn_proc_pt proc;
	void *data;
	char *name;

	unsigned respawn :1;
	unsigned just_spawn :1;
	unsigned detached :1;
	unsigned exiting :1;
	unsigned exited :1;
} ngx_process_t;

typedef struct {
	char *path;
	char *name;
	char * const *argv;
	char * const *envp;
} ngx_exec_ctx_t;

#define NGX_MAX_PROCESSES         1024

#define NGX_PROCESS_NORESPAWN     -1
#define NGX_PROCESS_JUST_SPAWN    -2
#define NGX_PROCESS_RESPAWN       -3
#define NGX_PROCESS_JUST_RESPAWN  -4
#define NGX_PROCESS_DETACHED      -5

#define ngx_getpid   getpid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif

ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle, ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(void);
void ngx_debug_point(void);

#define ngx_sched_yield()  sched_yield()

extern ngx_pid_t ngx_pid;
extern int ngx_channel;
extern ngx_int_t ngx_process_slot;
extern ngx_int_t ngx_last_process;
extern ngx_process_t ngx_processes[NGX_MAX_PROCESSES];

#endif /* _NGX_PROCESS_H_INCLUDED_ */
