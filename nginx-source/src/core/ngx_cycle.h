
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
    void                     *sync;
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


typedef struct ngx_black_list_s {
    ngx_str_t         *IP;
    ngx_black_list_t  *next;
    ngx_black_list_t  *prev;
}ngx_black_list_t;


struct ngx_con_his_s {
    ngx_str_t      addr_text;
    ngx_con_his_t *next;
};


struct ngx_host_specs_s {
    ngx_str_t *host_cpu;
    ngx_str_t *host_mem;
    ngx_str_t *host_os;
};


struct ngx_cycle_s {
    void                  ****conf_ctx;
    ngx_pool_t               *pool;

    ngx_log_t                *log;
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    ngx_connection_t        **files;
    ngx_connection_t         *free_connections;
    ngx_uint_t                free_connection_n;

    ngx_host_specs_t         *host_specs;

    ngx_module_t            **modules;
    ngx_uint_t                modules_n;
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    ngx_queue_t               reusable_connections_queue;
    ngx_uint_t                reusable_connections_n;
    time_t                    connections_reuse_time;

    ngx_array_t               listening;
    ngx_array_t               paths;

    ngx_array_t               config_dump;
    ngx_rbtree_t              config_dump_rbtree;
    ngx_rbtree_node_t         config_dump_sentinel;

    ngx_list_t                open_files;
    ngx_list_t                shared_memory;

    ngx_uint_t                connection_n;
    ngx_uint_t                files_n;

    ngx_connection_t         *connections;
    ngx_event_t              *read_events;
    ngx_event_t              *write_events;

    ngx_cycle_t              *old_cycle;

    size_t                    connection_counter; /* total connections to the server */
    ngx_con_his_t            *connection_history; /* list of all connections made to the server */

    ngx_str_t                 conf_file;
    ngx_str_t                 conf_param;
    ngx_str_t                 conf_prefix;
    ngx_str_t                 prefix;
    ngx_str_t                 error_log;
    ngx_str_t                 lock_file;
    ngx_str_t                 hostname;
    ngx_black_list_t         *black_list;
};


typedef struct {
    ngx_flag_t                daemon;
    ngx_flag_t                master;
    ngx_flag_t                remote_admin;
    ngx_flag_t                trace_enable;

    ngx_msec_t                timer_resolution;
    ngx_msec_t                shutdown_timeout;

    ngx_int_t                 worker_processes;
    ngx_int_t                 debug_points;

    ngx_int_t                 rlimit_nofile;
    off_t                     rlimit_core;

    int                       priority;

    ngx_uint_t                cpu_affinity_auto;
    ngx_uint_t                cpu_affinity_n;
    ngx_cpuset_t             *cpu_affinity;

    char                     *username;
    ngx_uid_t                 user;
    ngx_gid_t                 group;

    ngx_str_t                 working_directory;
    ngx_str_t                 lock_file;

    ngx_str_t                 pid;
    ngx_str_t                 oldpid;

    ngx_array_t               env;
    char                    **environment;

    ngx_uint_t                transparent;  /* unsigned  transparent:1; */
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)
#define ngx_double_link_insert(x, y)            \
    (x)->next = (y);                            \
    (y)->prev = (x);

#define ngx_double_link_remove(x)               \
    if ((x)->prev) (x)->prev->next = (x)->next; \
    if ((x)->next) (x)->next->prev = (x)->prev;

#define ngx_destroy_black_list_link(x)          \
    ngx_memzero((x)->IP->data, (x)->IP->len);   \
    ngx_free((x)->IP->data);                    \
    (x)->IP->data = NULL;                       \
    ngx_memzero((x)->IP, sizeof(ngx_str_t));    \
    ngx_free((x)->IP);                          \
    (x)->IP = NULL;                             \
    ngx_memzero((x), sizeof(ngx_black_list_t)); \
    ngx_free((x));                              \
    (x) = NULL;

ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);
void ngx_set_shutdown_timer(ngx_cycle_t *cycle);
void ngx_insert_con_his(ngx_con_his_t **con_his_list, ngx_con_his_t *new_con);
ngx_con_his_t *ngx_get_con_his(ngx_con_his_t *con_his_list, size_t number);
void ngx_black_list_insert(ngx_black_list_t **black_list,
    u_char insert_ip[], size_t size, ngx_log_t *log);
ngx_int_t ngx_black_list_remove(ngx_black_list_t **black_list, u_char remove_ip[]);
ngx_int_t ngx_is_ip_banned(ngx_cycle_t *cycle, ngx_connection_t *connection);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */