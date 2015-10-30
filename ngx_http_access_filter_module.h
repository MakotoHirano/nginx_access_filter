/* Makoto Hiano. All rights reserved. */
#ifndef NGX_HTTP_ACCESS_FILTER_MODULE_H
#define NGX_HTTP_ACCESS_FILTER_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <regex.h>
#include <sys/time.h>

#define STORAGE_SHMEM "shmem"
#define STORAGE_MEMCACHED "memcached"

#define NGX_AF_OK 0
#define NGX_AF_NG -1

typedef struct storage_entry_s storage_entry_t;

struct storage_entry_s {
	struct timeval first_access_time;
	struct timeval banned_from;
	unsigned int access_count;
};

/**
 * directive struct
 */
typedef struct {
	ngx_flag_t enable;                // enable flag
	ngx_uint_t threshold_interval;    // interval count as continuous access (milli second)
	ngx_uint_t threshold_count;       // continuous count to be banned.
	ngx_uint_t time_to_be_banned;     // limited interval to access site. (second)
	ngx_uint_t bucket_size;           // max size of bucket to hold each ip.
	ngx_str_t  except_regex;               // except_regex of target filename
	ngx_str_t  storage;                    // storage of user access data.
	ngx_str_t  memcached_server_host;      // identifiers of servers of memcached.
	ngx_uint_t memcached_server_port; // identifiers of servers of memcached.
} ngx_http_access_filter_conf_t;

ngx_http_request_t *ctx_r;

char* ngx_conf_set_mystr_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#include "storage_module_shmem.h"
#include "storage_module_memcached.h"

#endif
