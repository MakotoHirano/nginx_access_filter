/* Makoto Hiano. All rights reserved. */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <regex.h>
#include <sys/time.h>
#include <storage_module_memcached.h>
#include <storage_module_shmem.h>

#define STORAGE_SHMEM "shmem"
#define STORAGE_MEMCACHED "memcached"

#define NGX_AF_OK 0
#define NGX_AF_NG -1

typedef struct storage_entry_s storage_entry_t;

struct storage_entry_s {
	struct timeval last_access_time;
	struct timeval banned_from;
	unsigned int access_count;
};

ngx_http_request_t *ctx_r;