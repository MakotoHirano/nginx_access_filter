/* Makoto Hiano. All rights reserved. */
#ifndef STORAGE_MODULE_MEMCACHED_H
#define STORAGE_MODULE_MEMCACHED_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "ngx_http_access_filter_module.h"

#define MEMCACHED_KEY_PREFIX "ngx_af_"

typedef struct memcached_entry_s memcached_entry_t;

struct memcached_entry_s {
	storage_entry_t data;
};

extern ngx_http_request_t *ctx_r;

// public functions
int init_memcached(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf);
void* get_entry_memcached(char *key, ngx_http_access_filter_conf_t *afcf);
storage_entry_t* get_data_memcached(void *entry_p);
void free_entry_memcached(void *entry_p);
int add_count_memcached(char *key, void *entry_p, ngx_http_access_filter_conf_t *afcf);
int update_entry_memcached(char *key, void *entry_p, ngx_http_access_filter_conf_t *afcf);
int create_entry_memcached(char *key, ngx_http_access_filter_conf_t *afcf);
int fin_memcached(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf);

#endif
