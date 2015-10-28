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

typedef struct hashtable_entry_s hashtable_entry_t;

struct hashtable_entry_s {
	char ip[16];
	storage_entry_t data;
	hashtable_entry_t *p_next;
	hashtable_entry_t *p_prev;
	fifo_entry_t *p_fifo;
	unsigned int hash;
};

extern ngx_http_request_t *ctx_r;

// public functions
int init_memcached(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf);
void* get_entry_memcached(char *key, ngx_http_access_filter_conf_t *afcf);
storage_entry_t* get_data_memcached(void *entry_p);
int add_count_memcached(storage_entry_t *data, ngx_http_access_filter_conf_t *afcf);
int update_entry_memcached(char *key, void *entry_p, ngx_http_access_filter_conf_t *afcf);
int create_entry_memcached(char *key, ngx_http_access_filter_conf_t *afcf);
int fin_memcached(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf);

#endif
