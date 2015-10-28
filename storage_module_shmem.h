/* Makoto Hiano. All rights reserved. */
#ifndef STORAGE_MODULE_SHMEM_H
#define STORAGE_MODULE_SHMEM_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "ngx_http_access_filter_module.h"

#define KEY_SEMAPHORE "./semaphore_nginx_access_filter"
#define KEY_SHMEM "./shmem_nginx_access_filter"

#define LOCK -1
#define UNLOCK 1

typedef struct hashtable_entry_s hashtable_entry_t;
typedef struct fifo_entry_s fifo_entry_t;

struct hashtable_entry_s {
	char ip[16];
	storage_entry_t data;
	hashtable_entry_t *p_next;
	hashtable_entry_t *p_prev;
	fifo_entry_t *p_fifo;
	unsigned int hash;
};

struct fifo_entry_s {
	fifo_entry_t *p_next;
	fifo_entry_t *p_prev;
	hashtable_entry_t *p_hash;
};

extern ngx_http_request_t *ctx_r;

// public functions
int init_shmem(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf);
void* get_entry_shmem(char *key, ngx_http_access_filter_conf_t *afcf);
storage_entry_t* get_data_shmem(void *entry_p);
int add_count_shmem(storage_entry_t *data, ngx_http_access_filter_conf_t *afcf);
int update_entry_shmem(char *key, void *entry_p, ngx_http_access_filter_conf_t *afcf);
int create_entry_shmem(char *key, ngx_http_access_filter_conf_t *afcf);
int fin_shmem(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf);

#endif
