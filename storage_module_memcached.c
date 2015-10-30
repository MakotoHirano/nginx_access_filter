/* Makoto Hiano. All rights reserved. */
#include "storage_module_shmem.h"
#include <libmemcached/memcached.h>

static memcached_entry_t* _parse(char *value);
static char* _compose(memcached_entry_t *entry);
static int _connect(ngx_http_access_filter_conf_t *afcf);
static int _set(char *key, memcached_entry_t *entry_p, time_t expire_sec);
static char* _get(char *remote_ip);
static char* _create_key(char *remote_ip);

static memcached_server_st *servers = NULL;
static memcached_st *memc = NULL;

#define VALUE_FORMAT "%ld.%ld,%ld.%ld,%d"

/**
 * this module will compose (like persist) storage_entry_t as string since it is stored inside memcached.
 * the format is csv and order is below.
 *  <first_access_time>,<banned_from>,<access_count>
 */

int init_memcached(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf)
{
	// concern whether keep connection or not.
	if (_connect(afcf) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "failed to create memcached connection.");
	}

	return NGX_AF_OK;
}

void* get_entry_memcached(char *remote_ip, ngx_http_access_filter_conf_t *afcf)
{
	char *value = _get(remote_ip);

	memcached_entry_t *entry = _parse(value);

	if (value != NULL) {
		free(value);
	}

	return entry;
}

storage_entry_t* get_data_memcached(void *entry_p)
{
	if (entry_p == NULL) {
		return NULL;
	}

	memcached_entry_t *me_p = (memcached_entry_t*) entry_p;

	return &me_p->data;
}

void free_entry_memcached(void *entry_p)
{
	if (entry_p != NULL) {
		free(entry_p);
	}

	return;
}

int add_count_memcached(char *key, void *entry_p, ngx_http_access_filter_conf_t *afcf)
{
	//
	// update data.
	//

	memcached_entry_t *me_p = (memcached_entry_t*) entry_p;
	struct timeval now, diff;
	time_t expire_sec;

	// add count
	me_p->data.access_count++;

	// updte last access time.
	gettimeofday(&now, NULL);
	timersub(&now, &me_p->data.first_access_time, &diff);

	expire_sec = ((int) (afcf->threshold_interval/1000)) - diff.tv_sec;
	if (expire_sec <= 0) {
		expire_sec = 1;
	}

	_set(key, entry_p, expire_sec);

	return NGX_AF_OK;
}

int update_entry_memcached(char *key, void *entry_p, ngx_http_access_filter_conf_t *afcf)
{
	// create new entry.
	return create_entry_memcached(key, afcf);
}

int create_entry_memcached(char *key, ngx_http_access_filter_conf_t *afcf)
{
	time_t expire_sec = ((time_t) (afcf->threshold_interval/1000)) + 1; // plus 1 to adjust milli sec.

	memcached_entry_t *entry_p = NULL;
	entry_p = malloc(sizeof(memcached_entry_t));

	gettimeofday(&entry_p->data.first_access_time, NULL);
	timerclear(&entry_p->data.banned_from);
	entry_p->data.access_count = 1;

	_set(key, entry_p, expire_sec);

	if (entry_p != NULL) {
		free(entry_p);
	}

	return NGX_AF_OK;
}

int fin_memcached(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf)
{
	if (memc != NULL) {
		memcached_free(memc);
	}
}

static memcached_entry_t* _parse(char *value)
{
	if (value == NULL) {
		return NULL;
	}

	memcached_entry_t *entry = NULL;
	entry = malloc(sizeof(memcached_entry_t));

	sscanf(value, VALUE_FORMAT,
		&entry->data.first_access_time.tv_sec, &entry->data.first_access_time.tv_usec,
		&entry->data.banned_from.tv_sec, &entry->data.banned_from.tv_usec,
		&entry->data.access_count
	);

	return entry;
}

static char* _compose(memcached_entry_t *entry)
{
	char buff[100], *value;
	unsigned int size;

	memset(buff, '\0', 100);
	sprintf(buff, VALUE_FORMAT,
		entry->data.first_access_time.tv_sec, entry->data.first_access_time.tv_usec,
		entry->data.banned_from.tv_sec, entry->data.banned_from.tv_usec,
		entry->data.access_count
	);

	size = strlen(buff);
	value = malloc(sizeof(char) * (size+1));
	strncpy(value, buff, size);
	value[size] = '\0';

	return value;
}

static int _connect(ngx_http_access_filter_conf_t *afcf)
{
	memcached_return rc;

	if (servers == NULL) {
		char *host = malloc(sizeof(char) * (afcf->memcached_server_host.len + 1));
		strncpy(host, afcf->memcached_server_host.data, afcf->memcached_server_host.len);
		host[afcf->memcached_server_host.len] = '\0';

		memc = memcached_create(NULL);
		servers = memcached_server_list_append(servers, host, afcf->memcached_server_port, &rc);
		rc = memcached_server_push(memc, servers);

		free(host);

		if (rc = MEMCACHED_SUCCESS) {
			return NGX_AF_NG;
		}
	}

	return NGX_AF_OK;
}

static int _set(char *key, memcached_entry_t *entry_p, time_t expire_sec)
{
	char *fullkey = _create_key(key);
	char *value;
	int flags = 0;
	memcached_return rc;

	value = _compose(entry_p);
	rc = memcached_set(memc, fullkey, strlen(fullkey), value, strlen(value), expire_sec, flags);

	if (fullkey != NULL) {
		free(fullkey);
	}
	if (value != NULL) {
		free(value);
	}

	return NGX_AF_OK;
}

static char* _get(char *remote_ip)
{
	char *fullkey = _create_key(remote_ip);
	char *value;
	int value_length;
	int flag;
	memcached_return rc;

	if (memc == NULL) {
		ngx_log_error(NGX_LOG_ERR, ctx_r->connection->log, 0, "memc is NULL");
		return NULL;
	}

	value = memcached_get(memc, fullkey, strlen(fullkey), &value_length, &flag, &rc);

	if (rc == MEMCACHED_NOTFOUND) {
		return NULL;
	}

	if (rc != MEMCACHED_SUCCESS) {
		ngx_log_error(NGX_LOG_ERR, ctx_r->connection->log, 0, "failed to get from memcached. %s", memcached_strerror(memc, rc));
		return NULL;
	}

	free(fullkey);
	return value;
}

static char* _create_key(char *remote_ip)
{
	char *fullkey;
	int size = strlen(remote_ip) + strlen(MEMCACHED_KEY_PREFIX);
	fullkey = malloc(sizeof(char) * (size + 1));

	strncpy(fullkey, MEMCACHED_KEY_PREFIX, strlen(MEMCACHED_KEY_PREFIX));
	strncpy(&fullkey[strlen(MEMCACHED_KEY_PREFIX)], remote_ip, strlen(remote_ip));
	fullkey[size] = '\0';

#ifdef DEBUG
	ngx_log_error(NGX_LOG_DEBUG, ctx_r->connection->log, 0, "_create_key called. remote_ip: %s, key: %s", remote_ip, fullkey);
#endif

	return fullkey;
}