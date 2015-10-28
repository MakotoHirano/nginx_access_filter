#include "storage_module_shmem.h"
#include <libmemcached/memcached.h>

static int _connect();
static int _disconnect();

static memcached_st *memc = NULL;

int init_memcached(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf)
{
	// concern whether keep connection or not.
	_connect(afcf->memcached_servers);

	return NGX_AF_OK;
}

void* get_entry_memcached(char *key, ngx_http_access_filter_conf_t *afcf)
{

}

storage_entry_t* get_data_memcached(void *entry_p)
{

}

int add_count_memcached(storage_entry_t *data, ngx_http_access_filter_conf_t *afcf)
{

}

int update_entry_memcached(char *key, void *entry_p, ngx_http_access_filter_conf_t *afcf)
{

}

int create_entry_memcached(char *key, ngx_http_access_filter_conf_t *afcf)
{

}

int fin_memcached(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf)
{
	if (memc != NULL) {
		memcached_free(memc);
	}
}

int _connect(char *hosts)
{
	memc = memcached(hosts, strlen(hosts));

	return NGX_AF_OK;
}
