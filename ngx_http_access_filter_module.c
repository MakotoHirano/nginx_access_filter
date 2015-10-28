/* Makoto Hiano. All rights reserved. */
#include "ngx_http_access_filter_module.h"

/**
 * function pointers.
 * it behaves like interface.
 */
typedef struct {
	int (*init)(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf);
	void* (*get_entry)(char *key, ngx_http_access_filter_conf_t *afcf);
	storage_entry_t* (*get_data)(void *entry_p);
	int (*add_count)(storage_entry_t *data, ngx_http_access_filter_conf_t *afcf);
	int (*update_entry)(char *key, void *entry_p, ngx_http_access_filter_conf_t *afcf);
	int (*create_entry)(char *key, ngx_http_access_filter_conf_t *afcf);
	int (*fin)(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf);
} storage_accessor;

// nginx functions
static void * ngx_http_access_filter_create_conf(ngx_conf_t *cf);
static char * ngx_http_access_filter_init_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_access_filter_postconfig(ngx_conf_t *cf);
static ngx_int_t ngx_http_access_filter_handler(ngx_http_request_t *r);
static ngx_int_t init_module(ngx_cycle_t *cycle);
static void exit_master(ngx_cycle_t *cycle);

static regex_t regex_buffer;
static storage_accessor accessor;

static ngx_command_t ngx_http_access_filter_commands[] = {
	{
		ngx_string("access_filter"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_access_filter_conf_t, enable),
		NULL
	},
	{
		ngx_string("access_filter_threshold_interval"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_access_filter_conf_t, threshold_interval),
		NULL
	},
	{
		ngx_string("access_filter_threshold_count"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_access_filter_conf_t, threshold_count),
		NULL
	},
	{
		ngx_string("access_filter_time_to_be_banned"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_access_filter_conf_t, time_to_be_banned),
		NULL
	},
	{
		ngx_string("access_filter_bucket_size"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_access_filter_conf_t, bucket_size),
		NULL
	},
	{
		ngx_string("access_filter_except_regex"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_access_filter_conf_t, except_regex),
		NULL
	},
	{
		ngx_string("access_filter_storage"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_access_filter_conf_t, storage),
		NULL
	},

	ngx_null_command
};

static ngx_http_module_t ngx_http_access_filter_module_ctx = {
	NULL, /* preconfiguration */
	ngx_http_access_filter_postconfig, /* postconfiguration */

	ngx_http_access_filter_create_conf, /* create main configuation */
	ngx_http_access_filter_init_conf, /* init main configuation */

	NULL, /* create server configuration */
	NULL,   /* merge server configuration */

	NULL, /* create location configuration */
	NULL  /* merge location configuration */
};

ngx_module_t ngx_http_access_filter_module = {
	NGX_MODULE_V1,
	&ngx_http_access_filter_module_ctx, /* module context */
	ngx_http_access_filter_commands, /* module directives */
	NGX_HTTP_MODULE, /* module type */
	NULL, /* init master */
	init_module, /* init module */
	NULL, /* init process */
	NULL, /* init thread */
	NULL, /* exit thread */
	NULL, /* exit process */
	exit_master, /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t init_module(ngx_cycle_t *cycle)
{
	char *regex;
	ngx_http_access_filter_conf_t *afcf;
	afcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_access_filter_module);

#ifdef DEBUG
	ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "init_module called. enable: %d, threshold_interval: %d, threshold_count: %d, time_to_be_banned: %d, bucket_size: %d",
		afcf->enable, afcf->threshold_interval, afcf->threshold_count, afcf->time_to_be_banned, afcf->bucket_size);
#endif

	//
	// initialize accessor functions.
	//
	if (strcmp(afcf->storage, STORAGE_SHMEM) == 0) {
		accessor.init = init_shmem;
		accessor.get_entry = get_entry_shmem;
		accessor.get_data = get_data_shmem;
		accessor.add_count = add_count_shmem;
		accessor.update_entry = update_entry_shmem;
		accessor.create_entry = create_entry_shmem;
		accessor.fin = fin_shmem;

	} else if (strcmp(afcf->storage, STORAGE_MEMCACHED) == 0) {
		accessor.init = init_memcached;
		accessor.get_entry = get_entry_memcached;
		accessor.get_data = get_data_memcached;
		accessor.add_count = add_count_memcached;
		accessor.update_entry = update_entry_memcached;
		accessor.create_entry = create_entry_memcached;
		accessor.fin = fin_memcached;

	} else {
		// exit
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "init_module invalid storage type found: %s", afcf->storage);
		return NGX_ERROR;
	}

	if ((accessor.init != NULL) && (accessor.init(cycle, afcf) == NGX_AF_NG)) {
		ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "initialize failed.");
		return NGX_ERROR;
	}

	//
	// compile regex.
	//
	regex = malloc(sizeof(char) * (strlen(afcf->except_regex) + 1));
	strncpy(regex, afcf->except_regex, strlen(afcf->except_regex));
	regex[strlen(afcf->except_regex)] = '\0';
	regcomp(&regex_buffer, regex, REG_EXTENDED|REG_NEWLINE|REG_NOSUB);
	free(regex);

	return NGX_OK;
}

static void exit_master(ngx_cycle_t *cycle)
{
#ifdef DEBUG
	ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exit master called.");
#endif

	ngx_http_access_filter_conf_t *afcf;
	afcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_access_filter_module);

	if ((accessor.fin != NULL) && (accessor.fin(cycle, afcf) == NGX_AF_NG)) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "fin failed.");
	}

	return;
}

static void * ngx_http_access_filter_create_conf(ngx_conf_t *cf)
{
	ngx_http_access_filter_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_access_filter_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}

	conf->enable             = NGX_CONF_UNSET_UINT;
	conf->threshold_interval = NGX_CONF_UNSET_UINT;
	conf->threshold_count    = NGX_CONF_UNSET_UINT;
	conf->time_to_be_banned  = NGX_CONF_UNSET_UINT;
	conf->bucket_size        = NGX_CONF_UNSET_UINT;
	conf->except_regex       = NGX_CONF_UNSET_PTR;
	conf->storage            = NGX_CONF_UNSET_PTR;

	return conf;
}

static char * ngx_http_access_filter_init_conf(ngx_conf_t *cf, void *_conf)
{
	ngx_http_access_filter_conf_t *conf = _conf;

	ngx_conf_init_value(conf->enable, 0);
	ngx_conf_init_uint_value(conf->threshold_interval, 1000); // msec
	ngx_conf_init_uint_value(conf->threshold_count, 10);
	ngx_conf_init_uint_value(conf->time_to_be_banned, 60 * 60); // sec
	ngx_conf_init_uint_value(conf->bucket_size, 50);
	ngx_conf_init_ptr_value(conf->except_regex, "\\.(js|css|mp3|ogg|wav|png|jpeg|jpg|gif|ico|woff|swf)\\??");
	ngx_conf_init_ptr_value(conf->storage, STORAGE_SHMEM);

	if (conf->enable != 1 && conf->enable != 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "enable must be on or off");
		return NGX_CONF_ERROR;
	}

	if (conf->threshold_interval < 1) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "threshold_interval must be equals or more than 1");
		return NGX_CONF_ERROR;
	}

	if (conf->threshold_count < 1) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "threshold_count must be equals or more than 1");
		return NGX_CONF_ERROR;
	}

	if (conf->time_to_be_banned < 1) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "time_to_be_banned must be equals or more than 1");
		return NGX_CONF_ERROR;
	}

	if (conf->bucket_size < 1) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bucket_size must be equals or more than 1");
		return NGX_CONF_ERROR;
	}

	if ((strcmp(conf->storage, STORAGE_SHMEM) != 0) && (strcmp(conf->storage, STORAGE_MEMCACHED) != 0)) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "storage must be %s or %s.", STORAGE_SHMEM, STORAGE_MEMCACHED);
		return NGX_CONF_ERROR;
	}

	ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "access_filter merge conf done. enable: %d, threshold_interval: %d, threshold_count: %d, time_to_be_banned: %d, bucket_size: %d",
		conf->enable, conf->threshold_interval, conf->threshold_count, conf->time_to_be_banned, conf->bucket_size);
	return NGX_CONF_OK;
}

/**
 * post config.
 */
static ngx_int_t ngx_http_access_filter_postconfig(ngx_conf_t *cf)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}
	*h = ngx_http_access_filter_handler;

	return NGX_OK;
}

/**
 * request handler.
 */
static ngx_int_t ngx_http_access_filter_handler(ngx_http_request_t *r)
{
	char *remote_ip, *uri;
	void *entry_exist_p = NULL;
	storage_entry_t *data_exist_p = NULL;
	ngx_http_access_filter_conf_t *afcf;
	struct timeval now, diff;
	double elapsed;
	int regret;

	ctx_r = r;
	afcf = ngx_http_get_module_main_conf(r, ngx_http_access_filter_module);

	//
	// check enable config.
	//
	if (afcf->enable == 0) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "*** ngx_http_access_header_handler disabled. will return. ***");
		return NGX_DECLINED;
	}

	//
	// filter except regex.
	//
	uri = ngx_pcalloc(r->pool, sizeof(char) * (r->uri.len+1));
	strncpy(uri, (char *) r->uri.data, r->uri.len);
	uri[r->uri.len] = '\0';
	regret = regexec(&regex_buffer, uri, 0, NULL, 0);
	ngx_pfree(r->pool, uri);

	if (regret == 0) { // matched.
		return NGX_DECLINED;
	}

	gettimeofday(&now, NULL);

	//
	// get remote ip.
	//
	remote_ip = ngx_pcalloc(r->pool, sizeof(char) * (r->connection->addr_text.len+1));
	strncpy(remote_ip, (char *) r->connection->addr_text.data, r->connection->addr_text.len);
	remote_ip[r->connection->addr_text.len] = '\0';

	//
	// get entry.
	//
	if (accessor.get_entry != NULL) {
		entry_exist_p = accessor.get_entry(remote_ip, afcf);
	}
	if (accessor.get_data != NULL) {
		data_exist_p = accessor.get_data(entry_exist_p);
	}

	//
	// already exists.
	//
	if (data_exist_p != NULL) {
		if (timerisset(&data_exist_p->banned_from)) {
			timersub(&now, &data_exist_p->banned_from, &diff);
			elapsed = (double) diff.tv_sec + ((double) diff.tv_usec / 1000.0 / 1000.0);

			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "banned elapsed: %.3f, threshold: %d", elapsed, afcf->time_to_be_banned);

			if (elapsed <= (double) afcf->time_to_be_banned) {
				ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "forbidden. still in banned interval. elapsed: %.3f", elapsed);
				return NGX_HTTP_FORBIDDEN;
			}
		}

		timersub(&now, &data_exist_p->last_access_time, &diff);
		elapsed = (double) diff.tv_sec + ((double) diff.tv_usec / 1000.0 / 1000.0);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "access elapsed: %.3f, threshold: %.3f", elapsed, afcf->threshold_interval/1000.0);

		if ((timerisset(&data_exist_p->last_access_time) == 0) || (elapsed >= (double) afcf->threshold_interval / 1000.0)) {
			if ((accessor.update_entry != NULL) && (accessor.update_entry(remote_ip, entry_exist_p, afcf) == NGX_AF_NG)) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to update_entry.");
				return NGX_DECLINED;
			}

		} else {
			if ((accessor.add_count != NULL) && (accessor.add_count(data_exist_p, afcf) == NGX_AF_NG)) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to add_count.");
				return NGX_DECLINED;
			}

			//
			// check threshold.
			//
			if (data_exist_p->access_count >= afcf->threshold_count) {
				ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "over access. ip: %s, count: %d", remote_ip, data_exist_p->access_count);
				timerclear(&data_exist_p->last_access_time);
				gettimeofday(&data_exist_p->banned_from, NULL);
				return NGX_HTTP_FORBIDDEN;
			}
		}

	} else {
		if ((accessor.create_entry != NULL) && (accessor.create_entry(remote_ip, afcf) == NGX_AF_NG)) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to create_entry.");
			return NGX_DECLINED;
		}
	}

	ngx_pfree(r->pool, remote_ip);

	return NGX_DECLINED;
}
