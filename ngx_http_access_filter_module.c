/* Makoto Hiano. All rights reserved. */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <regex.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define KEY_SEMAPHORE "./semaphore_nginx_access_filter"
#define KEY_SHMEM "./shmem_nginx_access_filter"
#define NGX_AF_OK 0
#define NGX_AF_NG -1
#define LOCK -1
#define UNLOCK 1

/**
 * directive struct
 */
typedef struct {
	ngx_flag_t enable;               // enable flag
	ngx_uint_t threshold_interval;   // interval count as continuous access (milli second)
	ngx_uint_t threshold_count;      // continuous count to be banned.
	ngx_uint_t time_to_be_banned;    // limited interval to access site. (second)
	ngx_uint_t bucket_size;          // max size of bucket to hold each ip.
	char* except_regex;          // except_regex of target filename
} ngx_http_access_filter_conf_t;

typedef struct hashtable_entry_s hashtable_entry_t;
typedef struct fifo_entry_s fifo_entry_t;

struct hashtable_entry_s {
	char ip[16];
	struct timeval last_access_time;
	struct timeval banned_from;
	ngx_uint_t access_count;
	hashtable_entry_t *p_next;
	hashtable_entry_t *p_prev;
	fifo_entry_t *p_fifo;
	ngx_uint_t hash;
};

struct fifo_entry_s {
	fifo_entry_t *p_next;
	fifo_entry_t *p_prev;
	hashtable_entry_t *p_hash;
};

// nginx functions
static void * ngx_http_access_filter_create_conf(ngx_conf_t *cf);
static char * ngx_http_access_filter_init_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_access_filter_postconfig(ngx_conf_t *cf);
static ngx_int_t ngx_http_access_filter_handler(ngx_http_request_t *r);
static ngx_int_t init_module(ngx_cycle_t *cycle);
static void exit_master(ngx_cycle_t *cycle);

// user functions
ngx_int_t _initialize_shmem(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf);
int _get_semaphore(void);
int _ctl_semaphore(int op);
void _update_reference(hashtable_entry_t *he);
void _reconstruct_reference(ngx_uint_t hash, hashtable_entry_t *he);
void _create_reference(ngx_uint_t hash, char* remote_ip);
void _update_fifo_reference(fifo_entry_t *fe);
void _delete_hashtable_reference(hashtable_entry_t *he);
void _insert_hashtable_reference(hashtable_entry_t *he, ngx_uint_t hash);
ngx_int_t _get_next_index(ngx_int_t current_index, ngx_int_t bucket_size);
ngx_int_t _get_previous_index(ngx_int_t current_index, ngx_int_t bucket_size);
ngx_int_t _hash(char *str, ngx_uint_t bucket_size);

static fifo_entry_t **fifo_ptr;
static fifo_entry_t *fifo_head;
static hashtable_entry_t **hashtable_ptr;
static ngx_http_request_t *ctx_r;
static regex_t regex_buffer;
static int shmid = -1;
static int semid = -1;
static void* shm_ptr = NULL;

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
	ngx_http_access_filter_conf_t *afcf;
	afcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_access_filter_module);

#ifdef DEBUG
	ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "init_module called. enable: %d, threshold_interval: %d, threshold_count: %d, time_to_be_banned: %d, bucket_size: %d",
		afcf->enable, afcf->threshold_interval, afcf->threshold_count, afcf->time_to_be_banned, afcf->bucket_size);
#endif

	semid = _get_semaphore();

	if (_ctl_semaphore(LOCK) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "init_module#failed to lock semaphore. will exit.");
		return NGX_ERROR;
	}

	if (_initialize_shmem(cycle, afcf) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "init_module#failed to initialize shmem. will exit.");
		return NGX_ERROR;
	}

	if (_ctl_semaphore(UNLOCK) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "init_module#failed to unlock semaphore. will exit.");
		return NGX_ERROR;
	}

	return NGX_OK;
}

static void exit_master(ngx_cycle_t *cycle)
{
#ifdef DEBUG
	ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exit master called.");
#endif

	//
	// cleanup.
	//
	if (shmid != NGX_AF_NG && shm_unlink(KEY_SHMEM) == -1) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "exit_master: shm_unlink failed.");
	}

	if (semid != NGX_AF_NG && semctl(semid, 0, IPC_RMID) == -1) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "exit_master: remove semaphore failed.");
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

	conf->enable = NGX_CONF_UNSET_UINT;
	conf->threshold_interval = NGX_CONF_UNSET_UINT;
	conf->threshold_count = NGX_CONF_UNSET_UINT;
	conf->time_to_be_banned = NGX_CONF_UNSET_UINT;
	conf->bucket_size = NGX_CONF_UNSET_UINT;
	conf->except_regex = NGX_CONF_UNSET_PTR;

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
	unsigned int hash;
	hashtable_entry_t *hash_p = NULL, *hash_exist_p = NULL;
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
	// remote_ip = malloc(sizeof(char) * (r->connection->addr_text.len+1));
	remote_ip = ngx_pcalloc(r->pool, sizeof(char) * (r->connection->addr_text.len+1));
	strncpy(remote_ip, (char *) r->connection->addr_text.data, r->connection->addr_text.len);
	remote_ip[r->connection->addr_text.len] = '\0';

	//
	// traverse hashtable_ptr.
	//
	hash = _hash(remote_ip, afcf->bucket_size);

	for(hash_p = hashtable_ptr[hash]; hash_p != NULL; hash_p = hash_p->p_next) {
		if (strlen(hash_p->ip) != 0 && hash_p->ip != NULL) {
			if ((strlen(hash_p->ip) == r->connection->addr_text.len)
				&& (strncmp(hash_p->ip, remote_ip, r->connection->addr_text.len) == 0)) {
				hash_exist_p = hash_p;
				break;
			}
		}
	}

	//
	// already exists.
	//
	if (hash_exist_p != NULL) {
		if (timerisset(&hash_exist_p->banned_from)) {
			timersub(&now, &hash_exist_p->banned_from, &diff);
			elapsed = (double) diff.tv_sec + ((double) diff.tv_usec / 1000.0 / 1000.0);

			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "banned elapsed: %.3f, threshold: %d", elapsed, afcf->time_to_be_banned);

			if (elapsed <= (double) afcf->time_to_be_banned) {
				ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "forbidden. still in banned interval. elapsed: %.3f", elapsed);
				return NGX_HTTP_FORBIDDEN;
			}
		}

		timersub(&now, &hash_exist_p->last_access_time, &diff);
		elapsed = (double) diff.tv_sec + ((double) diff.tv_usec / 1000.0 / 1000.0);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "access elapsed: %.3f, threshold: %.3f", elapsed, afcf->threshold_interval/1000.0);

		if ((timerisset(&hash_exist_p->last_access_time) == 0) || (elapsed >= (double) afcf->threshold_interval / 1000.0)) {
			if (_ctl_semaphore(LOCK) == NGX_AF_NG) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to lock semaphore.");
				return NGX_DECLINED;
			}
			_reconstruct_reference(hash, hash_exist_p);
			if (_ctl_semaphore(UNLOCK) == NGX_AF_NG) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to unlock semaphore.");
				return NGX_DECLINED;
			}

		} else {
			if (_ctl_semaphore(LOCK) == NGX_AF_NG) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to lock semaphore.");
				return NGX_DECLINED;
			}
			_update_reference(hash_exist_p);
			if (_ctl_semaphore(UNLOCK) == NGX_AF_NG) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to unlock semaphore.");
				return NGX_DECLINED;
			}

			//
			// check threshold.
			//
			if (hash_exist_p->access_count >= afcf->threshold_count) {
				ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "over access. ip: %s, count: %d", hash_exist_p->ip, hash_exist_p->access_count);
				timerclear(&hash_exist_p->last_access_time);
				gettimeofday(&hash_exist_p->banned_from, NULL);
				return NGX_HTTP_FORBIDDEN;
			}
		}

	} else {
		if (_ctl_semaphore(LOCK) == NGX_AF_NG) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to lock semaphore.");
			return NGX_DECLINED;
		}
		_create_reference(hash, remote_ip);
		if (_ctl_semaphore(UNLOCK) == NGX_AF_NG) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to unlock semaphore.");
			return NGX_DECLINED;
		}
	}

	ngx_pfree(r->pool, remote_ip);

	return NGX_DECLINED;
}

int _get_semaphore(void)
{
	int semid;
	union semnum {
		int val;
		struct semid_ds *buf;
		ushort *array;
	} semval;


	if ((semid = semget(ftok(KEY_SEMAPHORE, 1), 1, IPC_CREAT|S_IRWXU|S_IRWXG|S_IRWXO)) == -1) {
		perror("semget");
		return -1;
	}

	if (semctl(semid, 0, GETVAL, semval) == -1) {
		perror("semctl get");
		return -1;
	}

	semval.val = 1;
	if (semctl(semid, 0, SETVAL, semval) == -1) {
		perror("semctl set");
		return -1;
	}

	return semid;
}

int _ctl_semaphore(int op)
{
	struct sembuf sops[1];

	if (semid == -1) {
		return NGX_AF_NG;
	}

	sops[0].sem_num = 0;
	sops[0].sem_op = op;
	sops[0].sem_flg = 0;

	if (semop(semid, sops, 1) == -1) {
		return NGX_AF_NG;
	}

	return NGX_AF_OK;
}

void _update_reference(hashtable_entry_t *he)
{
	he->access_count++;
}

void _reconstruct_reference(ngx_uint_t hash, hashtable_entry_t *he)
{
	fifo_entry_t *fe;
	fe = he->p_fifo;

	//
	// initialize (except ip)
	//
	he->access_count = 1;
	gettimeofday(&he->last_access_time, NULL);
	timerclear(&he->banned_from);

	if (hashtable_ptr[hash] != he) {
		_delete_hashtable_reference(he);
		_insert_hashtable_reference(he, hash);
	}
	_update_fifo_reference(fe);
}

void _create_reference(ngx_uint_t hash, char *remote_ip)
{
	fifo_entry_t *fe;
	hashtable_entry_t *he;
	int len = 0;

	fe = fifo_head->p_prev; // latest
	he = fe->p_hash;

	//
	// initialize
	//
	he->access_count = 1;
	gettimeofday(&he->last_access_time, NULL);
	timerclear(&he->banned_from);

	len = strlen(remote_ip);
	strncpy(he->ip, remote_ip, len);
	he->ip[len] = '\0';

	_delete_hashtable_reference(he);
	_insert_hashtable_reference(he, hash);
	_update_fifo_reference(fe);
}

void _update_fifo_reference(fifo_entry_t *fe)
{
	if (fifo_head == fe) {
		return;
	}

	// delete
	fe->p_prev->p_next = fe->p_next;
	fe->p_next->p_prev = fe->p_prev;

	// insert
	fe->p_next = fifo_head;
	fe->p_prev = fifo_head->p_prev;

	fifo_head->p_prev->p_next = fe;
	fifo_head->p_prev = fe;

	fifo_head = fe;
}

void _delete_hashtable_reference(hashtable_entry_t *he)
{
	if (he->p_prev != NULL) {
		he->p_prev->p_next = he->p_next;
	}
	if (he->p_next != NULL) {
		he->p_next->p_prev = he->p_prev;
	}
	if (hashtable_ptr[he->hash] == he) {
		hashtable_ptr[he->hash] = NULL;
	}
}

void _insert_hashtable_reference(hashtable_entry_t *he, ngx_uint_t hash)
{
	hashtable_entry_t *head;
	head = hashtable_ptr[hash];

	if (head != NULL) {
		he->p_next = head;
		he->p_prev = head->p_prev;
		head->p_prev = he;
	} else {
		he->p_next = NULL;
		he->p_prev = NULL;
	}

	he->hash = hash;
	hashtable_ptr[hash] = he;
}

ngx_int_t _initialize_shmem(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf)
{
#ifdef DEBUG
	ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "_initialize_shmem called.");
#endif

	char *regex;
	ngx_uint_t i;
	int memsize;

	//
	// get shared memory.
	//
	memsize = afcf->bucket_size *
		(
			sizeof(fifo_entry_t) + sizeof(hashtable_entry_t) +
			sizeof(fifo_entry_t *) + sizeof(hashtable_entry_t *)
		);
	shmid = shm_open(KEY_SHMEM, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	ftruncate(shmid, memsize);
	if ((shm_ptr = mmap(0, memsize, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, shmid, 0)) == MAP_FAILED) {
		return NGX_AF_NG;
	}

	//
	// initialize fifo_ptr.
	// make fifo_ptr pool.
	//
	fifo_entry_t **fifo_pp, *fifo_p;

	fifo_head = fifo_p = shm_ptr;
	fifo_ptr = fifo_pp = (fifo_entry_t**) ((char *)shm_ptr + sizeof(fifo_entry_t) * afcf->bucket_size);
	for (i=0; i < afcf->bucket_size; i++) {
		int next = _get_next_index(i, afcf->bucket_size);
		int prev = _get_previous_index(i, afcf->bucket_size);

		fifo_p[i].p_next = &fifo_p[next];
		fifo_p[i].p_prev = &fifo_p[prev];
		fifo_p[i].p_hash = NULL;

		fifo_pp[i] = &fifo_p[i];
	}

	//
	// initialize hashtable_ptr.
	// make hashtable_ptr pool.
	//
	hashtable_entry_t **hashtable_pp, *hashtable_p;

	hashtable_p = (hashtable_entry_t*) ((char *) shm_ptr + (sizeof(fifo_entry_t) + sizeof(fifo_entry_t*)) * afcf->bucket_size);
	hashtable_ptr = hashtable_pp = (hashtable_entry_t**) ((char *) shm_ptr + (sizeof(fifo_entry_t) + sizeof(fifo_entry_t*) + sizeof(hashtable_entry_t)) * afcf->bucket_size);
	for (i=0; i<afcf->bucket_size; i++) {
		hashtable_p[i].ip[0] = '\0';
		gettimeofday(&hashtable_p[i].last_access_time, NULL);
		timerclear(&hashtable_p[i].banned_from);
		hashtable_p[i].access_count = 0;
		hashtable_p[i].p_next = NULL;
		hashtable_p[i].p_prev = NULL;
		hashtable_p[i].p_fifo = NULL;
		hashtable_p[i].hash = i;

		hashtable_pp[i] = &hashtable_p[i];
	}


	//
	// update each reference.
	//
	for (i=0; i<afcf->bucket_size; i++) {
		fifo_ptr[i]->p_hash = hashtable_ptr[i];
		hashtable_ptr[i]->p_fifo = fifo_ptr[i];
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

ngx_int_t _get_next_index(ngx_int_t current_index, ngx_int_t bucket_size)
{
	int next = current_index + 1;
	if (next >= bucket_size) {
		next = 0;
	}
	return next;
}

ngx_int_t _get_previous_index(ngx_int_t current_index, ngx_int_t bucket_size)
{
	int prev = current_index - 1;
	if (prev < 0) {
		prev = bucket_size - 1;
	}
	return prev;
}

/**
 * create hash value from string
 */
ngx_int_t _hash(char *str, ngx_uint_t bucket_size)
{
	ngx_uint_t hash = 31, i, len = strlen(str);

	for (i=0; i<len; i++) {
		hash *= str[i];
	}

	return hash % bucket_size;
}


