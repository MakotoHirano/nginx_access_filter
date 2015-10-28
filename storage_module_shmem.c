#include <ngx_http_access_filter_module.h>
#include <storage_module_shmem.h>

static fifo_entry_t **fifo_ptr;
static fifo_entry_t *fifo_head;
static hashtable_entry_t **hashtable_ptr;
static int shmid = -1;
static int semid = -1;
static void* shm_ptr = NULL;

// private functions
static int _get_semaphore(void);
static int _ctl_semaphore(int op);
static void _reconstruct_reference(unsigned int hash, hashtable_entry_t *he);
static void _create_reference(char* remote_ip);
static void _update_fifo_reference(fifo_entry_t *fe);
static void _delete_hashtable_reference(hashtable_entry_t *he);
static void _insert_hashtable_reference(hashtable_entry_t *he, unsigned int hash);
static unsigned int _get_next_index(unsigned int current_index, unsigned int bucket_size);
static unsigned int _get_previous_index(unsigned int current_index, unsigned int bucket_size);
static unsigned int _hash(char *str, unsigned int bucket_size);

int init_shmem(ngx_cycle_t *cycle, ngx_http_access_filter_conf_t *afcf)
{
	semid = _get_semaphore();

	if (semid == -1) {
		return NGX_AF_NG;
	}

	if (_ctl_semaphore(LOCK) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "init_module#failed to lock semaphore. will exit.");
		return NGX_AF_NG;
	}

	if (_initialize_shmem(cycle, afcf) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "init_module#failed to initialize shmem. will exit.");
		return NGX_AF_NG;
	}

	if (_ctl_semaphore(UNLOCK) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "init_module#failed to unlock semaphore. will exit.");
		return NGX_AF_NG;
	}

	return NGX_AF_OK;
}

void* get_entry_shmem(char *remote_ip, ngx_http_access_filter_conf_t *afcf)
{
	if (rempte_ip == NULL || afcf == NULL) {
		return NULL;
	}

	hashtable_entry_t *hash_exist_p = NULL;
	unsigned int hash = _hash(remote_ip, afcf->bucket_size);

	for(hash_p = hashtable_ptr[hash]; hash_p != NULL; hash_p = hash_p->p_next) {
		if (strlen(hash_p->ip) != 0) {
			if ((strlen(hash_p->ip) == ctx_r->connection->addr_text.len)
				&& (strncmp(hash_p->ip, remote_ip, ctx_r->connection->addr_text.len) == 0)) {
				hash_exist_p = hash_p;
				break;
			}
		}
	}

	return hash_exist_p;
}

storage_entry_t* get_data_shmem(void *entry_p)
{
	if (entry_p == NULL) {
		return NULL;
	}

	hashtable_entry_t *hash_p = (hashtable_entry_t*) entry_p;

	return &hash_p->data;
}

int add_count_shmem(storage_entry_t *data, ngx_http_access_filter_conf_t *afcf)
{
	if (data == NULL || afcf == NULL) {
		return NGX_AF_OK;
	}

	if (_ctl_semaphore(LOCK) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_ERR, ctx_r->connection->log, 0, "failed to lock semaphore.");
		return NGX_AF_NG;
	}

	data->access_count++;

	if (_ctl_semaphore(UNLOCK) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_ERR, ctx_r->connection->log, 0, "failed to unlock semaphore.");
		return NGX_AF_NG;
	}

	return NGX_AF_OK;
}

int update_entry_shmem(char *key, void *entry_p, ngx_http_access_filter_conf_t *afcf)
{
	if (key == NULL || entry_p == NULL || strlen(key) == 0 || afcf == NULL) {
		return NGX_AF_OK;
	}

	if (_ctl_semaphore(LOCK) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_ERR, ctx_r->connection->log, 0, "failed to lock semaphore.");
		return NGX_AF_NG;
	}

	_reconstruct_reference((hashtable_entry_t*) entry_p);

	if (_ctl_semaphore(UNLOCK) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_ERR, ctx_r->connection->log, 0, "failed to unlock semaphore.");
		return NGX_AF_NG;
	}

	return NGX_AF_OK;
}

int create_entry_shmem(char *key, ngx_http_access_filter_conf_t *afcf)
{
	if (key == NULL || strlen(key) == 0 || afcf == NULL) {
		return NGX_AF_OK;
	}

	if (_ctl_semaphore(LOCK) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to lock semaphore.");
		return NGX_AF_NG;
	}

	_create_reference(remote_ip);

	if (_ctl_semaphore(UNLOCK) == NGX_AF_NG) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to unlock semaphore.");
		return NGX_AF_NG;
	}

	return NGX_AF_OK;
}

int fin_shmem(ngx_cycle_t *cycle)
{
	if (shmid != -1 && shm_unlink(KEY_SHMEM) == -1) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "exit_master: shm_unlink failed.");
		return NGX_AF_NG;
	}

	if (semid != -1 && semctl(semid, 0, IPC_RMID) == -1) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "exit_master: remove semaphore failed.");
		return NGX_AF_NG;
	}

	return NGX_AF_OK;
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

void _reconstruct_reference(hashtable_entry_t *he)
{
	fifo_entry_t *fe;
	fe = he->p_fifo;
	unsigned int hash = _hash(he->ip);

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

void _create_reference(char *remote_ip)
{
	fifo_entry_t *fe;
	hashtable_entry_t *he;
	int len = 0;
	unsigned int hash = _hash(remote_ip);

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

void _insert_hashtable_reference(hashtable_entry_t *he, unsigned int hash)
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

unsigned int _get_next_index(unsigned int current_index, unsigned int bucket_size)
{
	int next = current_index + 1;
	if (next >= bucket_size) {
		next = 0;
	}
	return next;
}

unsigned int _get_previous_index(unsigned int current_index, unsigned int bucket_size)
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
unsigned int _hash(char *str, unsigned int bucket_size)
{
	unsigned int hash = 31, i, len = strlen(str);

	for (i=0; i<len; i++) {
		hash *= str[i];
	}

	return hash % bucket_size;
}
