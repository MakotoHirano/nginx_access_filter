### nginx_access_filter_module
`ngx_http_access_module` is developed to provide function which avoid DOS attack.
This module counts accesses from client using IP origin.

And if the count exceed certain count while certain time (the count and time are set by configuration file), the nginx web server will response 403 Forbidden while after certain time.

And the case you don't want to count all files. (ex. you want to count only html extension but not image files like jpg, png, gif)
You can set URI to be counted or not using regular expression on confing file.

This module uses unix os shared memory segment to save access histories.
so of course, if there are multiple worker processes, they can access same memory spaces.

And on demand, also you can use memcached as storage.
so you can prepare nginx server hosts with memcached configuration.

### Configuration
There are some kind of configurations.
The configurations must be inside http directive.

|Key|Description|Default|
|---|---|---|
|access_filter|enable filter or not. can takes on or off|off|
|access_filter_threshold_interval|interval time (millisec) counted as continuous access.|1000 (millisec)|
|access_filter_threshold_count|access count which is recognized as too much access.|10|
|access_filter_time_to_be_banned|the time (sec) to respond 403 after recognized as illegular access|60 * 60|
|access_filter_bucket_size|the bucket size to retain latest accesses. so module retain that number of IP count in the process|50|
|access_filter_except_regex|the clanguage regular expression filter that will be ignored.|-|
|access_filter_storage|the storage that is used to save user access information.|shmem|
|access_filter_memcached_server_host|the host name or ip of memcached server.|127.0.0.1|
|access_filter_memcached_server_port|the port num of memcached server.|11211|

#### Example
Then I will show you example configuration below.
If there are client which access over 10 count in 1000 millisec, the nginx http will response 403 for 30 seconds.

```
server {
	...
	access_filter on;
	access_filter_threshold_interval 1000;
	access_filter_threshold_count 10;
	access_filter_time_to_be_banned 30;
	access_filter_bucket_size 50;
	access_filter_regex \\.(js|css|mp3|ogg|wav|png|jpeg|jpg|gif|ico|woff|swf)\\??;
	access_filter_storage shmem;
	...
}
```

If you want to use memcached as storage. you can set configuration like below.

```
server {
	...
	access_filter on;
	access_filter_threshold_interval 1000;
	access_filter_threshold_count 10;
	access_filter_time_to_be_banned 30;
	access_filter_storage memcached;
	access_filter_memcached_host 127.0.0.1;
	access_filter_memcached_port 11211;
	...
}
```


#### Install
Just as ordinal. add --add-module options to configure.
notice that you have to prepare `libmemcached`.

```
./configure --add-module=/path/to/nginx_access_filter_module --with-ld-opt="-lrt -lmemcached"
make
make install
```