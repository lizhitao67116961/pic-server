/*
 * imgzip_conf.c
 *
 *  Created on: 2013-4-23
 *      Author: lizhitao
 */

#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#define NGX_CONF_ERROR       (void *) -1
#define NGX_CONF_BUFFER 4096
#define NGX_CONF_BLOCK_START 1
#define NGX_CONF_BLOCK_DONE  2
#define NGX_CONF_FILE_DONE   3

imgzip_http_server_conf_t imgzip_server_conf;
ngx_hash_t *hashtable;
//ngx_array_t *checkip;
typedef struct {
	ngx_array_t *args;
	ngx_buf_t *buf;
	ngx_pool_t *pool;
	int fd;
	off_t offset;
	struct stat file_info;
} ngx_conf_t;
typedef void* (*imgzip_create_conf)();
typedef struct imgzip_conf_module_s imgzip_conf_module_t;
struct imgzip_conf_module_s {
	ngx_str_t name;
	imgzip_create_conf create;
	off_t offset;
	char *(*set)(ngx_conf_t *cf, imgzip_conf_module_t *cmd, void *conf, void *sub_conf);
	void *sub_conf;
	off_t next;
};

static void* imgzip_conf_create_memc_conf(ngx_conf_t *cf);
static void* imgzip_conf_create_img_conf(ngx_conf_t *cf);
static void* imgzip_conf_create_mysql_conf(ngx_conf_t *cf);
static char* imgzip_conf_set_struct_value(ngx_conf_t *cf, imgzip_conf_module_t *mod, void *conf, void *sub_conf);
static char* imgzip_conf_set_int_val(ngx_conf_t *cf, imgzip_conf_module_t *mod, void *conf, void *sub_conf);
static char* imgzip_conf_set_str_val(ngx_conf_t *cf, imgzip_conf_module_t *mod, void *conf, void *sub_conf);
static ngx_int_t ngx_conf_handler(ngx_conf_t *cf, ngx_int_t last, imgzip_conf_module_t *conf_module, void *conf);
static ngx_int_t ngx_conf_read_token(ngx_conf_t *cf);
static ssize_t ngx_read_file(int fd, u_char *buf, size_t size, off_t offset);
static char *conf_parse(ngx_str_t *filename, ngx_conf_t *cf, imgzip_conf_module_t *conf_module, void *conf);
static char* mime_parse(ngx_str_t *filepath, ngx_conf_t *cf, ngx_array_t *elements);
static ngx_int_t ngx_http_image_create_hashtable(ngx_conf_t *cf,ngx_array_t *elts,ngx_str_t *value,ngx_int_t *index);
static ngx_int_t ngx_image_hash_init(ngx_array_t *elements,ngx_pool_t *pool);
//static char* ip_parse(ngx_str_t *full_ip, ngx_array_t *checkip);

static imgzip_conf_module_t img_module_conf[] = { { ngx_string("img_max_width"), 0, offsetof(imgzip_img_conf_t,img_max_width), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("img_max_height"), 0, offsetof(imgzip_img_conf_t,img_max_height), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("add_water_min_size"), 0, offsetof(imgzip_img_conf_t,add_water_min_size), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("add_water_point_x"), 0, offsetof(imgzip_img_conf_t,add_water_point_x), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("add_water_point_y"), 0, offsetof(imgzip_img_conf_t,add_water_point_y), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_null_string, 0, 0, 0, 0, 0 } };

static imgzip_conf_module_t mysql_module_conf[] = { { ngx_string("address"), 0, offsetof(imgzip_mysql_server_conf_t,address), imgzip_conf_set_str_val, 0, 0 }, //
		{ ngx_string("back_address"), 0, offsetof(imgzip_mysql_server_conf_t,back_address), imgzip_conf_set_str_val, 0, 0 }, //
		{ ngx_string("range"), 0, offsetof(imgzip_mysql_server_conf_t,range), imgzip_conf_set_str_val, 0, 0 }, //
		{ ngx_string("user_name"), 0, offsetof(imgzip_mysql_server_conf_t,user_name), imgzip_conf_set_str_val, 0, 0 }, //
		{ ngx_string("pass_word"), 0, offsetof(imgzip_mysql_server_conf_t,pass_word), imgzip_conf_set_str_val, 0, 0 }, //
		{ ngx_string("max_pool_size"), 0, offsetof(imgzip_mysql_server_conf_t,max_pool_size), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("min_pool_size"), 0, offsetof(imgzip_mysql_server_conf_t,min_pool_size), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("port"), 0, offsetof(imgzip_mysql_server_conf_t,port), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("timeout"), 0, offsetof(imgzip_mysql_server_conf_t,timeout), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("idle_timeout"), 0, offsetof(imgzip_mysql_server_conf_t,idle_timeout), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_null_string, 0, 0, 0, 0, 0 }

};
static imgzip_conf_module_t memc_module_conf[] = { { ngx_string("memc_ip"), 0, offsetof(imgzip_memc_conf_t,memc_ip), imgzip_conf_set_str_val, 0, 0 }, //
		{ ngx_string("port"), 0, offsetof(imgzip_memc_conf_t,port), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("memc_max_cached_size"), 0, offsetof(imgzip_memc_conf_t,memc_max_cached_size), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("memc_recv_buf"), 0, offsetof(imgzip_memc_conf_t,memc_recv_buf), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("retry_time"), 0, offsetof(imgzip_memc_conf_t,retry_time), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("memc_client_max_fails"), 0, offsetof(imgzip_memc_conf_t,memc_client_max_fails), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("read_timeout"), 0, offsetof(imgzip_memc_conf_t,read_timeout), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_null_string, 0, 0, 0, 0, 0 }

};

static imgzip_conf_module_t server_module_conf[] = { { ngx_string("listen_port"), 0, offsetof(imgzip_http_server_conf_t,listen_port), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("server_id"), 0, offsetof(imgzip_http_server_conf_t,server_id), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("error_log_level"), 0, offsetof(imgzip_http_server_conf_t,error_log_level), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("daemon"), 0, offsetof(imgzip_http_server_conf_t,daemon), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("master_process"), 0, offsetof(imgzip_http_server_conf_t,master_process), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("resources_path"), 0, offsetof(imgzip_http_server_conf_t,resources_path), imgzip_conf_set_str_val, 0, 0 }, //
		{ ngx_string("process_num"), 0, offsetof(imgzip_http_server_conf_t,process_num), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("worker_connectons"), 0, offsetof(imgzip_http_server_conf_t,worker_connectons), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("mysql_db_max_range"), 0, offsetof(imgzip_http_server_conf_t,mysql_db_max_range), imgzip_conf_set_int_val, 0, 0 }, //
		{ ngx_string("little_access_mysql"), 0, offsetof(imgzip_http_server_conf_t,little_access_mysql), imgzip_conf_set_int_val, 0, 0}, //
		{ ngx_string("error_log_path"), 0, offsetof(imgzip_http_server_conf_t,error_log_path), imgzip_conf_set_str_val, 0, 0 }, //
		{ ngx_string("access_log_path"), 0, offsetof(imgzip_http_server_conf_t,access_log_path), imgzip_conf_set_str_val, 0, 0 }, //
		{ ngx_string("mysql_conf"), imgzip_conf_create_mysql_conf, offsetof(imgzip_http_server_conf_t,mysql_conf), imgzip_conf_set_struct_value, mysql_module_conf,
				offsetof(imgzip_mysql_server_conf_t,next) }, //
		{ ngx_string("memc_conf"), imgzip_conf_create_memc_conf, offsetof(imgzip_http_server_conf_t,memc_conf), imgzip_conf_set_struct_value, memc_module_conf,
				offsetof(imgzip_memc_conf_t,next) }, //
		{ ngx_string("img_conf"), imgzip_conf_create_img_conf, offsetof(imgzip_http_server_conf_t,img_conf), imgzip_conf_set_struct_value, img_module_conf, 0 }, //
		{ ngx_null_string, 0, 0, 0, 0, 0 }

};
/*ngx_int_t imgzip_conf_load(ngx_str_t *conf_file) {
	ngx_conf_t cf;
	char *rv;
	cf.pool = ngx_create_pool(1024);
	cf.args = ngx_array_create(cf.pool, 10, sizeof(ngx_str_t));
	cf.offset=0;
	imgzip_server_conf.memc_conf = NULL;
	imgzip_server_conf.mysql_conf = NULL;
	rv = conf_parse(conf_file, &cf, server_module_conf, &imgzip_server_conf);
	if (rv == NULL) {
		return IMGZIP_OK;
	}
	return IMGZIP_ERR;
}*/

ngx_int_t imgzip_conf_load(u_char *conf_path) {
	ngx_pool_t *pool;
	ngx_conf_t cf;
	ngx_array_t *elements;
	char *rv;
	pool = ngx_create_pool(1024*10);
	elements = ngx_array_create(pool, 512, sizeof(ngx_hash_key_t));
//	checkip = ngx_array_create(pool, 128, sizeof(ngx_str_t));

	ngx_str_t types = ngx_string(".types");
	ngx_str_t conf = ngx_string(".conf");
	ngx_str_t ip	= ngx_string(".ip");
	ngx_str_t full_conf, full_types, full_ip;
	size_t len = strlen((char*)conf_path);
	full_conf.len = len + conf.len;
	full_types.len = len + types.len;
	full_ip.len = len + ip.len;
	u_char full_conf_path[full_conf.len];
	u_char full_types_path[full_types.len];
	u_char full_ip_path[full_ip.len];
	full_conf.data = full_conf_path;
	full_types.data = full_types_path;
	full_ip.data = full_ip_path;
	strcpy((char*)full_conf_path,(char*)conf_path);
	strcpy((char*)full_conf_path + len,(char*)conf.data);

	strcpy((char*)full_types_path,(char*)conf_path);
	strcpy((char*)full_types_path + len,(char*)types.data);

	strcpy((char*)full_ip_path, (char*)conf_path);
	strcpy((char*)full_ip_path + len, (char*)ip.data);
	cf.pool = ngx_create_pool(1024);
	cf.args = ngx_array_create(cf.pool, 128, sizeof(ngx_str_t));
	cf.offset = 0;
	imgzip_server_conf.memc_conf = NULL;
	imgzip_server_conf.mysql_conf = NULL;

	rv = conf_parse(&full_conf, &cf, server_module_conf, &imgzip_server_conf);
	if (rv != NULL) {
		return IMGZIP_ERR;
	}

	/*rv = ip_parse(&full_ip, checkip);
	if(rv != NULL)
	{
		return IMGZIP_ERR;
	}*/

	cf.offset = 0;
	rv = mime_parse(&full_types, &cf, elements);
	if (rv != NULL )
	{
		return IMGZIP_ERR;
	}

	if(ngx_image_hash_init(elements,pool) != IMGZIP_OK)
	{
		  ngx_destroy_pool(pool);
			return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}

static void* imgzip_conf_create_mysql_conf(ngx_conf_t *cf) {
	imgzip_mysql_server_conf_t *conf;
	conf = ngx_palloc(cf->pool, sizeof(imgzip_mysql_server_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}
	conf->next = 0;
	return conf;
}
static void* imgzip_conf_create_memc_conf(ngx_conf_t *cf) {
	imgzip_memc_conf_t *conf;
	conf = ngx_palloc(cf->pool, sizeof(imgzip_memc_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}
	conf->next = 0;
	return conf;
}

static void* imgzip_conf_create_img_conf(ngx_conf_t *cf) {
	imgzip_img_conf_t *conf;
	conf = ngx_palloc(cf->pool, sizeof(imgzip_img_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}
	return conf;
}

static char* imgzip_conf_set_struct_value(ngx_conf_t *cf, imgzip_conf_module_t *mod, void *conf, void *sub_conf) {
	void **field;
	void **next;
	char *p = conf;
	char *sub_p = sub_conf;
	field = (void **) (p + mod->offset);
	if (mod->next) {
		next = (void **) (sub_p + mod->next);
		*next = *field;
	}
	*field = sub_conf;
	return NULL;
}
static char* imgzip_conf_set_int_val(ngx_conf_t *cf, imgzip_conf_module_t *mod, void *conf, void *sub_conf) {
	char *p = conf;

	ngx_int_t *np;
	ngx_str_t *value;

	np = (ngx_int_t *) (p + mod->offset);

	value = cf->args->elts;
	*np = ngx_atoi(value[1].data, value[1].len);
	if (*np == IMGZIP_ERR) {
		return "invalid number";
	}

	return NULL;
}

static char* imgzip_conf_set_str_val(ngx_conf_t *cf, imgzip_conf_module_t *mod, void *conf, void *sub_conf) {
	char *p = conf;

	ngx_str_t *field, *value;

	field = (ngx_str_t *) (p + mod->offset);

//	if (field->data) {
//		return "is duplicate";
//	}

	value = cf->args->elts;

	*field = value[1];

	return NULL;
}

static char *mime_parse(ngx_str_t *filename, ngx_conf_t *cf, ngx_array_t *elements)
{
	ngx_int_t fd,index;
	ngx_buf_t buf;
	ngx_int_t rc;
	ngx_str_t *value = (ngx_str_t*)malloc(128*sizeof(ngx_str_t));
	index = 0;
	enum {
		parse_file = 0, parse_block, parse_param
	} type;

	if (filename) {
		char tmp_file_name[filename->len + 1];
		strncpy(tmp_file_name,(char*)filename->data,filename->len);
		tmp_file_name[filename->len]='\0';
		fd = open(tmp_file_name, O_RDONLY, 0);
		if (fd == -1) {
			stderr_print( "conf file open \"%s\" failed", tmp_file_name);
			return NGX_CONF_ERROR;
		}
	if (fstat(fd, &cf->file_info) == -1) {
		return NGX_CONF_ERROR;
	}
	cf->fd = fd;
	cf->buf = &buf;

	buf.start = ngx_alloc(NGX_CONF_BUFFER);
	if(buf.start == NULL)
	{
		return NGX_CONF_ERROR;
	}
	buf.pos = buf.start;
	buf.last = buf.start;
	buf.end = buf.last + NGX_CONF_BUFFER;
	buf.temporary = 1;
	type = parse_file;
	}
	else if(fd != -1)
	{
		type = parse_block;
	}
	else
	{
		type = parse_param;
	}
	for(;;)
	{
		rc = ngx_conf_read_token(cf);
		if(rc == IMGZIP_ERR)
		{
			goto done;
		}

		if (rc == NGX_CONF_BLOCK_DONE) {

				if (type != parse_block) {
					stderr_print("unexpected \"}\"");
					goto failed;
				}

				goto done;
		}

			if (rc == NGX_CONF_FILE_DONE) {

				if (type == parse_block) {
					stderr_print("unexpected end of file, expecting \"}\"");
					goto failed;
			    }

				goto done;
			}

				if (rc == NGX_CONF_BLOCK_START) {

					if (type == parse_param) {
						stderr_print("block directives are not supported in -g option");
						goto failed;
					}
				}

				rc = ngx_http_image_create_hashtable(cf,elements,value,&index);

				if (rc == IMGZIP_ERR) {
					goto failed;
				}
	}
			failed:

			rc = IMGZIP_ERR;

			done:

			if (filename) {
				if (cf->buf->start) {
					ngx_free(cf->buf->start);
				}

				if (close(fd) == IMGZIP_ERR) {
					stderr_print("close file %s failed", filename->data);
					return NGX_CONF_ERROR;
				}
			}

			if (rc == IMGZIP_ERR) {
				return NGX_CONF_ERROR;
			}
	return NULL;
}

static char *conf_parse(ngx_str_t *filename, ngx_conf_t *cf, imgzip_conf_module_t *conf_module, void *conf) {
	int fd;
	ngx_int_t rc;
	ngx_buf_t buf;
	enum {
		parse_file = 0, parse_block, parse_param
	} type;

	/* open configuration file */
	if (filename) {
		char tmp_file_name[filename->len + 1];//
		strncpy(tmp_file_name,(char*)filename->data,filename->len);
		tmp_file_name[filename->len]='\0';
		fd = open(tmp_file_name, O_RDONLY, 0);
		if (fd == -1) {
			stderr_print( "conf file open \"%s\" failed", tmp_file_name);
			return NGX_CONF_ERROR;
		}

		if (fstat(fd, &cf->file_info) == -1) {
			stderr_print( "fstat \"%s\" failed", filename->data);
		}

		cf->fd = fd;
		cf->buf = &buf;

		buf.start = ngx_alloc(NGX_CONF_BUFFER);
		if (buf.start == NULL) {
			goto failed;
		}

		buf.pos = buf.start;
		buf.last = buf.start;
		buf.end = buf.last + NGX_CONF_BUFFER;
		buf.temporary = 1;

		type = parse_file;
	} else if (cf->fd != IMGZIP_ERR) {

		type = parse_block;

	} else {
		type = parse_param;
	}
	for (;;) {
		rc = ngx_conf_read_token(cf);

		/*
		 * ngx_conf_read_token() may return
		 *
		 *    IMGZIP_ERR             there is error
		 *    IMGZIP_OK                the token terminated by ";" was found
		 *    NGX_CONF_BLOCK_START  the token terminated by "{" was found
		 *    NGX_CONF_BLOCK_DONE   the "}" was found
		 *    NGX_CONF_FILE_DONE    the configuration file is done
		 */

		if (rc == IMGZIP_ERR) {
			goto done;
		}

		if (rc == NGX_CONF_BLOCK_DONE) {

			if (type != parse_block) {
				stderr_print("unexpected \"}\"");
				goto failed;
			}

			goto done;
		}

		if (rc == NGX_CONF_FILE_DONE) {

			if (type == parse_block) {
				stderr_print("unexpected end of file, expecting \"}\"");
				goto failed;
			}

			goto done;
		}

		if (rc == NGX_CONF_BLOCK_START) {

			if (type == parse_param) {
				stderr_print("block directives are not supported in -g option");
				goto failed;
			}
		}

		rc = ngx_conf_handler(cf, rc, conf_module, conf);

		if (rc == IMGZIP_ERR) {
			goto failed;
		}
	}

	failed:

	rc = IMGZIP_ERR;

	done:

	if (filename) {
		if (cf->buf->start) {
			ngx_free(cf->buf->start);
		}

		if (close(fd) == IMGZIP_ERR) {
			stderr_print("close file %s failed", filename->data);
			return NGX_CONF_ERROR;
		}

	}

	if (rc == IMGZIP_ERR) {
		return NGX_CONF_ERROR;
	}

	return NULL;
}

static ngx_int_t ngx_conf_handler(ngx_conf_t *cf, ngx_int_t last, imgzip_conf_module_t *conf_module, void *conf) {
	char *rv;
	ngx_uint_t multi;
	ngx_str_t *name;
	void *field;
	name = cf->args->elts;

	multi = 0;

	for ( /* void */; conf_module->name.len; conf_module++) {

		if (name->len != conf_module->name.len) {
			continue;
		}

		if (strncmp((char*) name->data, (char*) conf_module->name.data, name->len) != 0) {
			continue;
		}
		if (conf_module->sub_conf && last != NGX_CONF_BLOCK_START) {
			return IMGZIP_ERR;
		}
		if (conf_module->create) {
			field = conf_module->create(cf);
			rv = conf_parse(NULL, cf, conf_module->sub_conf, field);
			if (rv != NULL) {
				return IMGZIP_ERR;
			}
			rv = conf_module->set(cf, conf_module, conf, field);
		} else {
			rv = conf_module->set(cf, conf_module, conf, NULL);
		}
		if (rv == NULL) {
			return IMGZIP_OK;
		}

		if (rv == NGX_CONF_ERROR) {
			return IMGZIP_ERR;
		}

		stderr_print("\"%s\" directive %s", name->data, rv);

		return IMGZIP_ERR;
	}
	stderr_print("\"%s\" not find!", name->data);
	return IMGZIP_ERR;
}
static ngx_int_t ngx_conf_read_token(ngx_conf_t *cf) {
	u_char *start, ch, *src, *dst;
	off_t file_size;
	size_t len;
	ssize_t n, size;
	ngx_uint_t found, need_space, last_space, sharp_comment;
	ngx_uint_t s_quoted, d_quoted;
	ngx_str_t *word;
	ngx_buf_t *b;

	found = 0;
	need_space = 0;
	last_space = 1;
	sharp_comment = 0;
	s_quoted = 0;
	d_quoted = 0;

	cf->args->nelts = 0;
	b = cf->buf;
	start = b->pos;

	file_size = cf->file_info.st_size;

	for (;;) {

		if (b->pos >= b->last) {

			if (cf->offset >= file_size) {

				if (cf->args->nelts > 0) {
					stderr_print("unexpected end of file, expecting \";\" or \"}\"");
					return IMGZIP_ERR;
				}

				return NGX_CONF_FILE_DONE;
			}

			len = b->pos - start;

			if (len == NGX_CONF_BUFFER) {

				if (d_quoted) {
					ch = '"';

				} else if (s_quoted) {
					ch = '\'';

				} else {
					stderr_print("too long parameter \"%*s...\" started", 10, start);
					return IMGZIP_ERR;
				}

				stderr_print("too long parameter, probably missing terminating \"%c\" character", ch);
				return IMGZIP_ERR;
			}

			if (len) {
				memmove(b->start, start, len);
			}

			size = (ssize_t) (file_size - cf->offset);

			if (size > b->end - (b->start + len)) {
				size = b->end - (b->start + len);
			}

			n = ngx_read_file(cf->fd, b->start + len, size, cf->offset);
			cf->offset += n;

			if (n == IMGZIP_ERR) {
				return IMGZIP_ERR;
			}

			if (n != size) {
				stderr_print(" returned only %z bytes instead of %z", n, size);
				return IMGZIP_ERR;
			}

			b->pos = b->start + len;
			b->last = b->pos + n;
			start = b->start;
		}

		ch = *b->pos++;

		if (ch == LF) {
			if (sharp_comment) {
				sharp_comment = 0;
			}
		}

		if (sharp_comment) {
			continue;
		}

		if (need_space) {
			if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
				last_space = 1;
				need_space = 0;
				continue;
			}

			if (ch == ';') {
				return IMGZIP_OK;
			}

			if (ch == '{') {
				return NGX_CONF_BLOCK_START;
			}

			if (ch == ')') {
				last_space = 1;
				need_space = 0;

			} else {
				stderr_print("unexpected \"%c\"", ch);
				return IMGZIP_ERR;
			}
		}

		if (last_space) {
			if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
				continue;
			}

			start = b->pos - 1;

			switch (ch) {

			case ';':
			case '{':
				if (cf->args->nelts == 0) {
					stderr_print("unexpected \"%c\"", ch);
					return IMGZIP_ERR;
				}

				if (ch == '{') {
					return NGX_CONF_BLOCK_START;
				}

				return IMGZIP_OK;

			case '}':
				if (cf->args->nelts != 0) {
					stderr_print("unexpected \"}\"");
					return IMGZIP_ERR;
				}

				return NGX_CONF_BLOCK_DONE;

			case '#':
				sharp_comment = 1;
				continue;

			case '"':
				start++;
				d_quoted = 1;
				last_space = 0;
				continue;

			case '\'':
				start++;
				s_quoted = 1;
				last_space = 0;
				continue;

			default:
				last_space = 0;
			}

		} else {

			if (d_quoted) {
				if (ch == '"') {
					d_quoted = 0;
					need_space = 1;
					found = 1;
				}

			} else if (s_quoted) {
				if (ch == '\'') {
					s_quoted = 0;
					need_space = 1;
					found = 1;
				}

			} else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF || ch == ';' || ch == '{') {
				last_space = 1;
				found = 1;
			}

			if (found) {
				word = ngx_array_push(cf->args);
				if (word == NULL) {
					return IMGZIP_ERR;
				}

				word->data = ngx_pnalloc(cf->pool, b->pos - start + 1);
				if (word->data == NULL) {
					return IMGZIP_ERR;
				}

				for (dst = word->data, src = start, len = 0; src < b->pos - 1; len++) {
					*dst++ = *src++;
				}
				*dst = '\0';
				word->len = len;

				if (ch == ';') {
					return IMGZIP_OK;
				}

				if (ch == '{') {
					return NGX_CONF_BLOCK_START;
				}

				found = 0;
			}
		}
	}
}

static ssize_t ngx_read_file(int fd, u_char *buf, size_t size, off_t offset) {
	ssize_t n;

	if (lseek(fd, offset, SEEK_SET) == -1) {
		stderr_print("lseek()  conf file failed");
		return IMGZIP_ERR;
	}

	n = read(fd, buf, size);

	if (n == -1) {
		stderr_print("read() conf file failed");
		return IMGZIP_ERR;
	}

	return n;
}

static ngx_int_t ngx_http_image_create_hashtable(ngx_conf_t *cf, ngx_array_t *elts, ngx_str_t *value, ngx_int_t *index)
{
	ngx_int_t i;
	ngx_hash_key_t *hashkey;
	ngx_str_t *p;
	p = cf->args->elts;
	value[*index].data = (u_char*)malloc(64*sizeof(u_char));
	strcpy((char*)(value[*index].data),(char*)(p[0].data));
	value[*index].len = p[0].len;

	for(i = 1;i < cf->args->nelts ;i++)
	{
		hashkey = (ngx_hash_key_t*)ngx_array_push(elts);
		hashkey->value = (void*)&value[*index];
		hashkey->key = p[i];
		hashkey->key_hash = ngx_hash_key_lc(hashkey->key.data,hashkey->key.len);
	}
	(*index)++;

	return IMGZIP_OK;
}

static ngx_int_t ngx_image_hash_init(ngx_array_t* elements,ngx_pool_t *pool)
{
	ngx_hash_init_t hashinit;
	hashtable = (ngx_hash_t*)ngx_pcalloc(pool,sizeof(ngx_hash_t));
	hashinit.hash = hashtable;
	hashinit.bucket_size = 64;
	hashinit.max_size = 1024*10;
	hashinit.pool = pool;
	hashinit.temp_pool = NULL;
	hashinit.name = "imgzip.type";
	hashinit.key = &ngx_hash_key_lc;

	if(ngx_hash_init(&hashinit,(ngx_hash_key_t*)elements->elts,elements->nelts) == IMGZIP_ERR)
	{
		return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}

/*static char*	ip_parse(ngx_str_t *filename, ngx_array_t *checkip)
{
	FILE *fp;
	u_char buf[64];
	ngx_str_t *str;
	if((fp = fopen((char*)filename->data, "r ")) != NULL)
	{
		while(fgets((char*)buf, sizeof(u_char)*64, fp))
		{
			str = ngx_array_push(checkip);
			str->len = strlen((char*)buf);
			str->data = (u_char*)malloc(str->len);
			strcpy((char*)str->data, (char*)buf);
			str->data[str->len - 1] = '\0';
		}
	}
	else
	{
		return NGX_CONF_ERROR;
	}

	return NULL;
}*/
