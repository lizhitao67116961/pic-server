#ifndef NGX_HTTP_DRIZZLE_MODULE_H
#define NGX_HTTP_DRIZZLE_MODULE_H


#include "../imgzip_config.h"
#include "../imgzip_core.h"
#include <libdrizzle-5.1/drizzle_client.h>


typedef struct {
    u_char                             *name;
    uint32_t                            key;
} ngx_drizzle_http_method_t;


/*typedef struct {
     drizzle database name
    ngx_str_t            										 *dbname;

     SQL query to be executed
    ngx_uint_t                           methods_set;
    ngx_array_t                         *queries;

     for quoting
    ngx_array_t                         *vars_to_quote;
                 of ngx_http_drizzle_var_to_quote_t

    ngx_array_t                         *user_types;
                 of ngx_http_drizzle_var_type_t

    size_t                               buf_size;
} ngx_http_drizzle_conf_t;*/


typedef enum {
    state_db_connect,
    state_db_send_query,
    state_db_recv_cols,
    state_db_recv_rows,
    state_db_idle

} ngx_http_drizzle_state_t;

#endif /* NGX_HTTP_DRIZZLE_MODULE_H */

