/*
 * des_help.h
 *
 *  Created on: 2013-3-18
 *      Author: lizhitao
 */

#ifndef DES_HELP_H_
#define DES_HELP_H_
#include "../imgzip_config.h"
#include "../imgzip_core.h"
ngx_int_t img_biz_url_decode(ngx_str_t *key, ngx_str_t *img_id);
ngx_int_t img_url_decode(u_char *img_id, int img_id_len, u_char *url, int url_len, u_char *img_info);
#endif /* DES_HELP_H_ */
