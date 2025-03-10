/*
 *      Copyright (C) 2023 Jean-Luc Barriere
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef NGX_MODULE_IPFILTER_H
#define NGX_MODULE_IPFILTER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>

#include "db.h"

#define IPFILTER_TAG "[IPF]"

extern ngx_module_t ngx_http_ipfilter_module;

/* The LOCATION configuration structure of the module */
typedef struct
{
  ngx_flag_t    pushed;             /* conf is registered */
  ngx_flag_t    enabled;            /* conf is enabled */
  ngx_flag_t    redirect;           /* redirect to denied url */
  ngx_str_t*    denied_url;
  ngx_str_t*    db_file;            /* path of database to use */

  IPF_DB*       db_instance;        /* handle of db instance */
  size_t        request_processed;  /* counter */
  size_t        request_blocked;    /* counter */
} ngx_http_ipfilter_loc_conf_t;

/* The MAIN configuration structure of the module */
typedef struct
{
  /* registered locations (ngx_http_ipfilter_loc_conf_t) */
  ngx_array_t* locations;
} ngx_http_ipfilter_main_conf_t;

typedef struct
{
  ngx_flag_t over;
  ngx_int_t response;
} ngx_http_request_ctx_t;

#define NX_CONF_DEBUG(FEATURE, DEF, CONF, ERR, ...)   \
  do {                                                \
    if (FEATURE)                                      \
      ngx_conf_log_error(DEF, CONF, ERR, __VA_ARGS__);\
  } while (0)

#define NX_DEBUG(FEATURE, DEF, LOG, ERR, ...)         \
  do {                                                \
    if (FEATURE)                                      \
      ngx_log_debug(DEF, LOG, ERR, __VA_ARGS__);      \
  } while (0)

void
ngx_http_ipfilter_data_parse(ngx_http_request_ctx_t* ctx,
        ngx_http_request_t* r, ngx_http_ipfilter_loc_conf_t* cf);

ngx_int_t
ngx_http_output_forbidden_page(ngx_http_request_ctx_t* ctx,
        ngx_http_request_t* r, ngx_http_ipfilter_loc_conf_t* cf);

#endif /* NGX_MODULE_IPFILTER_H */

