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

#include "ngx_module.h"
#include <ngx_http_variables.h>

#include <sys/times.h>

#ifndef _debug_mechanics
#define _debug_mechanics 0
#endif
#ifndef _debug_readconf
#define _debug_readconf 1
#endif

#define PROCESSING_THRESHOLD 1

/*
 * Module's registered function/handlers.
 */
static ngx_int_t
ngx_http_ipfilter_access_handler(ngx_http_request_t* r);

static ngx_int_t
ngx_http_ipfilter_pre(ngx_conf_t* cf);

static ngx_int_t
ngx_http_ipfilter_init(ngx_conf_t* cf);

static char*
ngx_http_ipfilter_du_loc_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

static char*
ngx_http_ipfilter_db_loc_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

static void*
ngx_http_ipfilter_create_loc_conf(ngx_conf_t* cf);

static char*
ngx_http_ipfilter_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);

static void*
ngx_http_ipfilter_create_main_conf(ngx_conf_t* cf);

static char*
ngx_http_ipfilter_enable_loc_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

static ngx_int_t
ngx_http_ipfilter_get_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

/* module context */
#define IPFILTER_VAR_RESPONSE   "ipfilter"
#define IPFILTER_X_HEADER       "x-ipfilter"

/* nginx-style names */
#define TOP_DBFILE_N            "ipfilter_db"
#define TOP_DENIED_URL_N        "ipfilter_denied_url"
#define TOP_ENABLED_FLAG_N      "ipfilter_enabled"

/* command handled by the module */
static ngx_command_t ngx_http_ipfilter_commands[] = {
  /* ipfilter_db */
  { ngx_string(TOP_DBFILE_N),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_1MORE,
    ngx_http_ipfilter_db_loc_conf,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL},

  /* denied_url - nginx style */
  { ngx_string(TOP_DENIED_URL_N),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_1MORE,
    ngx_http_ipfilter_du_loc_conf,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL},

  /* enable flag - nginx style */
  { ngx_string(TOP_ENABLED_FLAG_N),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
    ngx_http_ipfilter_enable_loc_conf,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL},

  ngx_null_command
};

static ngx_http_module_t ngx_http_ipfilter_module_ctx = {
  ngx_http_ipfilter_pre, /* preconfiguration */
  ngx_http_ipfilter_init, /* postconfiguration */
  ngx_http_ipfilter_create_main_conf, /* create main configuration */
  NULL, /* init main configuration */
  NULL, /* create server configuration */
  NULL, /* merge server configuration */
  ngx_http_ipfilter_create_loc_conf, /* create location configuration */
  ngx_http_ipfilter_merge_loc_conf /* merge location configuration */
};

ngx_module_t ngx_http_ipfilter_module = {
  NGX_MODULE_V1,
  &ngx_http_ipfilter_module_ctx, /* module context */
  ngx_http_ipfilter_commands, /* module directives */
  NGX_HTTP_MODULE, /* module type */
  NULL, /* init master */
  NULL, /* init module */
  NULL, /* init process */
  NULL, /* init thread */
  NULL, /* exit thread */
  NULL, /* exit process */
  NULL, /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_ipfilter_pre(ngx_conf_t* cf)
{
  ngx_http_variable_t * var;
  ngx_str_t * name;

  /* register variable for the response */
  name = ngx_pcalloc(cf->pool, sizeof (ngx_str_t));
  if (!name)
    return (NGX_ERROR);
  name->len = sizeof(IPFILTER_VAR_RESPONSE) - 1;
  name->data = ngx_pcalloc(cf->pool, name->len);
  if (!name->data)
    return (NGX_ERROR);
  memcpy(name->data, IPFILTER_VAR_RESPONSE, name->len);

  var = ngx_http_add_variable(cf, name, 0);
  if (!var)
    return (NGX_ERROR);
  var->get_handler = ngx_http_ipfilter_get_variable;
  return (NGX_OK);
}

static ngx_int_t
ngx_http_ipfilter_init(ngx_conf_t* cf)
{
  ngx_http_handler_pt* h;
  ngx_http_core_main_conf_t* cmcf;
  ngx_http_ipfilter_main_conf_t* main_cf;
  ngx_http_ipfilter_loc_conf_t** loc_cf;
  unsigned int i;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  main_cf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ipfilter_module);
  if (cmcf == NULL || main_cf == NULL)
    return (NGX_ERROR);

  /* Register for rewrite phase */
  h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
  if (h == NULL)
    return (NGX_ERROR);

  *h = ngx_http_ipfilter_access_handler;
  /* Go with each locations registered in the srv_conf. */
  loc_cf = main_cf->locations->elts;

  for (i = 0; i < main_cf->locations->nelts; ++i)
  {
    if (loc_cf[i]->enabled)
    {
      if (!loc_cf[i]->db_file || loc_cf[i]->db_file->len <= 0)
      {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           IPFILTER_TAG " Missing directive '" TOP_DBFILE_N "', abort");
        return (NGX_ERROR);
      }
    }
  }

  for (i = 0; i < main_cf->locations->nelts; ++i)
  {
    if (!loc_cf[i]->enabled)
      continue;

    /* mount db in read-only mode */
    IPF_DB* db = ipf_mount_db((char*) loc_cf[i]->db_file->data, 0);
    if (!db)
    {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         IPFILTER_TAG " Failed to mount database '%V', abort",
                         loc_cf[i]->db_file);
      return (NGX_ERROR);
    }
    loc_cf[i]->db_instance = db;
  }

  return (NGX_OK);
}

/*
 * Enable the location.
 */
static char*
ngx_http_ipfilter_enable_loc_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_http_ipfilter_loc_conf_t * alcf = conf, **bar;
  ngx_http_ipfilter_main_conf_t* main_cf;

  if (!alcf || !cf)
    return (NGX_CONF_ERROR);
  main_cf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ipfilter_module);
  if (!alcf->pushed)
  {
    bar = ngx_array_push(main_cf->locations);
    if (!bar)
      return (NGX_CONF_ERROR);
    *bar = alcf;
    alcf->pushed = 1;
  }

  alcf->enabled = 1;
  return (NGX_CONF_OK);
}

/*
 * Configure the denied url for the location and set flag redirect.
 */
static char*
ngx_http_ipfilter_du_loc_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_http_ipfilter_loc_conf_t * alcf = conf, **bar;
  ngx_http_ipfilter_main_conf_t* main_cf;
  ngx_str_t* value;

  if (!alcf || !cf)
    return (NGX_CONF_ERROR);

  main_cf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ipfilter_module);
  if (!alcf->pushed)
  {
    bar = ngx_array_push(main_cf->locations);
    if (!bar)
      return (NGX_CONF_ERROR);
    *bar = alcf;
    alcf->pushed = 1;
  }

  value = cf->args->elts;
  NX_CONF_DEBUG(_debug_readconf, NGX_LOG_NOTICE, cf, 0,
                IPFILTER_TAG " DU: %V %V", &(value[0]), &(value[1]));

  /* store denied URL for location */
  if (!ngx_strcmp(value[0].data, TOP_DENIED_URL_N) && value[1].len)
  {
    alcf->denied_url = ngx_pcalloc(cf->pool, sizeof (ngx_str_t));
    if (!alcf->denied_url)
      return (NGX_CONF_ERROR);
    alcf->denied_url->data = ngx_pcalloc(cf->pool, value[1].len + 1);
    if (!alcf->denied_url->data)
      return (NGX_CONF_ERROR);
    memcpy(alcf->denied_url->data, value[1].data, value[1].len);
    alcf->denied_url->len = value[1].len;
    alcf->redirect = 1;
    return (NGX_CONF_OK);
  }

  return NGX_CONF_ERROR;
}

/*
 * Configure the database to use for the location.
 */
static char*
ngx_http_ipfilter_db_loc_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_http_ipfilter_loc_conf_t * alcf = conf, **bar;
  ngx_http_ipfilter_main_conf_t* main_cf;
  ngx_str_t* value;

  if (!alcf || !cf)
    return (NGX_CONF_ERROR);

  main_cf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ipfilter_module);
  if (!alcf->pushed)
  {
    bar = ngx_array_push(main_cf->locations);
    if (!bar)
      return (NGX_CONF_ERROR);
    *bar = alcf;
    alcf->pushed = 1;
  }

  value = cf->args->elts;
  NX_CONF_DEBUG(_debug_readconf, NGX_LOG_NOTICE, cf, 0,
                IPFILTER_TAG " DB: %V %V", &(value[0]), &(value[1]));

  /* store db path for location */
  if (!ngx_strcmp(value[0].data, TOP_DBFILE_N) && value[1].len)
  {
    alcf->db_file = ngx_pcalloc(cf->pool, sizeof (ngx_str_t));
    if (!alcf->db_file)
      return (NGX_CONF_ERROR);
    alcf->db_file->data = ngx_pcalloc(cf->pool, value[1].len + 1);
    if (!alcf->db_file->data)
      return (NGX_CONF_ERROR);
    memcpy(alcf->db_file->data, value[1].data, value[1].len);
    alcf->db_file->len = value[1].len;
    return (NGX_CONF_OK);
  }

  return NGX_CONF_ERROR;
}

static void*
ngx_http_ipfilter_create_loc_conf(ngx_conf_t* cf)
{
  ngx_http_ipfilter_loc_conf_t* conf;

  conf = ngx_pcalloc(cf->pool, sizeof (ngx_http_ipfilter_loc_conf_t));
  if (conf == NULL)
    return NULL;

  return (conf);
}

static char*
ngx_http_ipfilter_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child)
{
  ngx_http_ipfilter_loc_conf_t* prev = parent;
  ngx_http_ipfilter_loc_conf_t* conf = child;

  if (conf->pushed == 0)
    conf->pushed = prev->pushed;
  if (conf->enabled == 0)
    conf->enabled = prev->enabled;
  if (conf->redirect == 0)
    conf->redirect = prev->redirect;
  if (conf->denied_url == NULL)
    conf->denied_url = prev->denied_url;
  if (conf->db_file == NULL)
    conf->db_file = prev->db_file;
  if (conf->db_instance == NULL)
    conf->db_instance = prev->db_instance;

  return NGX_CONF_OK;
}

#define DEFAULT_MAX_LOC_T 10

static void*
ngx_http_ipfilter_create_main_conf(ngx_conf_t* cf)
{
  ngx_http_ipfilter_main_conf_t* mc;

  mc = ngx_pcalloc(cf->pool, sizeof (ngx_http_ipfilter_main_conf_t));
  if (!mc)
    return (NGX_CONF_ERROR);
  mc->locations = ngx_array_create(cf->pool, DEFAULT_MAX_LOC_T, sizeof (ngx_http_ipfilter_loc_conf_t*));
  if (!mc->locations)
    return (NGX_CONF_ERROR);
  return (mc);
}

static ngx_int_t
ngx_http_ipfilter_get_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
  ngx_http_request_ctx_t* ctx;
  ngx_http_ipfilter_loc_conf_t* cf;

  ctx = ngx_http_get_module_ctx(r, ngx_http_ipfilter_module);
  cf = ngx_http_get_module_loc_conf(r, ngx_http_ipfilter_module);

  /* returns 1=allow in discarded context */
  if (r->internal || !cf || !cf->enabled || !ctx)
  {
    NX_DEBUG(_debug_mechanics, NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
             IPFILTER_TAG " GET VARIABLE(%V)|INTERNAL:%d",
             &(r->uri), r->internal);
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->len = 1;
    v->data = ngx_pcalloc(r->pool, 1);
    if (!v->data)
      return (NGX_ERROR);
    *(v->data) = '1'; /* allow */
    return (NGX_OK);
  }

  v->not_found = 0;
  v->valid = 1;
  v->no_cacheable = 0;
  v->len = 1;
  v->data = ngx_pcalloc(r->pool, 1);
  switch (ctx->response)
  {
  case ipf_not_found:
    *(v->data) = '0';
    break;
  case ipf_allow:
    *(v->data) = '1';
    break;
  case ipf_deny:
    *(v->data) = '2';
    break;
  default:
    *(v->data) = '3';
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  IPFILTER_TAG " DATABASE QUERY FAILED (%d).", errno);
  }

  return (NGX_OK);
}

/*
 * This is the function called by nginx :
 * - Check if the job is done and we're called again
 * - Set up the context for the request
 * - check if the request should be denied
 */
static ngx_int_t
ngx_http_ipfilter_access_handler(ngx_http_request_t* r)
{
  ngx_http_request_ctx_t* ctx;
  ngx_int_t rc;
  ngx_http_ipfilter_loc_conf_t* cf;
  struct tms tmsstart, tmsend;
  clock_t start, end;

  ctx = ngx_http_get_module_ctx(r, ngx_http_ipfilter_module);
  cf = ngx_http_get_module_loc_conf(r, ngx_http_ipfilter_module);

  /* job has been done */
  if (ctx && ctx->over)
    return (NGX_DECLINED);

  if (!cf)
    return (NGX_ERROR);

  /* the module is not enabled here */
  if (!cf->enabled)
    return (NGX_DECLINED);

  /* don't process internal requests. */
  if (r->internal)
  {
    NX_DEBUG(_debug_mechanics, NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
             IPFILTER_TAG " DON'T PROCESS (%V)|ADDR:%V|INTERNAL:%d",
             &(r->uri), &(r->connection->addr_text), r->internal);
    return (NGX_DECLINED);
  }

  NX_DEBUG(_debug_mechanics, NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
           IPFILTER_TAG " PROCESSING (%V)|ADDR:%V|INTERNAL:%d",
           &(r->uri), &(r->connection->addr_text), r->internal);

  if (!ctx)
  {
    ctx = ngx_pcalloc(r->pool, sizeof (ngx_http_request_ctx_t));
    if (ctx == NULL)
      return NGX_ERROR;
    ngx_http_set_ctx(r, ctx, ngx_http_ipfilter_module);
  }

  if ((start = times(&tmsstart)) == (clock_t) - 1)
    NX_DEBUG(_debug_mechanics, NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
             IPFILTER_TAG " Failed to get time");

  ngx_http_ipfilter_data_parse(ctx, r, cf);
  cf->request_processed++;

  if ((end = times(&tmsend)) == (clock_t) - 1)
    NX_DEBUG(_debug_mechanics, NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
             IPFILTER_TAG " Failed to get time");

  if (end - start > PROCESSING_THRESHOLD)
  {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  IPFILTER_TAG " PROCESSING TOOK TOO LONG : ELAPSED=%l",
                  (end - start));
  }

  /* job done */
  ctx->over = 1;

  if (cf->redirect)
  {
    switch (ctx->response)
    {
    case ipf_allow:
      NX_DEBUG(_debug_mechanics, NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               IPFILTER_TAG " DECLINED");
      return NGX_DECLINED;
    case ipf_error:
      ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                    IPFILTER_TAG " DATABASE QUERY FAILED (%d).", errno);
      break;
    default:
      break;
    }
    cf->request_blocked++;
    NX_DEBUG(_debug_mechanics, NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
             IPFILTER_TAG " BLOCKED (%l)", cf->request_blocked);
    rc = ngx_http_output_forbidden_page(ctx, r, cf);
    /* redirect: return (NGX_HTTP_OK) */
    return rc;
  }

  return NGX_DECLINED;
}
