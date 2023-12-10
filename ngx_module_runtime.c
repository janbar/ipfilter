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

void
ngx_http_ipfilter_data_parse(ngx_http_request_ctx_t* ctx,
                             ngx_http_request_t* r,
                             ngx_http_ipfilter_loc_conf_t* cf)
{
  if (!cf || !ctx)
  {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  IPFILTER_TAG " unable to parse data.");
    return;
  }

  /* AF_INET */
  if (r->connection->sockaddr->sa_family == AF_INET)
  {
    cidr_address cidr;
    char buf[16];
    memcpy(buf, r->connection->addr_text.data, r->connection->addr_text.len);
    buf[r->connection->addr_text.len] = '\0';
    if (create_cidr_address_2(&cidr, buf, 32) != 0)
    {
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    IPFILTER_TAG " Unable to parse address '%V'.",
                    r->connection->addr_text);
      ctx->block = 1;
      return;
    }
    switch (find_record(cf->db_instance, &cidr))
    {
    case db_not_found:
      ctx->block = (cf->rule_deny ? 0 : 1);
      break;
    case db_matched:
      ctx->block = cf->rule_deny;
      break;
    case db_error:
      ctx->block = 1;
      ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                    IPFILTER_TAG " Database query failed (%d)(%V).",
                    errno, r->connection->addr_text);
      break;
    }
  }
}

ngx_int_t
ngx_http_output_forbidden_page(ngx_http_request_ctx_t* ctx,
                               ngx_http_request_t* r,
                               ngx_http_ipfilter_loc_conf_t* cf)
{
  ngx_str_t empty = ngx_string("");
  ngx_http_internal_redirect(r, cf->denied_url, &empty);
  return (NGX_HTTP_OK);
}
