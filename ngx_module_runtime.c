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
//#include <netinet/in.h>

void
ngx_http_ipfilter_data_parse(ngx_http_request_ctx_t* ctx,
                             ngx_http_request_t* r,
                             ngx_http_ipfilter_loc_conf_t* cf)
{
  ngx_addr_t addr;
  in_addr_t inaddr;
  struct sockaddr_in *sin;
#if (NGX_HAVE_INET6)
  u_char *p;
  struct in6_addr *inaddr6;
#endif

  if (!cf || !ctx)
  {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  IPFILTER_TAG " unable to parse data.");
    return;
  }

  addr.sockaddr = r->connection->sockaddr;
  addr.socklen = r->connection->socklen;
  switch (addr.sockaddr->sa_family)
  {
#if (NGX_HAVE_INET6)
  case AF_INET6:
    inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;
    p = inaddr6->s6_addr;
    if (IN6_IS_ADDR_V4MAPPED(inaddr6))
    {
      inaddr = p[12] << 24;
      inaddr += p[13] << 16;
      inaddr += p[14] << 8;
      inaddr += p[15];
    }
    else
      inaddr = INADDR_NONE;
    break;
#endif
  default: /* AF_INET */
    sin = (struct sockaddr_in *) addr.sockaddr;
    inaddr = ntohl(sin->sin_addr.s_addr);
    break;
  }

  if (inaddr == INADDR_NONE)
  {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
              IPFILTER_TAG " Unable to process address family=%d.",
              r->connection->sockaddr->sa_family);
  }
  else
  {
    cidr_address cidr;
    cidr.addr[0] = (inaddr >> 24) & 0xff;
    cidr.addr[1] = (inaddr >> 16) & 0xff;
    cidr.addr[2] = (inaddr >> 8) & 0xff;
    cidr.addr[3] = inaddr & 0xff;
    cidr.prefix = 32;
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
                    IPFILTER_TAG " Database query failed (%d).", errno);
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
