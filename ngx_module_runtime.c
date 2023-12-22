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
/*#include <netinet/in.h>*/

void
ngx_http_ipfilter_data_parse(ngx_http_request_ctx_t* ctx,
                             ngx_http_request_t* r,
                             ngx_http_ipfilter_loc_conf_t* cf)
{
  cidr_address cidr;
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
    memcpy(cidr.addr, p, 16);
    cidr.prefix = 128;
    break;
#endif
  case AF_INET:
    sin = (struct sockaddr_in *) addr.sockaddr;
    inaddr = ntohl(sin->sin_addr.s_addr);
    init_address_ipv4_mapped(&cidr);
    cidr.addr[12] = (inaddr >> 24) & 0xff;
    cidr.addr[13] = (inaddr >> 16) & 0xff;
    cidr.addr[14] = (inaddr >> 8) & 0xff;
    cidr.addr[15] = inaddr & 0xff;
    break;
  default:
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
              IPFILTER_TAG " Unable to process address family=%d.",
              r->connection->sockaddr->sa_family);
    return;
  }

  ctx->response = find_record(cf->db_instance, &cidr);
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
