#include <iostream>
#include <string>
#include <cstring>
#include <climits>
#include <db.h>
#include <tokenizer.h>

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

static const char * tmpdb = "tmp.db";
static IPF_DB * db;

static const char * sample_rules[] = {
  "ALLOW ::ffff:1.179.112.0/116",
  "DENY ::ffff:1.186.30.0/120",
  "DENY ::ffff:1.186.143.0/120",
  "ALLOW ::ffff:1.186.217.0/120",
  "ALLOW ::ffff:1.186.218.0/120",
  "ALLOW ::ffff:2.2.0.0/111",
  "ALLOW ::ffff:2.4.0.0/110",
  "DENY ::ffff:2.8.0.0/109",
  "ALLOW ::ffff:2.16.11.0/120",
  "ALLOW ::ffff:2.16.35.0/120",
  "DENY ::ffff:193.251.254.112/126",
  "DENY ::ffff:193.251.254.116/127",
  "ALLOW ::ffff:193.251.254.118/128",
  "ALLOW ::ffff:213.255.195.0/120",
  "DENY ::ffff:216.66.80.117/128",
  "ALLOW ::ffff:216.66.80.118/128",
  "ALLOW ::ffff:223.165.7.35/128",
  "ALLOW 2001:418:0:2000::162/128",
  "DENY 2001:438:ffff::407d:e25/128",
  "ALLOW 2001:438:ffff::407d:1d54/127",
  "DENY 2001:450:1e::/48",
  "DENY 2001:470:0:54::2/128",
  "DENY 2001:470:0:7b::/64",
  "ALLOW 2001:470:0:7c::/64",
  "ALLOW 2001:bc8:2db9:caef:73f0:b000::/100",
  "DENY 2a01:7c00:0:1::/64",
  "ALLOW 2a01:cb04:34d:300:16cc:20ff:fef8:8000/115",
  "ALLOW 2a01:cb04:34d:300:16cc:20ff:fef8:a000/117",
  "ALLOW 2a01:cb0c:9c7:a700:a62b:8000::/83",
  "DENY 2a01:cb0d:125:2400:ea94:f6ff:fee3:5b80/122",
  "ALLOW 2a0d:7e80::/29",
  "DENY 2a0d:82c1:5054::fe7a:605a/128",
  "ALLOW 2a13:ef45:375a::/47",
  "DENY 2c0f:feb0:21::/48",
  ""
};

static unsigned _readln(char * buf, unsigned n, FILE * file)
{
  unsigned r = 0;
  int c;
  while (r < n)
  {
    if ((c = fgetc(file)) <= 0)
      break;
    /* bypass CTRL+R */
    if (c == '\r')
      continue;
    ++r;
    *buf = (char) c;
    if (c == '\n')
      break;
    ++buf;
  }
  return r;
}

static uint32_t ipf_hash(uint32_t maxsize, const char * buf, unsigned len)
{
  /*
   * DJB Hash Function
   */
  uint32_t h = 5381;
  const char * end = buf + len;

  while (buf < end)
  {
    h = ((h << 5) + h) + *buf++;
  }
  return h % maxsize;
}

static std::string& upstr(std::string& str)
{
  std::string::iterator c = str.begin();
  while (c != str.end())
  {
    *c = toupper(*c);
    ++c;
  }
  return str;
}

static int load_rules(IPF_DB * db)
{
  const char * line;
  unsigned r = 0, l = 0;
  for (;;)
  {
    line = sample_rules[l];
    r = strlen(line);
    if (r == 0)
      break;
    /* parse line */
    std::vector<std::string> tokens;
    tokenize(line, " ", "", tokens, true);
    std::vector<std::string>::const_iterator it = tokens.begin();
    if (it == tokens.end())
      continue;
    std::string token(*it);
    /* discard comment or empty line */
    if (token.at(0) == '#')
      continue;
    /* parse RULE */
    ipf_rule rule;
    upstr(token);
    if (token == "ALLOW")
      rule = ipf_rule_allow;
    else if (token == "DENY")
      rule = ipf_rule_deny;
    else
      break;
    /* parse CIDR address */
    if (it == tokens.end())
      break;
    token.assign(*(++it));
    ipf_cidr_address adr;
    if (ipf_create_cidr_address(&adr, token.c_str()) < 0)
      break;
    if (ipf_insert_rule(db, &adr, rule) == ipf_error)
      break;
    ++l;
  }
  if (r != 0)
    return -(EINVAL);
  if (l > 0)
    return ipf_flush_db(db);
  return 0;
}

TEST_CASE("mount rw")
{
  db = ipf_mount_db(tmpdb, 1);
  REQUIRE(db != NULL);
  ipf_purge_db(db);
}

TEST_CASE("import")
{
  REQUIRE(load_rules(db) == 0);
}

TEST_CASE("check records")
{
  ipf_cidr_address cidr;
  ipf_create_cidr_address(&cidr, "::FFFF:1.186.218.15/124");
  REQUIRE(ipf_query(db, &cidr) == ipf_allow);
  ipf_create_cidr_address(&cidr, "::FFFF:193.251.254.117/128");
  REQUIRE(ipf_query(db, &cidr) == ipf_deny);
  ipf_create_cidr_address(&cidr, "::FFFF:193.251.254.118/128");
  REQUIRE(ipf_query(db, &cidr) == ipf_allow);
  ipf_create_cidr_address(&cidr, "2A01:CB04:34D:300:16CC:20FF:FEF8:805E/128");
  REQUIRE(ipf_query(db, &cidr) == ipf_allow);
  ipf_create_cidr_address(&cidr, "2A0D:82C1:5054::FE7A:605A/128");
  REQUIRE(ipf_query(db, &cidr) == ipf_deny);
  ipf_create_cidr_address(&cidr, "2C0F:FEB0:21::683A:6/129");
  REQUIRE(ipf_query(db, &cidr) == ipf_deny);
}

TEST_CASE("export")
{
  FILE * file = fopen("tmp.txt", "w+");
  REQUIRE(file != NULL);
  REQUIRE(ipf_export_db(db, file) == 0);
  fclose(file);

  file = fopen("tmp.txt", "r");
  REQUIRE(file != NULL);
  uint32_t h = 0;
  char line[80];
  int r;
  snprintf(line, 11, "%08x: ", h);
  while ((r = _readln(line + 10, sizeof (line) - 11, file)))
  {
    h = ipf_hash(0xffffffff, line, r + 10);
    snprintf(line, 11, "%08x: ", h);
  }
  fclose(file);
  REQUIRE(h == 0xf8771d01);
  remove("tmp.txt");
}

TEST_CASE("close")
{
  ipf_close_db(&db);
  REQUIRE(db == NULL);
}
