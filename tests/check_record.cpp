#include <iostream>
#include <string>
#include <cstring>
#include <climits>
#include <db.h>

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

static const char * tmpdb = "tmp.db";
static IPF_DB * db;

TEST_CASE("mount ro")
{
  db = ipf_mount_db(tmpdb, 0);
  REQUIRE(db != NULL);
}

TEST_CASE("check existing")
{
  ipf_cidr_address cidr;
  ipf_init_address_ipv4_mapped(&cidr);
  cidr.addr[12] = 192;
  cidr.addr[13] = 168;
  cidr.addr[14] = 0;
  cidr.addr[15] = 0;
  for (int i = 0; i < 64; ++i)
  {
    cidr.addr[14] = i & 0xff;
    for (int j = 0; j < 255; ++j)
    {
      cidr.addr[15] = j & 0xff;
      REQUIRE(ipf_query(db, &cidr) == ((i & 0x1) ? ipf_allow : ipf_deny));
      cidr.addr[15] = (++j) & 0xff;
      REQUIRE(ipf_query(db, &cidr) == ((i & 0x1) ? ipf_deny : ipf_allow));
    }
  }

  ipf_create_cidr_address(&cidr, "2A0F:CA80:616:2CE::/80");
  for (int i = 0; i < 64; ++i)
  {
    cidr.addr[8] = i & 0xff;
    for (int j = 0; j < 255; ++j)
    {
      cidr.addr[9] = j & 0xff;
      REQUIRE(ipf_query(db, &cidr) == ((i & 0x1) ? ipf_allow : ipf_deny));
      cidr.addr[9] = (++j) & 0xff;
      REQUIRE(ipf_query(db, &cidr) == ((i & 0x1) ? ipf_deny : ipf_allow));
    }
  }
}

TEST_CASE("check not found")
{
  ipf_cidr_address cidr;
  ipf_init_address_ipv4_mapped(&cidr);
  cidr.addr[12] = 192;
  cidr.addr[13] = 168;
  cidr.addr[14] = 0;
  cidr.addr[15] = 0;
  for (int i = 64; i < 128; ++i)
  {
    cidr.addr[14] = i & 0xff;
    for (int j = 0; j < 255; ++j)
    {
      cidr.addr[15] = j & 0xff;
      REQUIRE(ipf_query(db, &cidr) == ipf_not_found);
    }
  }

  ipf_create_cidr_address(&cidr, "2A0F:CA80:616:2CF::/80");
  for (int i = 0; i < 64; ++i)
  {
    cidr.addr[8] = i & 0xff;
    for (int j = 0; j < 255; ++j)
    {
      cidr.addr[9] = j & 0xff;
      REQUIRE(ipf_query(db, &cidr) == ipf_not_found);
    }
  }
}

TEST_CASE("close")
{
  ipf_close_db(&db);
  REQUIRE(db == NULL);
}
