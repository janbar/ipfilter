#include <iostream>
#include <string>
#include <cstring>
#include <climits>
#include <db.h>

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

static const char * tmpdb = "tmp.db";
static DB * db;

TEST_CASE("mount ro")
{
  db = mount_db(tmpdb, 0);
  REQUIRE(db != NULL);
}

TEST_CASE("check existing")
{
  cidr_address cidr;
  init_address_ipv4_mapped(&cidr);
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
      REQUIRE(find_record(db, &cidr) == ((i & 0x1) ? db_allow : db_deny));
      cidr.addr[15] = (++j) & 0xff;
      REQUIRE(find_record(db, &cidr) == ((i & 0x1) ? db_deny : db_allow));
    }
  }

  create_cidr_address(&cidr, "2A0F:CA80:616:2CE::/80");
  for (int i = 0; i < 64; ++i)
  {
    cidr.addr[8] = i & 0xff;
    for (int j = 0; j < 255; ++j)
    {
      cidr.addr[9] = j & 0xff;
      REQUIRE(find_record(db, &cidr) == ((i & 0x1) ? db_allow : db_deny));
      cidr.addr[9] = (++j) & 0xff;
      REQUIRE(find_record(db, &cidr) == ((i & 0x1) ? db_deny : db_allow));
    }
  }
}

TEST_CASE("check not found")
{
  cidr_address cidr;
  init_address_ipv4_mapped(&cidr);
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
      REQUIRE(find_record(db, &cidr) == db_not_found);
    }
  }

  create_cidr_address(&cidr, "2A0F:CA80:616:2CF::/80");
  for (int i = 0; i < 64; ++i)
  {
    cidr.addr[8] = i & 0xff;
    for (int j = 0; j < 255; ++j)
    {
      cidr.addr[9] = j & 0xff;
      REQUIRE(find_record(db, &cidr) == db_not_found);
    }
  }
}

TEST_CASE("close")
{
  close_db(&db);
  REQUIRE(db == NULL);
}
