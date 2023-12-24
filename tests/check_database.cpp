#include <iostream>
#include <string>
#include <cstring>
#include <climits>

extern "C"
{
#include <db.c>
}

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

static const char * tmpdb = "tmp.db";
static DB * db;

TEST_CASE("create")
{
  struct stat filestat;

  /* check file exists */
  if (stat(tmpdb, &filestat) == 0)
  {
    REQUIRE((remove(tmpdb) == 0));
  }

  db = create_db(tmpdb, "tmpdb", SEGS);
  REQUIRE(db != NULL);
  REQUIRE(db->header != NULL);
  REQUIRE(db->data != NULL);
  REQUIRE(db->cache.seg_nb > 0);
  REQUIRE(db->cache.seg_sz == SEGS);
  REQUIRE(db->cache.seg_sz == SEGMENT_SIZE(db->header->seg_mask));
  REQUIRE(db->cache.seg_nb == db->header->seg_nb);
  REQUIRE((db->header->root4_addr & ADDR) != 0);
  REQUIRE((db->header->root6_addr & ADDR) != 0);

  REQUIRE(db->destructor != NULL);
  REQUIRE(g_mounted != NULL);
  REQUIRE(g_mounted->refcount == 1);
}

TEST_CASE("mount")
{
  DB * dbro = mount_db(tmpdb, 0);
  REQUIRE(dbro != NULL);
  REQUIRE(g_mounted->refcount == 2);

  REQUIRE(dbro->header != NULL);
  REQUIRE(dbro->data != NULL);
  REQUIRE(dbro->cache.seg_nb > 0);
  REQUIRE(dbro->cache.seg_sz == SEGS);
  REQUIRE(dbro->cache.seg_sz == SEGMENT_SIZE(dbro->header->seg_mask));
  REQUIRE(dbro->cache.seg_nb == dbro->header->seg_nb);
  REQUIRE((dbro->header->root4_addr & ADDR) != 0);
  REQUIRE((dbro->header->root6_addr & ADDR) != 0);

  REQUIRE(dbro->destructor != NULL);
  close_db(&dbro);
  REQUIRE(dbro == NULL);
  REQUIRE(g_mounted->refcount == 1);
}

TEST_CASE("fill")
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
      insert_cidr(db, &cidr, (i & 0x1) ? rule_allow : rule_deny);
      cidr.addr[15] = (++j) & 0xff;
      insert_cidr(db, &cidr, (i & 0x1) ? rule_deny : rule_allow);
    }
  }
  REQUIRE(db->cache.seg_nb == 65);

  create_cidr_address(&cidr, "2A0F:CA80:616:2CE::/80");
  for (int i = 0; i < 64; ++i)
  {
    cidr.addr[8] = i & 0xff;
    for (int j = 0; j < 255; ++j)
    {
      cidr.addr[9] = j & 0xff;
      insert_cidr(db, &cidr, (i & 0x1) ? rule_allow : rule_deny);
      cidr.addr[9] = (++j) & 0xff;
      insert_cidr(db, &cidr, (i & 0x1) ? rule_deny : rule_allow);
    }
  }
  REQUIRE(db->cache.seg_nb == 129);
}

TEST_CASE("close")
{
  close_db(&db);
  REQUIRE(db == NULL);
  REQUIRE(g_mounted == NULL);
}
