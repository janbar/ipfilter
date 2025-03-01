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
static IPF_DB * dbrw;
static IPF_DB * dbro;

TEST_CASE("create database")
{
  struct stat filestat;

  /* check file exists */
  if (stat(tmpdb, &filestat) == 0)
  {
    REQUIRE((remove(tmpdb) == 0));
  }

  dbrw = ipf_create_db(tmpdb, "tmpdb", SEGS);
  REQUIRE(dbrw != NULL);
  REQUIRE(dbrw->header != NULL);
  REQUIRE(dbrw->data != NULL);
  REQUIRE(dbrw->cache.seg_nb > 0);
  REQUIRE(dbrw->cache.seg_sz == SEGS);
  REQUIRE(dbrw->cache.seg_sz == SEGMENT_SIZE(dbrw->header->seg_mask));
  REQUIRE(dbrw->cache.seg_nb == dbrw->header->seg_nb);
  REQUIRE((dbrw->header->root4_addr & ADDR) != 0);
  REQUIRE((dbrw->header->root6_addr & ADDR) != 0);

  REQUIRE(dbrw->destructor != NULL);
  REQUIRE(ipf_mounted != NULL);
  REQUIRE(ipf_mounted->refcount == 1);
}

TEST_CASE("fill database")
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
      ipf_insert_rule(dbrw, &cidr, (i & 0x1) ? ipf_rule_allow : ipf_rule_deny);
      cidr.addr[15] = (++j) & 0xff;
      ipf_insert_rule(dbrw, &cidr, (i & 0x1) ? ipf_rule_deny : ipf_rule_allow);
    }
  }
  REQUIRE(dbrw->cache.seg_nb == 65);

  ipf_create_cidr_address(&cidr, "2A0F:CA80:616:2CE::/80");
  for (int i = 0; i < 64; ++i)
  {
    cidr.addr[8] = i & 0xff;
    for (int j = 0; j < 255; ++j)
    {
      cidr.addr[9] = j & 0xff;
      ipf_insert_rule(dbrw, &cidr, (i & 0x1) ? ipf_rule_allow : ipf_rule_deny);
      cidr.addr[9] = (++j) & 0xff;
      ipf_insert_rule(dbrw, &cidr, (i & 0x1) ? ipf_rule_deny : ipf_rule_allow);
    }
  }
  REQUIRE(dbrw->cache.seg_nb == 129);
}

TEST_CASE("check mount refcount")
{
  dbro = ipf_mount_db(tmpdb, 0);
  REQUIRE(dbro != NULL);
  REQUIRE(dbro == dbrw);
  REQUIRE(ipf_mounted->refcount == 2);

  REQUIRE(dbro->header != NULL);
  REQUIRE(dbro->data != NULL);
  REQUIRE(dbro->cache.seg_nb > 0);
  REQUIRE(dbro->cache.seg_sz == SEGS);
  REQUIRE(dbro->cache.seg_sz == SEGMENT_SIZE(dbro->header->seg_mask));
  REQUIRE(dbro->cache.seg_nb == dbro->header->seg_nb);
  REQUIRE((dbro->header->root4_addr & ADDR) != 0);
  REQUIRE((dbro->header->root6_addr & ADDR) != 0);

  REQUIRE(dbro->destructor != NULL);
  ipf_close_db(&dbro);
  REQUIRE(dbro == NULL);
  REQUIRE(ipf_mounted->refcount == 1);
}

TEST_CASE("check existing")
{
  dbro = ipf_mount_db(tmpdb, 0);

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
      REQUIRE(ipf_query(dbro, &cidr) == ((i & 0x1) ? ipf_allow : ipf_deny));
      cidr.addr[15] = (++j) & 0xff;
      REQUIRE(ipf_query(dbro, &cidr) == ((i & 0x1) ? ipf_deny : ipf_allow));
    }
  }

  ipf_create_cidr_address(&cidr, "2A0F:CA80:616:2CE::/80");
  for (int i = 0; i < 64; ++i)
  {
    cidr.addr[8] = i & 0xff;
    for (int j = 0; j < 255; ++j)
    {
      cidr.addr[9] = j & 0xff;
      REQUIRE(ipf_query(dbro, &cidr) == ((i & 0x1) ? ipf_allow : ipf_deny));
      cidr.addr[9] = (++j) & 0xff;
      REQUIRE(ipf_query(dbro, &cidr) == ((i & 0x1) ? ipf_deny : ipf_allow));
    }
  }

  ipf_close_db(&dbro);
}

TEST_CASE("check not found")
{
  dbro = ipf_mount_db(tmpdb, 0);

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
      REQUIRE(ipf_query(dbro, &cidr) == ipf_not_found);
    }
  }

  ipf_create_cidr_address(&cidr, "2A0F:CA80:616:2CF::/80");
  for (int i = 0; i < 64; ++i)
  {
    cidr.addr[8] = i & 0xff;
    for (int j = 0; j < 255; ++j)
    {
      cidr.addr[9] = j & 0xff;
      REQUIRE(ipf_query(dbro, &cidr) == ipf_not_found);
    }
  }

  ipf_close_db(&dbro);
}

TEST_CASE("close rw")
{
  ipf_stat_db(dbrw, stdout);
  ipf_close_db(&dbrw);
  REQUIRE(dbrw == NULL);
  REQUIRE(ipf_mounted == NULL);
}
