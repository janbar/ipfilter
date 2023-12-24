#include <iostream>
#include <string>
#include <cstring>
#include <climits>
#include <db.h>

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

static cidr_address cidr;

TEST_CASE("Parse CIDR from IPv4 string")
{
  create_cidr_address(&cidr, "192.168.2.254/32");
  REQUIRE( cidr.addr[0] == 0);
  REQUIRE( cidr.addr[1] == 0);
  REQUIRE( cidr.addr[2] == 0);
  REQUIRE( cidr.addr[3] == 0);
  REQUIRE( cidr.addr[4] == 0);
  REQUIRE( cidr.addr[5] == 0);
  REQUIRE( cidr.addr[6] == 0);
  REQUIRE( cidr.addr[7] == 0);
  REQUIRE( cidr.addr[8] == 0);
  REQUIRE( cidr.addr[9] == 0);
  REQUIRE( cidr.addr[10] == 255);
  REQUIRE( cidr.addr[11] == 255);
  REQUIRE( cidr.addr[12] == 192);
  REQUIRE( cidr.addr[13] == 168);
  REQUIRE( cidr.addr[14] == 2);
  REQUIRE( cidr.addr[15] == 254);
  REQUIRE( cidr.prefix == (96+32));
}

TEST_CASE("Parse CIDR from IPv4 mapped string")
{
  create_cidr_address(&cidr, "::FFFF:192.168.2.254/112");
  REQUIRE( cidr.addr[0] == 0);
  REQUIRE( cidr.addr[1] == 0);
  REQUIRE( cidr.addr[2] == 0);
  REQUIRE( cidr.addr[3] == 0);
  REQUIRE( cidr.addr[4] == 0);
  REQUIRE( cidr.addr[5] == 0);
  REQUIRE( cidr.addr[6] == 0);
  REQUIRE( cidr.addr[7] == 0);
  REQUIRE( cidr.addr[8] == 0);
  REQUIRE( cidr.addr[9] == 0);
  REQUIRE( cidr.addr[10] == 255);
  REQUIRE( cidr.addr[11] == 255);
  REQUIRE( cidr.addr[12] == 192);
  REQUIRE( cidr.addr[13] == 168);
  REQUIRE( cidr.addr[14] == 2);
  REQUIRE( cidr.addr[15] == 254);
  REQUIRE( cidr.prefix == 112);
}

TEST_CASE("Parse CIDR from IPv6 string")
{
  create_cidr_address(&cidr, "2A01:CB08:1C4:E700:C24A:FF:FE09:56B7/128");
  REQUIRE( cidr.addr[0] == 0x2A);
  REQUIRE( cidr.addr[1] == 0x01);
  REQUIRE( cidr.addr[2] == 0xCB);
  REQUIRE( cidr.addr[3] == 0x08);
  REQUIRE( cidr.addr[4] == 0x01);
  REQUIRE( cidr.addr[5] == 0xC4);
  REQUIRE( cidr.addr[6] == 0xE7);
  REQUIRE( cidr.addr[7] == 0x00);
  REQUIRE( cidr.addr[8] == 0xC2);
  REQUIRE( cidr.addr[9] == 0x4A);
  REQUIRE( cidr.addr[10] == 0x00);
  REQUIRE( cidr.addr[11] == 0xFF);
  REQUIRE( cidr.addr[12] == 0xFE);
  REQUIRE( cidr.addr[13] == 0x09);
  REQUIRE( cidr.addr[14] == 0x56);
  REQUIRE( cidr.addr[15] == 0xB7);
  REQUIRE( cidr.prefix == 128);
}

TEST_CASE("Parse CIDR from IPv6 L string")
{
  create_cidr_address(&cidr, "2001:470:0:7B::/64");
  REQUIRE( cidr.addr[0] == 0x20);
  REQUIRE( cidr.addr[1] == 0x01);
  REQUIRE( cidr.addr[2] == 0x04);
  REQUIRE( cidr.addr[3] == 0x70);
  REQUIRE( cidr.addr[4] == 0x00);
  REQUIRE( cidr.addr[5] == 0x00);
  REQUIRE( cidr.addr[6] == 0x00);
  REQUIRE( cidr.addr[7] == 0x7B);
  REQUIRE( cidr.addr[8] == 0x00);
  REQUIRE( cidr.addr[9] == 0x00);
  REQUIRE( cidr.addr[10] == 0x00);
  REQUIRE( cidr.addr[11] == 0x00);
  REQUIRE( cidr.addr[12] == 0x00);
  REQUIRE( cidr.addr[13] == 0x00);
  REQUIRE( cidr.addr[14] == 0x00);
  REQUIRE( cidr.addr[15] == 0x00);
  REQUIRE( cidr.prefix == 64);
}

TEST_CASE("Parse CIDR from IPv6 R string")
{
  create_cidr_address(&cidr, "::CB08:460:E0/124");
  REQUIRE( cidr.addr[0] == 0x00);
  REQUIRE( cidr.addr[1] == 0x00);
  REQUIRE( cidr.addr[2] == 0x00);
  REQUIRE( cidr.addr[3] == 0x00);
  REQUIRE( cidr.addr[4] == 0x00);
  REQUIRE( cidr.addr[5] == 0x00);
  REQUIRE( cidr.addr[6] == 0x00);
  REQUIRE( cidr.addr[7] == 0x00);
  REQUIRE( cidr.addr[8] == 0x00);
  REQUIRE( cidr.addr[9] == 0x00);
  REQUIRE( cidr.addr[10] == 0xCB);
  REQUIRE( cidr.addr[11] == 0x08);
  REQUIRE( cidr.addr[12] == 0x04);
  REQUIRE( cidr.addr[13] == 0x60);
  REQUIRE( cidr.addr[14] == 0x00);
  REQUIRE( cidr.addr[15] == 0xE0);
  REQUIRE( cidr.prefix == 124);
}

TEST_CASE("Parse CIDR from IPv6 LR string")
{
  create_cidr_address(&cidr, "2001:470:0:1B0::8000:0/97");
  REQUIRE( cidr.addr[0] == 0x20);
  REQUIRE( cidr.addr[1] == 0x01);
  REQUIRE( cidr.addr[2] == 0x04);
  REQUIRE( cidr.addr[3] == 0x70);
  REQUIRE( cidr.addr[4] == 0x00);
  REQUIRE( cidr.addr[5] == 0x00);
  REQUIRE( cidr.addr[6] == 0x01);
  REQUIRE( cidr.addr[7] == 0xB0);
  REQUIRE( cidr.addr[8] == 0x00);
  REQUIRE( cidr.addr[9] == 0x00);
  REQUIRE( cidr.addr[10] == 0x00);
  REQUIRE( cidr.addr[11] == 0x00);
  REQUIRE( cidr.addr[12] == 0x80);
  REQUIRE( cidr.addr[13] == 0x00);
  REQUIRE( cidr.addr[14] == 0x00);
  REQUIRE( cidr.addr[15] == 0x00);
  REQUIRE( cidr.prefix == 97);
}
