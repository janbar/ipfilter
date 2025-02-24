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

#ifndef IPF_DB_H
#define IPF_DB_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>

/* define CIDR address */
#define IPF_ADDR_SZ     16
typedef struct
{
  unsigned char addr[IPF_ADDR_SZ];  /* IPv6 or IPv4 mapped IPv6 */
  int prefix;                       /* subnet bit mask (0..128) */
} ipf_cidr_address;

/* define opaque DB struct */
typedef struct IPF_DB IPF_DB;

typedef enum
{
  ipf_not_found  = 0,
  ipf_allow      = 1,
  ipf_deny       = 2,
  ipf_error      = 3,
} ipf_response;

typedef enum
{
  ipf_rule_allow = ipf_allow,
  ipf_rule_deny  = ipf_deny,
} ipf_rule;

const char * ipf_db_format();

/**
 * Create database with the given segment size (default 0 = 256).
 * Argument 'seg_size' defines the number of node per extent. The max count of
 * extent is fixed to 16K. Therefore the given value will define the max size
 * of the database as follows:
 *   bytes_per_node = 8
 *   max_nodes      = 16K * seg_size                : using 256 => 4M
 *   max_db_size    = byte_per_node * max_nodes     : using 256 => 32MB
 *
 * As max_db_size is reserved in virtual memory, do not increase seg_size
 * unnecessarily. In most cases the default value (256) is large enough.
 * The db handle must be closed to free allocated resources (see close_db).
 * @param filepath Path of the db file
 * @param db_name The string of the name (30 chars)
 * @param seg_size Number of node per segment (0=256 or 512,1024...)
 * @return The DB handle, else NULL
 */
IPF_DB * ipf_create_db(const char * filepath,
                       const char * db_name,
                       unsigned seg_size);

/**
 * Returns the database name
 * @param db The DB handle
 * @return The string terminated by 0
 */
const char * ipf_db_name(IPF_DB * db);

/**
 * Rename the database
 * @param db The DB handle
 * @param name The string of the new name (30 chars)
 */
void ipf_rename_db(IPF_DB * db, const char * name);

/**
 * Update database with a new rule for the given CIDR
 * @param db The DB handle
 * @param cidr
 * @param rule
 * @return The old state on success, else error
 */
ipf_response ipf_insert_rule(IPF_DB * db,
                             ipf_cidr_address * cidr,
                             ipf_rule rule);

/**
 * Flush the database
 * @param db The DB handle
 * @return 0 on success, else error
 */
int ipf_flush_db(IPF_DB * db);

/**
 * Mount database from the given db file. The db handle must be closed to free
 * allocated resources (see close_db).
 * WARNING: mount/close are not thread-safe, therefore you must lock the call
 * to these functions.
 * @param filepath Path of db file
 * @param rw The mode 0=Read 1=Read-Write
 * @return The DB handle, else NULL
 */
IPF_DB * ipf_mount_db(const char * filepath, int rw);

/*
 * Basic operations on database
 */

/**
 * Print the database header infos on the standard output
 * @param db The DB handle
 * @param out The file handle open for writing
 */
void ipf_stat_db(IPF_DB * db, FILE * out);

/**
 * Purge the mounted RW database
 * That allows to defrag an existing database, to be refilled on the fly.
 * @param db The DB handle
 */
void ipf_purge_db(IPF_DB * db);

/**
 * Close the database and free allocated resources
 * The given DB handle will be nullified (NULL)
 * @param db A pointer to the DB handle
 */
void ipf_close_db(IPF_DB ** db);

/**
 * Query the database for the given address/subnet
 * @param db The DB handle
 * @param cidr
 * @return The state among allow deny empty, else error
 */
ipf_response ipf_query(IPF_DB * db, ipf_cidr_address * cidr);

/**
 * Extract the contents of the database to a file
 * @param db The DB handle
 * @param out The file handle open for writing
 */
int ipf_export_db(IPF_DB * db, FILE * out);

/*
 * utilities
 */

/**
 * Helper to fill the struct cidr_address from CIDR string
 * The supported formats are:
 *   nnn.nnn.nnn.nnn/pp , ::FFFF:nnn.nnn.nnn.nnn/ppp , x:x:x:x:x:x:x:x/ppp
 * @param cidr The struct to load
 * @param cidr_str The formatted string
 * @return 0 on success, else error
 */
int ipf_create_cidr_address(ipf_cidr_address * cidr,
                            const char * cidr_str);

/**
 * Helper to fill the struct cidr_address from address string and prefix
 * The supported formats are:
 *   nnn.nnn.nnn.nnn , ::FFFF:nnn.nnn.nnn.nnn , x:x:x:x:x:x:x:x
 * @param cidr The struct to load
 * @param addr_str The formatted string
 * @param prefix subnet number (0-32/0-128)
 * @return 0 on success, else error
 */
int ipf_create_cidr_address_2(ipf_cidr_address * cidr,
                              const char * addr_str,
                              int prefix);

void ipf_init_address_ipv4_mapped(ipf_cidr_address * cidr);

#ifdef __cplusplus
}
#endif

#endif /* IPF_DB_H */

