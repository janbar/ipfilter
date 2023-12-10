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

#ifndef DB_H
#define DB_H

#ifdef __cplusplus
extern "C"
{
#endif

/* define IP4 CIDR address */
#define ADDR_SZ 4
typedef struct { char addr[ADDR_SZ]; int prefix; } cidr_address;

/* define opaque DB struct */
typedef struct DB DB;

typedef enum
{
  db_error      = -1,
  db_not_found  = 0,
  db_matched    = 1,
} db_response;

const char * db_format();

/*
 * In-memory db
 * First the database is empty. It has to be filled with records, and finally
 * it could be written in a static file.
 * The db handle must be closed to free allocated resources (see close_db).
 */

/* Create database with the given segment size (default 256).
 * Argument 'seg_size' defines the number of node per extent. The max count of
 * extent is fixed to 32K. Therefore the given value will define the max size
 * of the database as follows:
 *   bytes_per_node = 8
 *   max_nodes      = 32K * seg_size                : using 256 => 8M
 *   max_db_size    = byte_per_node * max_nodes     : using 256 => 64MB
 *
 * The number of nodes is limited to 2B: 32k * 64k
 */
DB * create_db(const char * filepath, const char * db_name, unsigned seg_size);

db_response create_record(DB * db, cidr_address * adr);

int fill_database_from_text(DB * db, const char * filepath);

const char * db_name(DB *db);

void rename_db(DB * db, const char * name);

/*
 * File db
 * Open read-only the database from an existing file.
 * The db handle must be closed to free allocated resources (see close_db).
 * WARNING: mount/close are not thread-safe, therefore you must lock the call
 * to these functions.
 */

DB * mount_db(const char * filepath, int rw);

/*
 * Basic operations on database
 */

void stat_db(DB * db);

void close_db(DB ** db);

db_response find_record(DB * db, cidr_address * adr);

/*
 * utilities
 */
int create_cidr_address(cidr_address * cidr, const char * cidr_str);

int create_cidr_address_2(cidr_address * cidr, const char * addr_str, int prefix);

#ifdef __cplusplus
}
#endif

#endif /* DB_H */

