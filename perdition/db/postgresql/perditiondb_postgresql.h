/**********************************************************************
 * perditiondb_postgresql.h                                  April 2000
 * Horms                                            horms@verge.net.au.
 *
 * Access a PostgreSQL database
 *
 * Adapted from code contributed for access to MySQL by:
 * Frederic Delchambre                                     October 1999
 * N.T.S. / Freegates                                dedel@freegates.be
 *                                             http://www.freegates.be/
 *                                                   http://www.nts.be/
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2005  Horms and Frederic Delchambre
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 **********************************************************************/

#ifndef PERDITIONDB_PGSQL_H
#define PERDITIONDB_PGSQL_H

#include "log.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <libpq-fe.h>
#include <vanessa_adt.h>

#define PERDITIONDB_PGSQL_FIELD_DELIMITER   ':'
#define PERDITIONDB_PGSQL_MAX_SLEEP         1800
#define PERDITIONDB_PGSQL_DEFAULT_DBHOST    "localhost"
#define PERDITIONDB_PGSQL_DEFAULT_DBPORT    NULL
#define PERDITIONDB_PGSQL_DEFAULT_DBNAME    "dbperdition"
#define PERDITIONDB_PGSQL_DEFAULT_DBTABLE   "tblPerdition"
#define PERDITIONDB_PGSQL_DEFAULT_DBUSER    "perdition"
#define PERDITIONDB_PGSQL_DEFAULT_DBPWD     "perdition"
#define PERDITIONDB_PGSQL_DEFAULT_DBUSERCOL "user"
#define PERDITIONDB_PGSQL_DEFAULT_DBSRVCOL  "servername"
#define PERDITIONDB_PGSQL_DEFAULT_DBPORTCOL "port"

#define PERDITIONDB_PGSQL_DBHOST    0
#define PERDITIONDB_PGSQL_DBPORT    1
#define PERDITIONDB_PGSQL_DBNAME    2
#define PERDITIONDB_PGSQL_DBTABLE   3
#define PERDITIONDB_PGSQL_DBUSER    4
#define PERDITIONDB_PGSQL_DBPWD     5
#define PERDITIONDB_PGSQL_DBSRVCOL  6
#define PERDITIONDB_PGSQL_DBUSERCOL 7
#define PERDITIONDB_PGSQL_DBPORTCOL 8

#define PERDITIONDB_PGSQL_QUERY_LENGTH 256

int dbserver_fini(void);

int dbserver_init(char *options_str);

int dbserver_get(
  const char   * key_str,
  const char   * options_str,
  char   **str_return,
  size_t *len_return
);

#endif
