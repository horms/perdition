/**********************************************************************
 * perditiondb_odbc.h                                        March 2002
 * Horms                                            horms@vergenet.net.
 *
 * Access a database using ODBC
 *
 * Adapted from code contributed by:
 * Frederic Delchambre                                     October 1999
 * N.T.S. / Freegates                                dedel@freegates.be
 *                                             http://www.freegates.be/
 *                                                   http://www.nts.be/
 * perdition
 * Mail retrieval proxy server, MySQL support
 * Copyright (C) 1999-2002  Horms, Frederic Delchambre
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#ifndef PERDITIONDB_MYSQ_H
#define PERDITIONDB_MYSQ_H

#include "log.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <sql.h>
#include <sqlext.h>
#include <sqltypes.h>
#include <vanessa_adt.h>

#define PERDITIONDB_ODBC_FIELD_DELIMITER   ':'
#define PERDITIONDB_ODBC_MAX_SLEEP         1800
#define PERDITIONDB_ODBC_DEFAULT_DBHOST    "localhost"
#define PERDITIONDB_ODBC_DEFAULT_DBPORT    0
#define PERDITIONDB_ODBC_DEFAULT_DBNAME    "dbPerdition"
#define PERDITIONDB_ODBC_DEFAULT_DBTABLE   "tblPerdition"
#define PERDITIONDB_ODBC_DEFAULT_DBUSER    "perdition"
#define PERDITIONDB_ODBC_DEFAULT_DBPWD     "perdition"
#define PERDITIONDB_ODBC_DEFAULT_DBUSERCOL "user"
#define PERDITIONDB_ODBC_DEFAULT_DBSRVCOL  "servername"
#define PERDITIONDB_ODBC_DEFAULT_DBPORTCOL "port"

#define PERDITIONDB_ODBC_DBHOST    0
#define PERDITIONDB_ODBC_DBPORT    1
#define PERDITIONDB_ODBC_DBNAME    2
#define PERDITIONDB_ODBC_DBTABLE   3
#define PERDITIONDB_ODBC_DBUSER    4
#define PERDITIONDB_ODBC_DBPWD     5
#define PERDITIONDB_ODBC_DBSRVCOL  6
#define PERDITIONDB_ODBC_DBUSERCOL 7
#define PERDITIONDB_ODBC_DBPORTCOL 8

#define PERDITIONDB_ODBC_QUERY_LENGTH 256
#define PERDITIONDB_ODBC_RESULT_LENGTH 256

int dbserver_fini(void);

int dbserver_init(char *options_str);

int dbserver_get(char *key_str,
		 char *options_str,
		 char **str_return, size_t * len_return);

#endif
