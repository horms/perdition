/**********************************************************************
 * perditiondb_cdb.h                                     December 1999
 * Horms                                             horms@verge.net.au
 *
 * Access a cdb(3) database
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2005  Horms
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

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <cdb.h>
#include <fcntl.h>

//extern cdb_error cdb_errno;
//extern char *cdb_version;

#ifndef PERDITIONDB_CDB_SYSCONFDIR
#define PERDITIONDB_CDB_SYSCONFDIR "/usr/local/etc/perdition"
#endif

#define PERDITIONDB_CDB_DEFAULT_MAPNAME \
  PERDITIONDB_CDB_SYSCONFDIR "/popmap.cdb"

int dbserver_get(
  const char *key_str,
  const char *options_str,
  char **str_return,
  int *len_return
);
