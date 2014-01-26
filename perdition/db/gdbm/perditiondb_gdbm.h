/**********************************************************************
 * perditiondb_gdbm.h                                     December 1999
 * Horms                                             horms@verge.net.au
 *
 * Access a gdbm(3) database
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
#include <gdbm.h>

#ifndef PERDITIONDB_GDBM_SYSCONFDIR
#define PERDITIONDB_GDBM_SYSCONFDIR "/usr/local/etc/perdition"
#endif

#define PERDITIONDB_GDBM_DEFAULT_MAPNAME \
  PERDITIONDB_GDBM_SYSCONFDIR "/popmap.gdbm.db"

int dbserver_get(
  const char *key_str, 
  const char *options_str,
  char **str_return, 
  int *len_return
);
