/**********************************************************************
 * perditiondb_gdbm.h                                     December 1999
 * Horms                                             horms@vergenet.net
 *
 * Access a gdbm(3) database
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2001  Horms
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

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <gdbm.h>

extern gdbm_error gdbm_errno;
extern char *gdbm_version;

#ifndef PERDITIONDB_GDBM_SYSCONFDIR
#define PERDITIONDB_GDBM_SYSCONFDIR "/usr/local/etc/perdition"
#endif

#define PERDITIONDB_GDBM_DEFAULT_MAPNAME \
  PERDITIONDB_GDBM_SYSCONFDIR "/popmap.db"

int dbserver_get(
  char *key_str, 
  char *options_str,
  char **str_return, 
  int *len_return
);
