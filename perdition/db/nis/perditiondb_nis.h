/**********************************************************************
 * perditiondb_nis.h                                       October 2000
 * Nathan Neulinger                                       nneul@umr.edu
 *
 * Access a nis/yp database map
 *
 * perdition
 * Mail retrieval proxy server, NIS support
 * Copyright (C) 1999-2002 Nathan Neulinge and Horms
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

#include "log.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpcsvc/ypclnt.h>

#define PERDITIONDB_NIS_DEFAULT_MAPNAME "user_mail_server"

int dbserver_get(
  const char *key_str, 
  const char *options_str,
  char **str_return, 
  int *len_return
);
