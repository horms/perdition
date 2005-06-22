/**********************************************************************
 * getserver.h                                            December 1999
 * Horms                                             horms@verge.net.au
 *
 * Access a database
 *
 * The database is accessed using the dlopen mechanism on a library.
 * See getserver.c for API details.
 *
 * Client server specification code courtesy of Daniel Roesen,
 * <droesen@entire-systems.com>. 
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#ifndef GETSERVER_FLIM
#define GETSERVER_FLIM

#include "options.h"
#include "server_port.h"
#include "log.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <dlfcn.h>


user_server_port_t 
*getserver(
  const char *user_str, const char *from_str, const char *to_str, 
  const uint16 from_port, const uint16 to_port, 
  int (*dbserver_get)(const char *, const char *, char **, size_t *),
  int (*dbserver_get2)(const char *, const char *, char **, char **, char **));

int 
getserver_openlib(
  char *libname,
  char *opt_string,
  void **handle_return,
  int (**dbgetserver_return)(const char *, const char *, char **, size_t *),
  int (**dbgetserver2_return)(const char *, const char *, char **, 
	  char **, char**)
);

int getserver_closelib(void *handle);

#endif
