/**********************************************************************
 * perditiondb_ldap.h                                        March 2000
 * ChrisS                                              chriss@uk.uu.net
 *
 * Access an LDAP database
 *
 * perdition
 * Mail retrieval proxy server, LDAP support
 * Copyright (C) 2000-2001 ChrisS and Horms
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

#ifndef PERDITIONDB_LDAP_H
#define PERDITIONDB_LDAP_H

#include "log.h"
#include "options.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <lber.h>
#include <ldap.h>

int dbserver_fini(void);

int dbserver_init(char *options_str);

int dbserver_get(
  char *key_str, 
  char *options_str,
  char **str_return, 
  int *len_return
);


#define PERDITIONDB_LDAP_DEFAULT_URL \
  "ldap://localhost/" \
  "ou=mailbox,dc=my-domain,dc=com?username,mailhost,port?one?(uid=%25s)"

#endif
