/**********************************************************************
 * perditiondb_bdb.c                                      February 2002
 * ChrisS                                              chriss@pipex.net
 *
 * Access a Berkeley DB database
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

#include "perditiondb_bdb.h"


/**********************************************************************
 * dbserver_get
 * Read the server (value) from a bdb map given the user (key)
 * pre: key_str: Key as a null terminated string
 *      options_str: Options string. 
 *                   Ignored if NULL
 *                   Used as the map to open otherwise
 *      str_return: value is returned here
 *      len_return: length of value is returned here
 * post: The str_key is looked up in the gdbm map and the
 *       corresponding value is returned in str_return and len_return.
 * return:  0 on success
 *         -1 on file access error
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_get(
  char *key_str, 
  char *options_str,
  char **str_return, 
  int  *len_return
){
  DB *dbp;
  DBT key, value;
  int ret;

  if ((ret = db_create(&dbp, NULL, 0)) != 0) {
    return(-3);
  }
  if ((ret = dbp->open(
       dbp,
#ifdef HAVE_BDB_4_1
       NULL,
#endif
       (options_str==NULL)?PERDITIONDB_BDB_DEFAULT_MAPNAME:options_str,
       NULL,
       DB_HASH,
       DB_RDONLY,
       0644
     )) != 0) {
     return(-1);
  }
  memset(&key, 0, sizeof(key));
  memset(&value, 0, sizeof(value));
  key.data = (void *)key_str;
  key.size = strlen(key_str) + 1;

  if ((ret = dbp->get(dbp, NULL, &key, &value, 0)) != 0) {
    VANESSA_LOGGER_INFO_UNSAFE("No match for %s", key_str);
    dbp->close(dbp, 0);
    return(-2);
  }

  /* Store the return string somewhere */
  if ((*str_return = (char *)malloc(value.size)) == NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("servername malloc");
    dbp->close(dbp, 0);
    return(-3);
  }
  *len_return=value.size;
  strcpy(*str_return, value.data);

  dbp->close(dbp, 0);

  return(0);
} 
