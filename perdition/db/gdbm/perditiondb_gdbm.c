/**********************************************************************
 * perditiondb_gdbm.c                                     December 1999
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

#include "perditiondb_gdbm.h"


/**********************************************************************
 * dbserver_get
 * Read the server (value) from a gdbm map given the user (key)
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
  GDBM_FILE dbf;
  datum key;
  datum content;
  
  key.dptr=key_str;
  key.dsize=strlen(key_str);
  if((dbf=gdbm_open(
      (options_str==NULL)?PERDITIONDB_GDBM_DEFAULT_MAPNAME:options_str,
      0, 
      GDBM_READER, 
      0644, 
      0
    ))==NULL){
    return(-1);
  }
  content=gdbm_fetch(dbf,key);
  gdbm_close(dbf);
  if(content.dptr==NULL){
     return(-2);
  }
  *str_return=content.dptr;
  *len_return=content.dsize;
  return(0);
} 
