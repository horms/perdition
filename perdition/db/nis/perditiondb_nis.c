/**********************************************************************
 * perditiondb_nis.c                                       October 2000
 * Nathan Neulinger                                       nneul@umr.edu
 *
 * Access a nis/yp database map
 *
 * perdition
 * Mail retreival proxy server, NIS support
 * Copyright (C) 2000 Nathan Neulinge and Horms
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


#include "perditiondb_nis.h"

/**********************************************************************
 * dbserver_get
 * Read the server (value) from a nis map given the user (key)
 * pre: key_str: Key as a null terminated string
 *      options_str: Options string. 
 *                   Ignored if NULL
 *                   Used as the map to open otherwise
 *      str_return: value is returned here
 *      len_return: length of value is returned here
 * post: The str_key is looked up in the gdbm map and the
 *       corresponding value is returned in str_return and len_return.
 * return:  0 on sucess
 *         -1 on file access error
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

/*****
      int yp_match(
           char *indomain,
           char *inmap,
           char *inkey,
           int inkeylen,
           char **outval,
           int *outvallen
      );
*****/


int dbserver_get(
  char *key_str, 
  char *options_str,
  char **str_return, 
  int  *len_return
){
  int res;
  char *domain = NULL;
  char *map = NULL;

  res = yp_get_default_domain(&domain);
  if ( res ) {
    PERDITION_LOG(LOG_DEBUG, 
      "perditiondb_nis: yp_get_default_domain: %s (%d)", yperr_string(res), 
      res);
    return(-1);
  }

  map = (options_str==NULL)?PERDITIONDB_NIS_DEFAULT_MAPNAME:options_str;

  res = yp_match(domain, 
	map,
	key_str,
	strlen(key_str),
	str_return,
	len_return);

  if ( res == YPERR_KEY ) {
    PERDITION_LOG(LOG_DEBUG, "perditiondb_nis: yp_match: %s (%d)", 
	yperr_string(res), res);
    return(-2);
  } else if ( res ) {
    PERDITION_LOG(LOG_DEBUG, "perditiondb_nis: yp_match: %s (%d)", 
	yperr_string(res), res);
    return(-2);
  };
  
  return(0);
} 
