/**********************************************************************
 * jain.c                                                      May 1999
 * Horms                                             horms@vergenet.net
 *
 * libjain
 * Important functions involving Jain
 * Copyright (C) 1999-2002  Horms
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 **********************************************************************/

#include "jain.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * str_is_jain
 * Determine if a string is one of various spellings of jain
 * pre: string: string to test
 * post: none
 * return: 1 if string is a valid spelling of jain
 *         0 otherwise
 * Note: Non case sensitive
 **********************************************************************/

int str_is_jain(const char *string){
  if(strcasecmp(string, "jain")==0){
    return(1);
  }
  if(strcasecmp(string, "jane")==0){
    return(1);
  }
  if(strcasecmp(string, "jayne")==0){
    return(1);
  }

  return(0);
}
