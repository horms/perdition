/**********************************************************************
 * str.h                                                 September 1999
 * Horms                                             horms@vergenet.net
 *
 * Various string handling functions
 *
 * perdition
 * Mail retreival proxy server
 * Copyright (C) 1999  Horms
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

#ifndef STRBERT
#define STRBERT

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/uio.h>

#include "log.h"
#include "perdition_types.h"

#define STR_NULL "(null)"

/*Flags for write_str */
#define WRITE_STR_NO_CLLF     0x1     /*Append a CLLF*/

int vanessa_socket_str_is_digigt(const char *str);

char *strn_to_str(const char *string, const size_t n);

int write_str(const int fd, flag_t flag, int nostring, ...);

char *cat_str(int nostring, ...);

/**********************************************************************
 * str_free
 * Free a string if it is not NULL
 * pre: string: string to free
 * post: string is freed if it is not NULL
 * return: none
 *
 * Not 8 bit clean
 **********************************************************************/

#define str_free(string) \
  if(string!=NULL){ \
    free(string); \
    string=NULL; \
  }


/**********************************************************************
 * str_null_safe
 * return a pinter to a sane string if string is NULL
 * So we can print NULL strings safely
 * pre: string: string to test
 * return: string is if it is not NULL
 *         STR_NULL otherwise
 *
 * 8 bit clean
 **********************************************************************/

#define str_null_safe(string) \
  (string==NULL)?STR_NULL:string


#endif
