/**********************************************************************
 * str.h                                                 September 1999
 * Horms                                             horms@vergenet.net
 *
 * Various string handling functions
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

#ifndef STRBERT
#define STRBERT

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/uio.h>
#include <vanessa_socket.h>

#include "perdition_types.h"
#include "io.h"

#define STR_NULL "(null)"

/*Flags for str_write */
#define WRITE_STR_NO_CLLF     0x1     /*Append a CLLF*/
#define STR_WRITE_BUF_LEN     MAX_LINE_LENGTH


/**********************************************************************
 * strn_to_str
 * pre: string:  source string
 *      n:    bytes from string to put in allocated string
 * post: a new string is allocated to hold n bytes of string and 
 *       a teminating '\0'
 * return: NULL on error
 *         allocated string otherwise
 *
 * Not 8 bit clean
 **********************************************************************/

char *strn_to_str(const char *string, const size_t n);


/**********************************************************************
 * str_write
 * write strings to fd by puting them into tokens and
 * printing the tokens
 * if !(flag&WRITE_STR_NO_CLLF)
 *   append a CRLF to the output (intput strings should not end in a CRLF)
 * 
 * pre: io: io_t to write to
 *      flag: If WRITE_STR_NO_CLLF then CLLF is appended to output
 *      fmt: format for output, as per vsnprintf()
 *      ...: strings
 * post strings are printed to fd
 * return: -1 on error
 *         0 otherwise
 *
 * Not 8 bit clean
 **********************************************************************/

int str_write(io_t *io, const flag_t flag, const char *fmt, ...);


/**********************************************************************
 * str_cat
 * 
 * pre: nostring: number of strings
 *      ...: strings
 * post: a string is allocated to store the concatenation of the strings
 * return: NULL on error
 *         concatenated string otherwise
 *
 * Not 8 bit clean
 **********************************************************************/

char *str_cat(const int nostring, ...);


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


/**********************************************************************
 * str_basename
 * 
 * pre: filename: name of file to find basename of
 * post: basename of filename is returned
 * return: NULL if filename is NULL
 *         pointer within filename pointing to basename of filename
 *
 * Not 8 bit clean
 **********************************************************************/

const char *str_basename(const char *filename);

#endif
