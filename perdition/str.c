/**********************************************************************
 * str.c                                                    August 1999
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

#include "str.h"
#include "options.h"


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

char *strn_to_str(const char *string, const size_t n){
  char *dest;

  if((dest=(char *)malloc(n+1))==NULL){
    PERDITION_DEBUG_ERRNO("malloc");
    return(NULL);
  }
  strncpy(dest, string, n);
  *(dest+n)='\0';

  return(dest);
}


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

static char __str_write_buf[STR_WRITE_BUF_LEN];

int str_write(io_t *io, const flag_t flag, const char *fmt, ...){
  va_list ap;
  int bytes=0;

  extern options_t opt;
  extern vanessa_logger_t *perdition_vl;

  va_start(ap, fmt);
  if((bytes=vsnprintf(__str_write_buf, STR_WRITE_BUF_LEN-2, fmt, ap))<0){
    PERDITION_DEBUG_ERRNO("vsnprintf");
  }
  va_end(ap);

  /* Add carriage return,newline to output. */
  if(!(flag&WRITE_STR_NO_CLLF)){
    *(__str_write_buf+bytes++) = '\r';
    *(__str_write_buf+bytes++) = '\n';
  }

  if(opt.connection_logging){
    vanessa_logger_log(perdition_vl, LOG_DEBUG, "%s", __str_write_buf);
  }
    
  /* Attempt one write system call and return an error if it
     doesn't write all the bytes. */
  if(io_write(io, __str_write_buf, bytes) != bytes){
    PERDITION_DEBUG_ERRNO("write");
    return(-1);
  }

  return(0);
}


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

char *str_cat(const int nostring, ...){
  va_list ap;
  char **string;
  char **current_string;
  char *dest;
  int length;
  int i;

  if(nostring<1){
    return(NULL);
  }

  if((string=(char **)malloc(sizeof(char *)*nostring))==NULL){
    PERDITION_DEBUG_ERRNO("malloc 1");
    return(NULL);
  }

  current_string=string;
  length=1;

  va_start(ap, nostring);
  for(i=0;i<nostring;i++){
    *current_string=va_arg(ap, char*);
    if(*current_string==NULL){
      PERDITION_DEBUG("null string");
      free(string);
      return(NULL);
    }
    length+=strlen(*current_string);
    current_string++;
  }
  va_end(ap);

  if((dest=(char *)malloc(sizeof(char)*length))==NULL){
    PERDITION_DEBUG_ERRNO("malloc 2");
    free(string);
    return(NULL);
  }

  current_string=string;
  strcpy(dest, *current_string++);
  for(i=1;i<nostring;i++){
    strcat(dest, *current_string++);
  }

  free(string);

  return(dest);
}

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

const char *str_basename(const char *filename){
    char *result;

    if(filename==NULL){
      return(NULL);
    }
    
    result=strrchr(filename, '/');

    return((result==NULL)?filename:result+1);
}
