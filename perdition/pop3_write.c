/**********************************************************************
 * pop3_write.c                                          September 1999
 * Horms                                             horms@vergenet.net
 *
 * Write POP3 protocol commands and responses
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2002  Horms
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pop3_write.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * pop3_write
 * Write a message of the form [<type> ]<string>
 * Pre: io: io_t to write to
 *      flag: flag to pass to str_write, as per str.h
 *      tag: ignored
 *      type: type of message, POP3_OK or POP3_ERR
 *            if NULL then only string is written
 *      string: mesage to display
 * Return 0 on success
 *        -1 otherwise
 **********************************************************************/
      
int pop3_write(
  io_t *io,
  const flag_t flag,
  const token_t *tag,
  const char *type, 
  const char *string
){
  const char *w_type;
  const char *w_space;
  const char *w_string;

  w_type = (type)?type:"";
  w_space = (type && string)?" ":"";
  w_string = (string)?string:"";

  if(str_write(io, flag, 3, "%s%s%s", w_type, w_space, w_string)<0){
    VANESSA_LOGGER_DEBUG("str_write");
    return(-1);
  }   
  return(0);
}   
