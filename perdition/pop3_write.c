/**********************************************************************
 * pop3_write.c                                          September 1999
 * Horms                                             horms@vergenet.net
 *
 * Write POP3 protocol commands and responses
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

#include "pop3_write.h"

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
  if(type==NULL){
    if(str_write(io, flag, "%s", string)<0){
      PERDITION_DEBUG("str_write");
      return(-1);
    }   
  }
  else {
    if(str_write(io, flag, "%s %s", type, string)<0){
      PERDITION_DEBUG("str_write");
      return(-1);
    }   
  }
  return(0);
}   
