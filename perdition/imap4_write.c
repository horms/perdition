/**********************************************************************
 * imap4_write .c                                        September 1999
 * Horms                                             horms@vergenet.net
 *
 * Subroutines to write IMAP4 protocol output
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

#include "imap4_write.h"

/**********************************************************************
 * imap4_write
 * Display an message of the form [<tag> <type> ]<string>
 * Pre: fd: file descriptor to write to
 *      flag: flag to pass to write_str as per str.h
 *      tag: tag to display
 *           if NULL, then IMAP4_UNTAGED is used
 *      type: type of message, IMAP4_OK, IMAP4_NO or IMAP4_BAD
 *            if NULL then only string is written, no tag and no type
 *      string: mesage to display
 * Return 0 on success
 *        -1 otherwise
 **********************************************************************/

int imap4_write(
  const int fd, 
  const flag_t flag,
  const token_t *tag, 
  const char *type, 
  const char *string
){
  char *tag_string=NULL;
  int free_tag_string=0;

  if(type==NULL){
    if(write_str(fd, flag, 1, string)<0){
      PERDITION_LOG(LOG_DEBUG, "imap4_write: write_strings");
      return(-1);
    }
  }
  else {
    if(tag==NULL){
      tag_string=IMAP4_UNTAGED;
    }
    else {
      if((tag_string=token_to_string(tag))==NULL){
        PERDITION_LOG(LOG_DEBUG, "imap4_in_tagged_ok: token_to_string");
        return(-1);
      }
      free_tag_string=1;
    }
    if(write_str(fd, flag, 5, tag_string, " ", type, " ", string)<0){
      PERDITION_LOG(LOG_DEBUG, "imap4_write: write_strings");
      return(-1);
    }
  }
  
  if(free_tag_string){
    str_free(tag_string);
  }
  return(0);
}
