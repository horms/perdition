/**********************************************************************
 * quit.c                                                  October 1999
 * Horms                                             horms@vergenet.net
 *
 * Protocol independent quit
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

#include "quit.h"


/**********************************************************************
 * quit
 * Send a quit request to a server
 * Pre: fd: file descriptor to write to
 * Return 0 on success
 *        -1 on error
 **********************************************************************/

int quit(const int out_fd, const int in_fd, protocol_t *protocol){
  token_t *t;
  vanessa_queue_t *q;
  int status;

  if(write_str(out_fd,
    NULL_FLAG,
    3,
    protocol->one_time_tag,
    protocol->one_time_tag==NULL?"":" ",
    protocol->quit_string
  )<0){
    PERDITION_LOG(LOG_DEBUG, "quit: write_str");
    return(-1);
  }
 
  /* We need to read the response, even though we don't
   * care about it
   */

  status=-1;

  if((t=create_token())==NULL){
    PERDITION_LOG(LOG_DEBUG, "quit: create_token");
    goto leave;
  }
  assign_token(
    t, 
    (PERDITION_USTRING) protocol->type[PROTOCOL_OK], 
    strlen(protocol->type[PROTOCOL_OK]), 
    -1
  );

  if((protocol->out_response(in_fd,protocol->one_time_tag,t,&q,NULL,NULL))<0){
    PERDITION_LOG(LOG_DEBUG, "quit: out_response");
    goto leave;
  }

  status=0;

  leave:
  unassign_token(t);
  destroy_token(&t);
  vanessa_queue_destroy(q);
  return(status);
}
