/**********************************************************************
 * quit.c                                                  October 1999
 * Horms                                             horms@vergenet.net
 *
 * Protocol independent quit
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

#include "quit.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif



/**********************************************************************
 * quit
 * Send a quit request to a server
 * Pre: io: io_t to write to
 * Return 0 on success
 *        -1 on error
 **********************************************************************/

int quit(io_t *io, const protocol_t *protocol){
  token_t *t;
  vanessa_queue_t *q;
  int status;

  if(str_write(io, 
      NULL_FLAG, 
      3, 
      "%s%s%s", 
      protocol->one_time_tag==NULL?"":protocol->one_time_tag,
      protocol->one_time_tag==NULL?"":" ", 
      protocol->quit_string
    )<0){
    PERDITION_DEBUG("str_write");
    return(-1);
  }
 
  /* We need to read the response, even though we don't
   * care about it
   */

  status=-1;

  if((t=token_create())==NULL){
    PERDITION_DEBUG("token_create");
    goto leave;
  }
  token_assign(
    t, 
    (PERDITION_USTRING) protocol->type[PROTOCOL_OK], 
    strlen(protocol->type[PROTOCOL_OK]), 
    TOKEN_DONT_CARE
  );

  if((protocol->out_response(io, protocol->one_time_tag, t, &q, NULL, NULL))<0){
    PERDITION_DEBUG("out_response");
    goto leave;
  }

  status=0;

  leave:
  token_unassign(t);
  token_destroy(&t);
  vanessa_queue_destroy(q);
  return(status);
}
