/**********************************************************************
 * pop3.c                                                September 1999
 * Horms                                             horms@vergenet.net
 *
 * Functions to communicate with upstream POP3 server
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

#include "pop3_out.h"

/**********************************************************************
 * pop3_out_authenticate
 * Authenticate user with backend pop3 server
 * pre: in_fd: File descriptor to read server responses from
 *      out_fd: File descriptor to write to server on
 *      pw:     structure with username and passwd
 *      tag:    ignored 
 *      protocol: protocol structure for POP3
 *      buf: buffer to return server response in
 *      n: size of buffer
 * post: 1: on success
 *       0: on failure
 *       -1 on error
 **********************************************************************/

int pop3_out_authenticate(
  const int in_fd, 
  const int out_fd, 
  const struct passwd *pw,
  const token_t *tag,
  const protocol_t *protocol,
  unsigned char *buf,
  size_t *n
){
  token_t *ok;
  vanessa_queue_t *q;
  char *read_string=NULL;
  char *greeting_string=NULL;
  int status=-1;

  if((ok=create_token())==NULL){
    PERDITION_LOG(LOG_DEBUG, "pop3_out_get_pw: create_token");
    goto leave;
  }
  assign_token(ok, (PERDITION_USTRING) POP3_OK, strlen(POP3_OK), -1);

  if((status=pop3_out_response(in_fd, NULL, ok, &q, NULL, NULL))<0){
    PERDITION_LOG(LOG_DEBUG, "pop3_out_authenticate: pop3_out_response 1");
    goto leave;
  }
  else if(!status){
    status=0;
    goto leave;
  }

  if((read_string=queue_to_string(q))==NULL){
    PERDITION_LOG(LOG_DEBUG, "pop3_out_authenticate: queueo_string");
    status=-1;
    goto leave;
  }

  if((greeting_string=greeting_str(
    greeting_string, 
    protocol, 
    GREETING_ADD_NODENAME
  ))==NULL){
    PERDITION_LOG(LOG_DEBUG, "pop3_out_authenticate: greeting_str");
    status=-1;
    goto leave;
  }

  if((status=strcmp(read_string, greeting_string))==0){
    PERDITION_LOG(LOG_DEBUG, "Loop detected, abandoning connection");
    goto leave;
  }

  if(pop3_write(out_fd, NULL_FLAG, NULL, "USER", pw->pw_name)<0){
    PERDITION_LOG(LOG_DEBUG, "pop3_out_get_pw: pop3_write");
    goto leave;
  }

  if((status=pop3_out_response(in_fd, NULL, ok, &q, NULL, NULL))<0){
    PERDITION_LOG(LOG_DEBUG, "pop3_out_authenticate: pop3_out_response 2");
    goto leave;
  }
  else if(!status){
    status=0;
    goto leave;
  }

  vanessa_queue_destroy(q);

  if(pop3_write(out_fd, NULL_FLAG, NULL, "PASS", pw->pw_passwd)<0){
    PERDITION_LOG(LOG_DEBUG, "pop3_out_get_pw: pop3_write");
    return(-1);
  }

  if((status=pop3_out_response(in_fd, NULL, ok, &q, buf, n))<0){
    PERDITION_LOG(LOG_DEBUG, "pop3_out_authenticate: pop3_out_response 3");
  }
  vanessa_queue_destroy(q);

  leave:
  str_free(read_string);
  str_free(greeting_string);
  unassign_token(ok);
  destroy_token(&ok);
  return(status);
}
  

/**********************************************************************
 * pop3_out_response
 * Compare a respnse from a server with the desired response
 * pre: in_fd: file descriptor to read from
 *      out_fd: file descriptor to write to
 *      tag_string: ignored
 *      desired_token: token expected from server
 * post: 1 : tag and desired token found
 *       0: tag and desired token not found
 *       -1: on error
 **********************************************************************/


int pop3_out_response(
  int in_fd, 
  const char *tag_string,
  const token_t *desired_token,
  vanessa_queue_t **q,
  unsigned char *buf,
  size_t *n
){
  int status;
  token_t *t;

  if((*q=read_line(in_fd, buf, n))==NULL){
    PERDITION_LOG(LOG_DEBUG, "pop3_out_response: read_line");
    return(-1);
  }
  if((*q=vanessa_queue_pop(*q, (void *)&t))==NULL){
    PERDITION_LOG(LOG_DEBUG, "pop3_out_response: vanessa_queue_pop");
    return(-1);
  }

  status=token_cmp(desired_token, t);
  
  destroy_token(&t);
  return(status);
}
