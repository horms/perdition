/**********************************************************************
 * imap4_out.c                                               March 1999
 * Horms                                             horms@vergenet.net
 *
 * Functions to communicate with upstream IMAP4 server
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

#include "imap4_out.h"

/**********************************************************************
 * imap4_authenticate
 * Authenticate user with backend imap4 server
 * pre: in_fd: File descriptor to read server responses from
 *      out_fd: File descriptor to write to server on
 *      pw:     structure with username and passwd
 *      tag:    tag to use when authenticating with back-end server
 *      protocol: protocol structiure for imap4
 *      buf:    buffer to return response from server in
 *      n:      size of buf in bytes
 * post: 1: on success
 *       0: on failure
 *       -1 on error
 **********************************************************************/

int imap4_out_authenticate(
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
  char *tag_string=NULL;
  char *read_string=NULL;
  char *greeting_string=NULL;
  int status=-1;

  if((ok=token_create())==NULL){
    PERDITION_LOG(LOG_DEBUG, "imap4_out_authenticate: token_create");
    goto leave;
  }
  token_assign(ok,(PERDITION_USTRING)IMAP4_OK,strlen(IMAP4_OK),TOKEN_DONT_CARE);

  if((status=imap4_out_response(in_fd, IMAP4_UNTAGED, ok, &q, NULL, NULL))<0){
    PERDITION_LOG(LOG_DEBUG, "imap4_out_authenticate: imap4_out_response");
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
    PERDITION_LOG(LOG_DEBUG, "imap4_out_authenticate: greeting_str");
    goto leave;
  }

  if((status=strcmp(read_string, greeting_string))==0){
    PERDITION_LOG(LOG_DEBUG, "Loop detected, abandoning connection");
    goto leave;
  }

  if((tag_string=token_to_string(tag, TOKEN_NO_STRIP))==NULL){
    PERDITION_LOG(LOG_DEBUG, "imap4_in_tagged_ok: token_to_string");
    return(-1);
  }

  if(write_str(
    out_fd, 
    NULL_FLAG,
    6, 
    tag_string, 
    " LOGIN \"",
    pw->pw_name,
    "\" \"",
    pw->pw_passwd,
    "\"")<0
  ){
    PERDITION_LOG(LOG_DEBUG, "imap4_out_authenticate: imap4_write");
    status=-1;
    goto leave;
  }


  if((status=imap4_out_response(in_fd, tag_string, ok, &q, buf, n))<0){
    PERDITION_LOG(LOG_DEBUG, "imap4_out_authenticate: imap4_out_response 2");
  }
  vanessa_queue_destroy(q);

  leave:
  str_free(tag_string);
  str_free(greeting_string);
  token_unassign(ok);
  token_destroy(&ok);
  return(status);
}
  

/**********************************************************************
 * imap4_out_response
 * Compare a respnse from a server with the desired response
 * pre: in_fd: file descriptor to read from
 *      tag_string: tag expected from server
 *      desired_token: token expected from server
 *      q: resulting queue is stored here
 *      buf: buffer to read server response in to
 *      n: size of buf
 * post: 1 : tag and desired token found
 *       0: tag and desired token not found
 *       -1: on error
 **********************************************************************/

int imap4_out_response(
  const int in_fd, 
  const char *tag_string,
  const token_t *desired_token,
  vanessa_queue_t **q,
  unsigned char *buf,
  size_t *n
){
  int status;
  int tagged;
  token_t *t;
  char *server_tag_string;

  *q=NULL;
  server_tag_string=NULL;
  t=NULL;
  status=0;

  /*
   * tagged set to 0 if an untagged message is expected
   * set to non-zero otherwise
   */
  tagged=strcmp(tag_string, IMAP4_UNTAGED);

  /*Check tag*/
  while(1){
    if((*q=read_line(in_fd, buf, n))==NULL){
      PERDITION_LOG(LOG_DEBUG, "imap4_out_response: read_line");
      return(-1);
    }
  
    if((*q=vanessa_queue_pop(*q, (void **)&t))==NULL){
      PERDITION_LOG(LOG_DEBUG, "imap4_out_response: vanessa_queue_pop");
      return(-1);
    }

    if((server_tag_string=token_to_string(t, TOKEN_NO_STRIP))==NULL){
      PERDITION_LOG(LOG_DEBUG, "imap4_out_response: token_to_string");
      goto leave;
    }
    token_destroy(&t);
  
    if(tagged && !strcmp(server_tag_string, IMAP4_UNTAGED)){
      vanessa_queue_destroy(*q);
      continue;
    }
  
    if(strcmp(server_tag_string, tag_string)){
      PERDITION_LOG(LOG_DEBUG, "imap4_out_resonse: invalid tag from server");
      goto leave;
    }
  
    break;
  }

  if((*q=vanessa_queue_pop(*q, (void **)&t))==NULL){
    PERDITION_LOG(LOG_DEBUG, "imap4_out_response: vanessa_queue_pop");
    return(-1);
  }
  
  /*Check token*/
  status=token_cmp(desired_token, t);

  leave:
  token_destroy(&t);
  if(status!=1){
    vanessa_queue_destroy(*q);
    *q=NULL;
  }
  str_free(server_tag_string);
  return(status);
}
