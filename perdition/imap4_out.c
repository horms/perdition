/**********************************************************************
 * imap4_out.c                                               March 1999
 * Horms                                             horms@vergenet.net
 *
 * Functions to communicate with upstream IMAP4 server
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

#include "imap4_out.h"
#include "imap4_tag.h"
#include "options.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * imap4_out_get_capability
 * Read a capability from the server
 * pre: io: io to use to communicate to the server
 *      ok: token containing IMAP4_OK.
 *          Used to compare results from the server
 *      tag: tag to use when communicating with the server
 *           may be incremented using imap4_tag_inc()
 *      q: queue of data read from the server
 *         will be modified
 *      buf: buffer to read server response in to
 *      buf_n: size of buf in bytes
 *      str: capability to find as a string
 *      str_n: length of str in bytes (not including trailing '\0',
 *             which may be omitted)
 * post: CAPABILITY command is sent to the server
 *       the result is checked to see if str is present
 * return: 0: if str is not found
 *         1: if str is found
 *        -1: on error
 **********************************************************************/

static int imap4_out_get_capability(io_t *io, token_t *ok, token_t *tag, 
		vanessa_queue_t **q, char *buf, size_t *buf_n,
		char *str, size_t str_n)
{
	int status = -1;
	int found = 0;
	token_t *t;
	token_t *capability;
	char *tag_string = NULL;

	if((capability=token_create())==NULL){
	    	VANESSA_LOGGER_DEBUG("token_create");
		goto leave;
	}

	if((tag_string=token_to_string(tag, TOKEN_NO_STRIP))==NULL){
		VANESSA_LOGGER_DEBUG("token_to_string");
		goto leave;
	}
	if(str_write(io, NULL_FLAG, 2, "%s %s", tag_string, 
	      			IMAP4_CMD_CAPABILLTY)<0){
		VANESSA_LOGGER_DEBUG("str_write");
		goto leave;
	}
	token_assign(capability, IMAP4_CMD_CAPABILLTY, 
			strlen(IMAP4_CMD_CAPABILLTY), 
	      		TOKEN_NONE);
	status=imap4_out_response(io, IMAP4_UNTAGED, capability, q, buf, 
			buf_n);
	if(status<0) {
		VANESSA_LOGGER_DEBUG("imap4_out_response 2");
		goto leave;
	}

	token_assign(capability, str, str_n, TOKEN_DONT_CARE);
	while(vanessa_queue_length(*q)) {
		if((*q=vanessa_queue_pop(*q, (void **)&t))==NULL){
			VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
			goto leave;
		}
		if(!found && token_cmp(t, capability)) {
			found = 1;
		}
		if(token_is_eol(t)) {
			break;
		}
		token_destroy(&t);
	}
	token_destroy(&t);
	
	if(imap4_out_response(io, tag_string, ok, q, buf, buf_n) < 0) {
		VANESSA_LOGGER_DEBUG("imap4_out_response 3");
		goto leave;
	}
	imap4_tag_inc(tag);

	status = found;
leave:
	token_unassign(capability);
  	token_destroy(&capability);
	token_destroy(&t);
	if(tag_string) {
		free(tag_string);
	}
	return(status);
}

	
	
/**********************************************************************
 * imap4_out_setup
 * Begin interaction with real server by checking that
 * the connection is ok and doing TLS if neccessary.
 * pre: io: io_t to read from and write to
 *      pw:     structure with username and passwd
 *      tag:    tag to use when authenticating with back-end server
 *      protocol: protocol structiure for imap4
 * post: Read the greeting string from the server
 *       If tls_outgoing is set issue the CAPABILITY command and check
 *       for the STARTTLS capability.
 * return: Logical or of PROTOCOL_S_OK and
 *         PROTOCOL_S_STARTTLS if ssl_mode is tls_outgoing (or tls_all)
 *         and the STARTTLS capability was reported by the server
 *       0: on failure
 *       -1 on error
 **********************************************************************/

int imap4_out_setup(
  io_t *io,
  const struct passwd *pw,
  token_t *tag,
  const protocol_t *protocol
){
  token_t *ok = NULL;
  token_t *t = NULL;
  token_t *check_t = NULL;
  vanessa_queue_t *q = NULL;
  char *read_string = NULL;
  char *greeting_string=NULL;
  char *tag_string=NULL;
  int status=-1;
  int protocol_status = PROTOCOL_S_OK;
  int capability_status;
  char buf[MAX_LINE_LENGTH];
  size_t n = MAX_LINE_LENGTH;

  extern options_t opt;

  if((check_t=token_create())==NULL){
    VANESSA_LOGGER_DEBUG("token_create 1");
    goto leave;
  }
  if((ok=token_create())==NULL){
    VANESSA_LOGGER_DEBUG("token_create 2");
    goto leave;
  }
  token_assign(ok, (PERDITION_USTRING)IMAP4_OK, strlen(IMAP4_OK),
      TOKEN_DONT_CARE);

  if((status=imap4_out_response(io, IMAP4_UNTAGED, ok, &q, NULL, NULL))<0){
    VANESSA_LOGGER_DEBUG("imap4_out_response 1");
    goto leave;
  }
  else if(!status){
    status=0;
    goto leave;
  }

  /* N.B: Calling queue_to_string() destroys q */
  if((read_string=queue_to_string(q))==NULL){
    VANESSA_LOGGER_DEBUG("queue_to_string");
    status=-1;
    goto leave;
  }
  q = NULL;

  if((greeting_string=greeting_str(
    greeting_string, 
    protocol,
    GREETING_ADD_NODENAME
  ))==NULL){
    VANESSA_LOGGER_DEBUG("greeting_str");
    goto leave;
  }

  if((status=strcmp(read_string, greeting_string))==0){
    VANESSA_LOGGER_DEBUG("Loop detected, abandoning connection");
    goto leave;
  }

  /* Ok to go */

#ifdef WITH_SSL_SUPPORT
  if(!(opt.ssl_mode & SSL_MODE_TLS_OUTGOING)) {
    goto ok;
  }

  capability_status = imap4_out_get_capability(io, ok, tag, &q, buf, &n, 
        IMAP4_CMD_STARTTLS, strlen(IMAP4_CMD_STARTTLS));
  if(capability_status < 0) {
    VANESSA_LOGGER_DEBUG("imap4_out_get_capability");
    goto leave;
  }

  if(capability_status) {
    protocol_status |= PROTOCOL_S_STARTTLS;
    if((tag_string=token_to_string(tag, TOKEN_NO_STRIP))==NULL){
      VANESSA_LOGGER_DEBUG("token_to_string 3");
      goto leave;
    }
    if(str_write(io, NULL_FLAG, 2, "%s %s", tag_string, IMAP4_CMD_STARTTLS)<0){
      VANESSA_LOGGER_DEBUG("str_write 2");
      goto leave;
    }
    if((status=imap4_out_response(io, tag_string, ok, &q, buf, &n))<0) {
      VANESSA_LOGGER_DEBUG("imap4_out_response 4");
      goto leave;
    }
    free(tag_string);
    tag_string = NULL;
    imap4_tag_inc(tag);
  }
#endif /* WITH_SSL_SUPPORT */

ok:
  status=protocol_status;
leave:
  str_free(greeting_string);
  token_unassign(check_t);
  token_destroy(&check_t);
  token_unassign(ok);
  token_destroy(&ok);
  token_destroy(&t);
  if(q) {
    vanessa_queue_destroy(q);
  }
  if(tag_string) {
    free(tag_string);
  }
  return(status);

  /* Stop compiler from complaining */
  capability_status = 0;
}
  

/**********************************************************************
 * imap4_authenticate
 * Authenticate user with backend imap4 server
 * You should call imap4_setup() first
 * pre: io: io_t to read from and write to
 *      pw:     structure with username and passwd
 *      tag:    tag to use when authenticating with back-end server
 *      protocol: protocol structiure for imap4
 *      buf:    buffer to return response from server in
 *      n:      size of buf in bytes
 * post: The CAPABILITY command is sent to the server and the result is read
 *       If the LOGINDISABLED capability is set porocessing stops
 *       Otherwise the LOGIN command is sent and the result is checked
 * return: 2: if the server has the LOGINDISABLED capability set
 *         1: on success
 *         0: on failure
 *        -1: on error
 **********************************************************************/

int imap4_out_authenticate(
  io_t *io,
  const struct passwd *pw,
  token_t *tag,
  const protocol_t *protocol,
  unsigned char *buf,
  size_t *n
){
  token_t *ok;
  vanessa_queue_t *q;
  char *tag_string=NULL;
  int status=-1;
  int capability_status;

  if((ok=token_create())==NULL){
    VANESSA_LOGGER_DEBUG("token_create");
    goto leave;
  }
  token_assign(ok, (PERDITION_USTRING)IMAP4_OK, strlen(IMAP4_OK),
      TOKEN_DONT_CARE);

  capability_status = imap4_out_get_capability(io, ok, tag, &q, buf, n, 
        IMAP4_CMD_LOGINDISABLED, strlen(IMAP4_CMD_LOGINDISABLED));
  if(capability_status < 0) {
    VANESSA_LOGGER_DEBUG("imap4_out_get_capability");
    goto leave;
  }
  if(capability_status) {
    status = 2;
    goto leave;
  }

  if((tag_string=token_to_string(tag, TOKEN_NO_STRIP))==NULL){
    VANESSA_LOGGER_DEBUG("token_to_string");
    goto leave;
  }

  if(str_write(io, NULL_FLAG, 2, "%s " IMAP4_CMD_LOGIN " {%d}", tag_string, 
      strlen(pw->pw_name))<0){
    VANESSA_LOGGER_DEBUG("str_write 1");
    status=-1;
    goto leave;
  }
  if((status=imap4_out_response(io, IMAP4_CONT_TAG, ok, &q, buf, n))<0){
    VANESSA_LOGGER_DEBUG("imap4_out_response 2");
  }

  if(str_write(io, NULL_FLAG, 2, "%s {%d}", pw->pw_name, 
      strlen(pw->pw_passwd))<0){
    VANESSA_LOGGER_DEBUG("str_write 2");
    status=-1;
    goto leave;
  }
  if((status=imap4_out_response(io, IMAP4_CONT_TAG, ok, &q, buf, n))<0){
    VANESSA_LOGGER_DEBUG("imap4_out_response 2");
  }

  if(str_write(io, NULL_FLAG, 1, "%s", pw->pw_passwd)<0){
    VANESSA_LOGGER_DEBUG("str_write 3");
    status=-1;
    goto leave;
  }
  if((status=imap4_out_response(io, tag_string, ok, &q, buf, n))<0){
    VANESSA_LOGGER_DEBUG("imap4_out_response 3");
  }
  
  vanessa_queue_destroy(q);

  leave:
  imap4_tag_inc(tag);
  str_free(tag_string);
  token_unassign(ok);
  token_destroy(&ok);
  return(status);
}
  

/**********************************************************************
 * imap4_out_response
 * Compare a respnse from a server with the desired response
 * pre: io: io_t to read from
 *      tag_string: tag expected from server
 *      desired_token: token expected from server
 *      q: resulting queue is stored here
 *      buf: buffer to read server response in to
 *      n: size of buf
 * post: Response is read from the server
 * return: 1 : tag and desired token found
 *         0: tag and desired token not found
 *         -1: on error
 **********************************************************************/

int imap4_out_response(
  io_t *io,
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
  status=-1;

  /*
   * tagged set to 0 if an untagged message is expected
   * set to non-zero otherwise
   */
  tagged=strcmp(tag_string, IMAP4_UNTAGED);

  /*Check tag*/
  while(1){
    *q=read_line(io, buf, n, TOKEN_IMAP4, 0, PERDITION_LOG_STR_REAL);
    if(!*q){
      VANESSA_LOGGER_DEBUG("read_line");
      return(-1);
    }
  
    if((*q=vanessa_queue_pop(*q, (void **)&t))==NULL){
      VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
      return(-1);
    }

    if((server_tag_string=token_to_string(t, TOKEN_NO_STRIP))==NULL){
      VANESSA_LOGGER_DEBUG("token_to_string");
      goto leave;
    }
    token_destroy(&t);
  
    if(tagged && !strcmp(server_tag_string, IMAP4_UNTAGED)){
      vanessa_queue_destroy(*q);
      continue;
    }
  
    if(strcmp(server_tag_string, tag_string)){
      VANESSA_LOGGER_DEBUG_UNSAFE("invalid tag from server "
		      "got:\"%s\" expected:\"%s\"",
		      server_tag_string, tag_string);
      goto leave;
    }
  
    break;
  }

  if((*q=vanessa_queue_pop(*q, (void **)&t))==NULL){
    VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
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


