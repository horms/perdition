/**********************************************************************
 * imap4_out.c                                               March 1999
 * Horms                                             horms@verge.net.au
 *
 * Functions to communicate with upstream IMAP4 server
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2005  Horms
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 **********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "auth.h"
#include "imap4.h"
#include "imap4_out.h"
#include "imap4_tag.h"
#include "options.h"
#include "perdition_globals.h"
#include "unused.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * imap4_out_get_capability
 * Read a capability from the server
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
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

static int imap4_out_get_capability(io_t *rs_io, io_t *eu_io, token_t *ok, 
				    token_t *tag, vanessa_queue_t **q,
				    char *buf, size_t *buf_n, char *str,
				    size_t str_n)
{
	int status = -1;
	int found = 0;
	token_t *t = NULL;
	token_t *capability = NULL;
	size_t new_buf_n = 0;

	if(buf) {
		memset(buf, 0, *buf_n);
	}
  	if(buf_n) { 
		new_buf_n = *buf_n; 
	}

	if((capability=token_create())==NULL){
	    	VANESSA_LOGGER_DEBUG("token_create");
		goto leave;
	}

	if (imap4_write_str(rs_io, NULL_FLAG, tag, IMAP4_CMD_CAPABILITY,
			    NULL) <0 ) {
		VANESSA_LOGGER_DEBUG("imap4_write_str");
		goto leave;
	}
	token_assign(capability, IMAP4_CMD_CAPABILITY,
			strlen(IMAP4_CMD_CAPABILITY), 
	      		TOKEN_NONE);
  	if(buf_n) { new_buf_n = *buf_n; }
	status=imap4_out_response(rs_io, eu_io, NULL, capability, q, 
				  buf, &new_buf_n);
	if(status<0) {
		VANESSA_LOGGER_DEBUG("imap4_out_response capability untagged");
		goto leave;
	}
	if(!status) {
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
	
  	if(buf_n) { new_buf_n = *buf_n; }
	if (imap4_out_response(rs_io, eu_io, tag, ok, q, buf, &new_buf_n) < 0) {
		VANESSA_LOGGER_DEBUG("imap4_out_response capability ok");
		goto leave;
	}
	imap4_tag_inc(tag);

	status = found;
leave:
	if(buf) {
		char *tag_offset;
		tag_offset = strchr((char *)buf, ' ');
		if(tag_offset) {
			memmove(buf, tag_offset + 1, 
					strlen(tag_offset + 1) + 1);
		}
	}
	if(buf_n) {
		*buf_n = new_buf_n;
	}
	token_unassign(capability);
  	token_destroy(&capability);
	token_destroy(&t);
	return(status);
}

	
	
/**********************************************************************
 * imap4_out_setup
 * Begin interaction with real server by checking that
 * the connection is ok and doing TLS if necessary.
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      auth:   structure with username and passwd
 *      tag:    tag to use when authenticating with back-end server
 * post: Read the greeting string from the server
 *       If tls_outgoing is set issue the CAPABILITY command and check
 *       for the STARTTLS capability.
 * return:
 *       PROTOCOL_S_OK: success, don't use STARTTLS
 *       PROTOCOL_S_OK|PROTOCOL_S_STARTTLS: success, use STARTTLS
 *       0: on failure
 *       -1 on error
 **********************************************************************/

int imap4_out_setup(io_t *rs_io, io_t *eu_io,
		    const struct auth *UNUSED(auth), token_t *tag)
{
  token_t *ok = NULL;
  token_t *t = NULL;
  vanessa_queue_t *q = NULL;
  char *read_string = NULL;
  char *greeting_string=NULL;
  int status=-1;
  int protocol_status = PROTOCOL_S_OK;
  int capability_status;
  char buf[MAX_LINE_LENGTH];
  size_t n = MAX_LINE_LENGTH;

  if((ok=token_create())==NULL){
    VANESSA_LOGGER_DEBUG("token_create");
    goto leave;
  }
  token_assign(ok, IMAP4_OK, strlen(IMAP4_OK),
      TOKEN_DONT_CARE);

  if((status=imap4_out_response(rs_io, eu_io, NULL, ok, &q, NULL, NULL))<0){
    VANESSA_LOGGER_DEBUG("imap4_out_response greeting");
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

  greeting_string = imap4_greeting_str(GREETING_ADD_NODENAME);
  if(!greeting_string){
    VANESSA_LOGGER_DEBUG("greeting_str");
    goto leave;
  }

  if((status=strcmp(read_string, greeting_string))==0){
    VANESSA_LOGGER_DEBUG("Loop detected, abandoning connection");
    goto leave;
  }

#ifdef WITH_SSL_SUPPORT
  if(!(opt.ssl_mode & SSL_MODE_TLS_OUTGOING)) {
    goto ok;
  }

  capability_status = imap4_out_get_capability(rs_io, eu_io, ok, tag, &q, 
					       buf, &n, IMAP4_CMD_STARTTLS,
					       strlen(IMAP4_CMD_STARTTLS));
  if(capability_status < 0) {
    VANESSA_LOGGER_DEBUG("imap4_out_get_capability");
    goto leave;
  }
  if(!capability_status) {
	  if (!(opt.ssl_mode & SSL_MODE_TLS_OUTGOING_FORCE)) {
		  VANESSA_LOGGER_DEBUG_RAW("tls_outgoing is set, "
				  "but the real-server does not have the "
				  "STARTTLS capability, "
	  			  "connection will not be encrypted");
	    	  goto ok;
	  }
	  VANESSA_LOGGER_DEBUG_RAW("tls_outgoing_force is set, but the "
				   "real-server does not have the STARTTLS"
				   "capability, closing connection");
      	  status = 0;
	  goto leave;
  }

  protocol_status |= PROTOCOL_S_STARTTLS;
  if (imap4_write_str(rs_io, NULL_FLAG, tag, IMAP4_CMD_STARTTLS, NULL) < 0 ){
	  VANESSA_LOGGER_DEBUG("imap4_write_str starttls");
	  goto leave;
  }
  status = imap4_out_response(rs_io, eu_io, tag, ok, &q, buf, &n);
  if (status < 0) {
     	  VANESSA_LOGGER_DEBUG("imap4_out_response starttls");
	  goto leave;
  }
  imap4_tag_inc(tag);
#endif /* WITH_SSL_SUPPORT */

ok:
  status=protocol_status;
leave:
  str_free(greeting_string);
  token_unassign(ok);
  token_destroy(&ok);
  token_destroy(&t);
  if(q) {
    vanessa_queue_destroy(q);
  }
  return(status);
}
  

/**********************************************************************
 * imap4_authenticate
 * Authenticate user with back-end imap4 server
 * You should call imap4_setup() first
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      auth:   structure with username and passwd
 *      tag:    tag to use when authenticating with back-end server
 *      protocol: protocol structure for imap4
 *      buf:    buffer to return response from server in
 *      n:      size of buf in bytes
 * post: The CAPABILITY command is sent to the server and the result is read
 *       If the LOGINDISABLED capability is set processing stops
 *       Otherwise the LOGIN command is sent and the result is checked
 * return: 2: if the server has the LOGINDISABLED capability set
 *         1: on success
 *         0: on failure
 *        -1: on error
 **********************************************************************/

int imap4_out_authenticate(io_t *rs_io, io_t *eu_io, const struct auth *auth,
			   token_t *tag, const protocol_t *UNUSED(protocol),
			   char *buf, size_t *n)
{
  token_t *ok=NULL;
  token_t *cont=NULL;
  vanessa_queue_t *q;
  int status=-1;
  int capability_status;
  size_t new_n = 0;

  if((ok=token_create())==NULL){
    VANESSA_LOGGER_DEBUG("token_create");
    goto leave;
  }
  token_assign(ok, IMAP4_OK, strlen(IMAP4_OK), TOKEN_DONT_CARE);

  if((cont=token_create())==NULL){
    VANESSA_LOGGER_DEBUG("token_create");
    goto leave;
  }
  token_assign(cont, IMAP4_CONT_TAG, strlen(IMAP4_CONT_TAG), TOKEN_DONT_CARE);

  if(n) { new_n = *n; }
  capability_status = imap4_out_get_capability(rs_io, eu_io, ok, tag, &q, 
		  buf, &new_n, IMAP4_CMD_LOGINDISABLED, 
		  strlen(IMAP4_CMD_LOGINDISABLED));
  if(capability_status < 0) {
	  VANESSA_LOGGER_DEBUG("imap4_out_get_capability");
	  goto leave;
  }
  if(capability_status) {
	  VANESSA_LOGGER_DEBUG_RAW("real-server has LOGINDISABLED, "
			  "closing connection");
	  status = 2;
	  goto leave;
  }

  if(imap4_write(rs_io, NULL_FLAG, tag, IMAP4_CMD_LOGIN, 1, "{%d}",
			  strlen(auth->authentication_id)) < 0) {
	  VANESSA_LOGGER_DEBUG("imap4_write login");
	  status=-1;
	  goto leave;
  }
  if(n) { new_n = *n; }
  status = imap4_out_response(rs_io, eu_io, cont, ok, &q, buf, &new_n);
  if (status < 0)
	  VANESSA_LOGGER_DEBUG("imap4_out_response login");

  if (imap4_write(rs_io, NULL_FLAG, NULL, NULL, 2, "%s {%d}",
		   auth->authentication_id, strlen(auth->passwd)) < 0) {
	  VANESSA_LOGGER_DEBUG("imap4_write name");
	  status=-1;
	  goto leave;
  }
  if(n) { new_n = *n; }
  status = imap4_out_response(rs_io, eu_io, cont, ok, &q, buf, &new_n);
  if (status < 0)
	  VANESSA_LOGGER_DEBUG("imap4_out_response name");

  if (imap4_write_str(rs_io, NULL_FLAG, NULL, NULL, auth->passwd) < 0) {
	  VANESSA_LOGGER_DEBUG("imap4_write_str passwd");
	  status=-1;
	  goto leave;
  }
  if(n) { new_n = *n; }
  status = imap4_out_response(rs_io, eu_io, tag, ok, &q, buf, &new_n);
  if (status < 0)
	  VANESSA_LOGGER_DEBUG("imap4_out_response passwd");
  
  vanessa_queue_destroy(q);

  leave:
  if(buf) {
  	  char *tag_offset;
  	  tag_offset = strchr((char *)buf, ' ');
  	  if(tag_offset) {
  		  memmove(buf, tag_offset + 1, 
  				  strlen(tag_offset + 1) + 1);
  	  }
  }
  if(n) {
  	  *n = new_n;
  }
  imap4_tag_inc(tag);
  token_unassign(ok);
  token_destroy(&ok);
  token_unassign(cont);
  token_destroy(&cont);
  return(status);
}
  

/**********************************************************************
 * imap4_out_write_queue
 * Write a queue out to a socket
 * Not very efficient, but likely not called that often
 * pre: io: io to use to write to
 *      tag:  tag for message
 *      q: the rest of the message
 * post: tag and q are written to io
 * return: 0: on success
 *         -1: on error
 **********************************************************************/

static int
imap4_out_write_queue (io_t *io, token_t *tag, vanessa_queue_t **q)
{
	char *info_str = NULL;
	char *cmd_str = NULL;
	token_t *cmd = NULL;
	int status = -1;
  
	*q = vanessa_queue_pop(*q, (void **)&cmd);
	if (!*q) {
		VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
		goto leave;
	}
	
	cmd_str = token_to_string(cmd, TOKEN_NO_STRIP);
	if (!cmd_str) {
		VANESSA_LOGGER_DEBUG("token_to_string");
			goto leave;
	}
	
	info_str = queue_to_string(*q);
	if (!info_str) {
		VANESSA_LOGGER_DEBUG("queue_to_string");
		goto leave;
	}
	*q = NULL;

	if (imap4_write_str(io, NULL_FLAG, tag, cmd_str, info_str) < 0) {
		VANESSA_LOGGER_DEBUG("imap4_write_str");
		goto leave;
	}

	status = 0;
leave:
	if (info_str)
		free(info_str);
	if (cmd_str)
		free(cmd_str);
	if (cmd)
		token_destroy(&cmd);

	return status;
}
	

/**********************************************************************
 * imap4_out_response
 * Compare a response from a server with the desired response
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      tag: tag expected from server. NULL for untagged.
 *      desired_token: token expected from server
 *      q: resulting queue is stored here
 *      buf: buffer to read server response in to
 *      n: size of buf
 * post: Response is read from the server
 * return: 1 : tag and desired token found
 *         0: tag and desired token not found
 *         -1: on error
 **********************************************************************/

int imap4_out_response(io_t *rs_io, io_t *eu_io, const token_t *tag, 
		const token_t *desired_token, vanessa_queue_t **q, 
		char *buf, size_t *n)
{
  int status = -1;
  token_t *t = NULL;

  status=-1;

  /*Check tag*/
  while(1){
    token_destroy(&t);
    *q=read_line(rs_io, buf, n, TOKEN_IMAP4, 0, PERDITION_LOG_STR_REAL);
    if(!*q){
      VANESSA_LOGGER_DEBUG("read_line");
      return(-1);
    }
  
    if((*q=vanessa_queue_pop(*q, (void **)&t))==NULL){
      VANESSA_LOGGER_DEBUG("vanessa_queue_pop tag");
      return(-1);
    }

    if(tag) {
      if (token_len(t) == IMAP4_UNTAGGED_LEN &&
		      ! strncmp((char *)token_buf(t), IMAP4_UNTAGGED, 
			      token_len(t))) {
	if (eu_io) {
		if (imap4_out_write_queue(eu_io, t, q) < 0) {
			VANESSA_LOGGER_DEBUG("imap4_out_write_queue");
			goto leave;
		}
	}
        vanessa_queue_destroy(*q);
        continue;
      }
      else if(!token_cmp(tag, t)){
        VANESSA_LOGGER_DEBUG("invalid tag from server 1");
        goto leave;
      }
    }
    else {
      if (token_len(t) != IMAP4_UNTAGGED_LEN ||
		      strncmp((char *)token_buf(t), IMAP4_UNTAGGED, 
			      token_len(t))) {
	VANESSA_LOGGER_DEBUG("invalid tag from server 2");
        goto leave;
      }
    }
  
    break;
  }

  if((*q=vanessa_queue_pop(*q, (void **)&t))==NULL){
    VANESSA_LOGGER_DEBUG("vanessa_queue_pop token");
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
  return(status);
}
