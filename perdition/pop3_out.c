/**********************************************************************
 * pop3.c                                                September 1999
 * Horms                                             horms@verge.net.au
 *
 * Functions to communicate with upstream POP3 server
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

#include "options.h"
#include "pop3_out.h"
#include "perdition_globals.h"
#include "unused.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * pop3_out_setup
 * Begin interaction with real server by checking that
 * the connection is ok and doing TLS if neccessar
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      pw:     structure with username and passwd
 *      tag:    ignored 
 * post: Read the vreeting string from the server
 *       It tls_outgoing is set then issue the CAPA command
 *       and check for STLS capability.
 *       Note, that as many POP3 daemons do not impliment the CAPA
 *       command, the failure of this is not considered an error
 * return:
 *       PROTOCOL_S_OK: success, don't use STARTTLS
 *       PROTOCOL_S_OK|PROTOCOL_S_STARTTLS: success, use STARTTLS
 *       0: on failure
 *       -1 on error
 **********************************************************************/

int pop3_out_setup(io_t *rs_io, io_t *eu_io,
		   const struct passwd *UNUSED(pw), token_t *UNUSED(tag))
{
	token_t *ok;
	token_t *capa_end = NULL;
	token_t *stls = NULL;
	token_t *tmp_token;
	vanessa_queue_t *q;
	char *read_string = NULL;
	char *greeting_string = NULL;
	int status = -1;
	int tmp_status = -1;
	int protocol_status = PROTOCOL_S_OK;

	ok = token_create();
	if(!ok){
		VANESSA_LOGGER_DEBUG("token_create ok");
		goto leave;
	}
	token_assign(ok, POP3_OK, strlen(POP3_OK), TOKEN_DONT_CARE);

	status = pop3_out_response(rs_io, eu_io, NULL, ok, &q, NULL, NULL);
	if(status<0){
		VANESSA_LOGGER_DEBUG("pop3_out_response 1");
		goto leave;
	}
	else if(!status){
		status = 0;
		goto leave;
	}

	read_string = queue_to_string(q);
	if(!read_string){
		VANESSA_LOGGER_DEBUG("queue_to_string");
		goto leave;
	}
	q = NULL;

	greeting_string = greeting_str(POP3_GREETING, GREETING_ADD_NODENAME);
	if(!greeting_string) {
		VANESSA_LOGGER_DEBUG("greeting_str");
		status=-1;
		goto leave;
	}
	
	if(!strcmp(read_string, greeting_string)){
		VANESSA_LOGGER_LOG(LOG_DEBUG, 
				"Loop detected, abandoning connection");
		status = 0;
		goto leave;
	}
	
#ifdef WITH_SSL_SUPPORT
	if(!(opt.ssl_mode & SSL_MODE_TLS_OUTGOING)) {
		goto ok;
	}
	
	if (pop3_write_str(rs_io, NULL_FLAG, NULL, POP3_CMD_CAPA, NULL) < 0) {
		VANESSA_LOGGER_DEBUG("pop3_write_str");
		goto leave;
	}
	
	tmp_status = pop3_out_response(rs_io, eu_io, NULL, ok, &q, NULL, NULL);
	if(tmp_status<0){
		VANESSA_LOGGER_DEBUG("pop3_out_response capa");
		goto leave;
	}
	
	/* NB: It is OK for the server not to support the CAPA command */
	if(!tmp_status){
		if (!(opt.ssl_mode & SSL_MODE_TLS_OUTGOING_FORCE)) {
			VANESSA_LOGGER_DEBUG_RAW("tls_outgoing is set "
					"but the real-server does not "
					"have the CAPA command, "
					"connection will not be encrypted");
			goto ok;
		}
		VANESSA_LOGGER_DEBUG_RAW("tls_outgoing_force is set "
				"but the real-server does not "
				"have the CAPA command, "
				"closing connection");
		goto leave;
	}
	
	capa_end=token_create();
	if(!capa_end){
		VANESSA_LOGGER_DEBUG("token_create capa_end");
		goto leave;
	}
	token_assign(capa_end, POP3_CAPA_END, strlen(POP3_CAPA_END), TOKEN_EOL);
	
	stls=token_create();
	if(!stls){
		VANESSA_LOGGER_DEBUG("token_create stls");
		goto leave;
	}
	token_assign(stls, POP3_CMD_STLS, strlen(POP3_CMD_STLS), TOKEN_EOL);

	/* Loop through  lines */
	while(1) {
		vanessa_queue_destroy(q);
		q = read_line(rs_io, NULL, NULL, TOKEN_POP3, 0, 
				PERDITION_LOG_STR_REAL);
      		if(!q) {
			VANESSA_LOGGER_DEBUG("read_line");
			goto leave;
		}
	
		/* Do we have a "STLS" or a "."? */
		q = vanessa_queue_pop(q, (void **)&tmp_token);
		if(!q){
			VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
			goto leave;
		}
		if(!(protocol_status & PROTOCOL_S_STARTTLS) && 
		      		token_cmp(stls, tmp_token)) {
			protocol_status |= PROTOCOL_S_STARTTLS;
		}
		tmp_status = token_cmp(capa_end, tmp_token);
		token_destroy(&tmp_token);
		
		if(tmp_status) {
			break;
		}
	}

	if(!(protocol_status & PROTOCOL_S_STARTTLS)) {
		if (opt.ssl_mode & SSL_MODE_TLS_OUTGOING_FORCE) {
			VANESSA_LOGGER_DEBUG_RAW("tls_outgoing_force is set "
					"but the real server does not "
					"have the STLS capability, "
					"closing connection");
			goto leave;
		}
		VANESSA_LOGGER_DEBUG_RAW("tls_outgoing is set "
				"but the real server does not "
				"have the STLS capability, "
				"connection will not be encrypted");
		goto ok;
	}

	if (pop3_write_str(rs_io, NULL_FLAG, NULL, POP3_CMD_STLS, NULL) < 0) {
		VANESSA_LOGGER_DEBUG("pop3_write_str");
		goto leave;
	}

	tmp_status = pop3_out_response(rs_io, eu_io, NULL, ok, &q, NULL, NULL);
	if(tmp_status < 0){
		VANESSA_LOGGER_DEBUG("pop3_out_response stls");
		goto leave;
	}
	else if(!status){
		status=0;
		goto leave;
	}
#endif /* WITH_SSL_SUPPORT */

ok:
	status = 1;
leave:
	str_free(read_string);
	str_free(greeting_string);
	token_unassign(ok);
	token_destroy(&ok);
	if(capa_end) {
		token_unassign(capa_end);
		token_destroy(&capa_end);
	}
	if(stls) {
		token_unassign(stls);
		token_destroy(&stls);
	}
	if(q) {
		vanessa_queue_destroy(q);
	}
	
	if(status == 1) {
		status = protocol_status;
	}
	return(status);
}
  

/**********************************************************************
 * pop3_out_authenticate
 * Authenticate user with backend pop3 server
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      pw:     structure with username and passwd
 *      tag:    ignored 
 *      protocol: protocol structure for POP3
 *      buf: buffer to return server response in
 *      n: size of buffer
 * post: The USER and PASS commands are sent to the server
 * return: 1: on success
 *         0: on failure
 *        -1: on error
 **********************************************************************/

int pop3_out_authenticate(
  io_t *rs_io,
  io_t *eu_io,
  const struct passwd *pw,
  token_t *UNUSED(tag),
  const protocol_t *UNUSED(protocol),
  char *buf,
  size_t *n
){
  token_t *ok;
  vanessa_queue_t *q = NULL;
  int status = -1;

  if((ok=token_create())==NULL){
    VANESSA_LOGGER_DEBUG("token_create");
    goto leave;
  }
  token_assign(ok, POP3_OK, strlen(POP3_OK), TOKEN_DONT_CARE);

  /* Send USER command */
  if (pop3_write_str(rs_io, NULL_FLAG, NULL, POP3_CMD_USER, pw->pw_name) < 0) {
    VANESSA_LOGGER_DEBUG("pop3_write_str");
    status = -1;
    goto leave;
  }

  if((status=pop3_out_response(rs_io, eu_io, NULL, ok, &q, NULL, NULL))<0){
    VANESSA_LOGGER_DEBUG("pop3_out_response user");
    status = -1;
    goto leave;
  }
  else if(!status){
    status=0;
    goto leave;
  }
  vanessa_queue_destroy(q);
  q = NULL;

  /* Send PASS command */
  if (pop3_write_str(rs_io, NULL_FLAG, NULL,
		     POP3_CMD_PASS, pw->pw_passwd) < 0) {
    VANESSA_LOGGER_DEBUG("pop3_write_str pass");
    status = -1;
    goto leave;
  }

  if((status=pop3_out_response(rs_io, eu_io, NULL, ok, &q, buf, n))<0){
    VANESSA_LOGGER_DEBUG("pop3_out_response pass");
  }

  leave:
  if(q) {
    vanessa_queue_destroy(q);
  }
  token_unassign(ok);
  token_destroy(&ok);
  return(status);
}
  

/**********************************************************************
 * pop3_out_response
 * Compare a respnse from a server with the desired response
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      tag: ignored
 *      desired_token: token expected from server
 *      buf: buffer to return server response in
 *      n: size of buffer
 * post: Response is read from the server
 * return: 1: tag and desired token found
 *         0: tag and desired token not found
 *        -1: on error
 **********************************************************************/

int pop3_out_response(
  io_t *rs_io,
  io_t *UNUSED(eu_io),
  const token_t *UNUSED(tag),
  const token_t *desired_token,
  vanessa_queue_t **q,
  char *buf,
  size_t *n
){
  int status;
  token_t *t;

  *q=read_line(rs_io, buf, n, TOKEN_POP3, 0, PERDITION_LOG_STR_REAL);
  if(!*q) {
    VANESSA_LOGGER_DEBUG("read_line");
    return(-1);
  }
  if((*q=vanessa_queue_pop(*q, (void *)&t))==NULL){
    VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
    return(-1);
  }

  status=token_cmp(desired_token, t);
  
  token_destroy(&t);
  return(status);
}
