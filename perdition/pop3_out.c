/**********************************************************************
 * pop3.c                                                September 1999
 * Horms                                             horms@verge.net.au
 *
 * Functions to communicate with upstream POP3 server
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2004  Horms
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

#include "options.h"
#include "pop3_out.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * pop3_out_setup
 * Begin interaction with real server by checking that
 * the connection is ok and doing TLS if neccessar
 * pre: io: io_t to read from and write to
 *      pw:     structure with username and passwd
 *      tag:    ignored 
 *      protocol: protocol structure for POP3
 * post: Read the vreeting string from the server
 *       It tls_outgoing is set then issue the CAPA command
 *       and check for STLS capability.
 *       Note, that as many POP3 daemons do not impliment the CAPA
 *       command, the failure of this is not considered an error
 * return: Logical or of PROTOCOL_S_OK and
 *         PROTOCOL_S_STARTTLS if ssl_mode is tls_outgoing (or tls_all)
 *         and the STARTTLS capability was reported by the server
 *       0: on failure
 *       -1 on error
 **********************************************************************/

int pop3_out_setup(io_t *io, const struct passwd *pw, token_t *tag,
	      	const protocol_t *protocol)
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

      	extern options_t opt;

	ok = token_create();
	if(!ok){
		VANESSA_LOGGER_DEBUG("token_create ok");
		goto leave;
	}
	token_assign(ok, POP3_OK, strlen(POP3_OK), TOKEN_DONT_CARE);

	status = pop3_out_response(io, NULL, ok, &q, NULL, NULL);
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

	greeting_string = greeting_str(protocol, GREETING_ADD_NODENAME);
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
	
	if(pop3_write(io, NULL_FLAG, NULL, POP3_CMD_CAPA, 0, "")<0){
		VANESSA_LOGGER_DEBUG("pop3_write");
		goto leave;
	}
	
	tmp_status = pop3_out_response(io, NULL, ok, &q, NULL, NULL);
	if(tmp_status<0){
		VANESSA_LOGGER_DEBUG("pop3_out_response capa");
		goto leave;
	}
	
	/* NB: It is OK for the server not to support the CAPA command */
	if(!tmp_status){
		goto ok;
	}
	
	capa_end=token_create();
	if(!capa_end){
		VANESSA_LOGGER_DEBUG("token_create capa_end");
		goto leave;
	}
	token_assign(capa_end, POP3_CAPA_END, 
			strlen(POP3_CAPA_END), TOKEN_EOL);
	
	stls=token_create();
	if(!stls){
		VANESSA_LOGGER_DEBUG("token_create stls");
		goto leave;
	}
	token_assign(stls, POP3_CMD_STLS, strlen(POP3_CMD_STLS), TOKEN_EOL);

	/* Loop through  lines */
	while(1) {
		vanessa_queue_destroy(q);
		q = read_line(io, NULL, NULL, TOKEN_POP3, 0, 
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
		goto ok;
	}

	if(pop3_write(io, NULL_FLAG, NULL, POP3_CMD_STLS, 0, "")<0){
		VANESSA_LOGGER_DEBUG("pop3_write");
		goto leave;
	}

	tmp_status = pop3_out_response(io, NULL, ok, &q, NULL, NULL);
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

	/* Stop compiler from complaining */
	if(&opt);
	if(tmp_status);
	if(tmp_token);
}
  

/**********************************************************************
 * pop3_out_authenticate
 * Authenticate user with backend pop3 server
 * pre: io: io_t to read from and write to
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
  io_t *io,
  const struct passwd *pw,
  token_t *tag,
  const protocol_t *protocol,
  unsigned char *buf,
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
  if(pop3_write(io, NULL_FLAG, NULL, POP3_CMD_USER, 1, "%s", pw->pw_name)<0){
    VANESSA_LOGGER_DEBUG("pop3_write");
    status = -1;
    goto leave;
  }

  if((status=pop3_out_response(io, NULL, ok, &q, NULL, NULL))<0){
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
  if(pop3_write(io, NULL_FLAG, NULL, POP3_CMD_PASS, 1, "%s", pw->pw_passwd)<0){
    VANESSA_LOGGER_DEBUG("pop3_write pass");
    status = -1;
    goto leave;
  }

  if((status=pop3_out_response(io, NULL, ok, &q, buf, n))<0){
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
 * pre: io: io_t to read from and write to
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
  io_t *io,
  const token_t *tag,
  const token_t *desired_token,
  vanessa_queue_t **q,
  unsigned char *buf,
  size_t *n
){
  int status;
  token_t *t;

  *q=read_line(io, buf, n, TOKEN_POP3, 0, PERDITION_LOG_STR_REAL);
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
