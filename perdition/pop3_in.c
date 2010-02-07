/**********************************************************************
 * pop3_in.c                                             September 1999
 * Horms                                             horms@verge.net.au
 *
 * Handle pop commands from a client
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

#include "pop3_in.h"
#include "options.h"
#include "perdition_globals.h"
#include "unused.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


#ifdef WITH_PAM_SUPPORT

/**********************************************************************
 * pop3_in_authenticate
 * Authenticate an incoming pop session
 * Not really needed if we are going to authenticate with an upstream
 * pop server but it may be useful in some cases
 * pre: pw: passwd struct with username and password to authenticate
 *      io: io_t to write any errors to
 *      tag: ignored
 * post: An attemped is made to authenticate the user locally.
 *       If this fails then an error message is written to io
 *       Else there is no output to io
 * return: 1 if authentication is successful
 *         0 if authentication is unsuccessful
 *         -1 on error
 **********************************************************************/

int pop3_in_authenticate(
  const struct passwd *pw, 
  io_t *io,
  const token_t *UNUSED(tag)
){
  pam_handle_t *pamh=NULL;

  if((
     pam_retval=pam_start(SERVICE_NAME, pw->pw_name, &conv_struct, &pamh)
  )!=PAM_SUCCESS){
    VANESSA_LOGGER_DEBUG_ERRNO("pam_start");
    do_pam_end(pamh, EX_PAM_ERROR);
    return(-1);
  }
  if(do_pam_authentication(pamh, pw->pw_name, pw->pw_passwd)<0){
    sleep(PERDITION_AUTH_FAIL_SLEEP);
    if(pop3_write(io, NULL_FLAG, NULL, POP3_ERR, 0,
        "Authentication failure, mate")<0){
      VANESSA_LOGGER_DEBUG("pop3_write");
      do_pam_end(pamh, EXIT_SUCCESS);
      return(-1);
    }
    do_pam_end(pamh, EXIT_SUCCESS);
    return(0);
  }

  do_pam_end(pamh, EXIT_SUCCESS);
  return(1);
}

#endif /* WITH_PAM_SUPPORT */


static int pop3_in_err(io_t *io, int nargs, const char *fmt, ...)
{
	va_list ap;
	int rc;

	sleep(VANESSA_LOGGER_ERR_SLEEP);

	va_start(ap, fmt);
	rc = pop3_vwrite(io, NULL_FLAG, NULL, POP3_ERR, nargs, fmt, ap);
	va_end(ap);

	if (rc < 0) {
		VANESSA_LOGGER_DEBUG("pop3_write err");
		return -1;
	}

	return 0;
}

#define __POP3_IN_ERR(_reason)						\
	if (pop3_in_err(io, 1, "%s", _reason) < 0) {			\
		break;							\
	}								\
	goto loop;

static int pop3_in_invalid_cmd(io_t *io, const char *msg)
{
	char *extra = "";

	if (opt.ssl_mode & SSL_MODE_TLS_LISTEN &&
	    io_get_type(io) != io_type_ssl)
		extra = POP3_CMD_STLS ", ";

	return pop3_in_err(io, 2, "Mate, %smust be one of %s"
			   POP3_CMD_CAPA ", " POP3_CMD_USER ", "
			   POP3_CMD_PASS " or " POP3_CMD_QUIT, msg, extra);
}

/**********************************************************************
 * pop3_in_mangle_capability
 * Modify a capability by exchanging delimiters and optionally
 * appending a tail.
 * pre: capability: capability string that has been set
 *      old_delimiter: Delimiter to remove
 * return: mangled_capability suitable for sending on the wire,
 *         caller should free this memory
 *         NULL on error
 **********************************************************************/

static char *pop3_in_mangle_capability(const char *capability,
				       const char *old_delimiter)
{
	const char *start;
	const char *end;
	char *mangled_capability;
	size_t n_len;
	int count;

	const char *new_delimiter = "\r\n";
	const char *tail = "\r\n.\r\n";

	const size_t old_delimiter_len = strlen(old_delimiter);
	const size_t new_delimiter_len = strlen(new_delimiter);
	const size_t tail_len = strlen(tail);

	n_len = 0;
	count = 0;
	start = capability;
	while ((start = strstr(start, old_delimiter))) {
		start += old_delimiter_len;
		count++;
	}

	n_len = strlen(capability) - (count * old_delimiter_len) +
		(count * new_delimiter_len) + tail_len;

	mangled_capability = (char *)malloc(n_len + 1);
	if (!mangled_capability) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		return NULL;
	}
	memset(mangled_capability, 0, n_len +1);

	end = capability;
	while (1) {
		start = end;
		end = strstr(start, old_delimiter);
		if (!end)
			break;
		strncat(mangled_capability, start, end-start);
		strcat(mangled_capability, new_delimiter);
		end += old_delimiter_len;
	}
	strncat(mangled_capability, start, end-start);
	strcat(mangled_capability, tail);

	return mangled_capability;
}

/**********************************************************************
 * pop3_in_capability
 * Return the capability string to be used.
 * pre: tls_flags: not used
 *      tls_state: not used
 * post: capability to use, caller should free this memory
 *       NULL on error
 **********************************************************************/

static char *pop3_in_capability(flag_t tls_flags, flag_t tls_state)
{
	flag_t mode;
	char *capability, *old_capability;

	capability = opt.pop_capability;

	if ((tls_flags & SSL_MODE_TLS_LISTEN) &&
	    !(tls_state & SSL_MODE_TLS_LISTEN))
		mode = PROTOCOL_C_ADD;
	else
		mode = PROTOCOL_C_DEL;

	capability = protocol_capability(mode, capability, POP3_CMD_STLS,
					 POP3_CAPABILITY_DELIMITER);
	if (!capability) {
		VANESSA_LOGGER_DEBUG("protocol_capability");
		return NULL;
	}

	old_capability = capability;
	capability = pop3_in_mangle_capability(old_capability,
					       POP3_CAPABILITY_DELIMITER);
	free(old_capability);
	if (!capability) {
		VANESSA_LOGGER_DEBUG("pop3_mangle_capability");
		return NULL;
	}

	return capability;
}

#define __POP3_IN_INVALID_CMD(_reason)					\
	if (pop3_in_invalid_cmd(io, _reason) < 0) {			\
		break;							\
	}								\
	goto loop;

/**********************************************************************
 * pop3_in_get_pw
 * read USER and PASS commands and return them in a struct passwd *
 * allocated by this function
 * pre: io: io_t to write to and read from
 *      tls_flags: the encryption flags that have been set
 *      tls_state: the current state of encryption for the session
 *      return_pw: pointer to an allocated struct pw, 
 *                 where username and password
 *                 will be returned if one is found
 *      return_tag: ignored 
 * post: pw_return structure with pw_name and pw_passwd set
 * return: 0 on success
 *         1 if user quits (QUIT command)
 *         -1 on error
 **********************************************************************/

int pop3_in_get_pw(io_t *io, flag_t tls_flags, flag_t tls_state,
		   struct passwd *return_pw, token_t **UNUSED(return_tag))
{
  vanessa_queue_t *q = NULL;
  token_t *t = NULL;
  char *message=NULL;
  char *capability;

  return_pw->pw_name=NULL;

  capability = pop3_in_capability(tls_flags, tls_state);
  if (!capability) {
    VANESSA_LOGGER_DEBUG("pop3_in_capability");
    return -1;
  }

  while(1){
    q=read_line(io, NULL, NULL, TOKEN_POP3, 0, PERDITION_LOG_STR_CLIENT);
    if(!q) {
      VANESSA_LOGGER_DEBUG("read_line");
      break;
    }

    if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
      VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
      t=NULL;
      break;
    }

    if(token_is_null(t)) {
	    __POP3_IN_ERR("Null command, mate");
    }

    if (token_len(t) != POP3_CMD_LEN) {
	    __POP3_IN_INVALID_CMD("the command is too short, ");
    }

    if(strncasecmp((char *)token_buf(t), POP3_CMD_CAPA, token_len(t))==0){
      if(vanessa_queue_length(q)!=0){
	    __POP3_IN_ERR("Mate, try: " POP3_CMD_CAPA);
      }
      pop3_write(io, NULL_FLAG, NULL, POP3_OK, 0,
		      "Capability list follows, mate");
      pop3_write(io, WRITE_STR_NO_CLLF, NULL, NULL, 1, "%s", capability);
      goto loop;
    }

#ifdef WITH_SSL_SUPPORT
    if(opt.ssl_mode & SSL_MODE_TLS_LISTEN &&
        !strncasecmp((char *)token_buf(t), POP3_CMD_STLS, token_len(t))){
      if(vanessa_queue_length(q)!=0){
	      __POP3_IN_ERR("Mate, try: " POP3_CMD_STLS);
      }
      if(io_get_type(io) != io_type_ssl){
        pop3_write(io, NULL_FLAG, NULL, POP3_OK, 0,
			"Begin TLS negotiation, mate");
        token_destroy(&t);
        vanessa_queue_destroy(q);
        return(2);
      }
      else
      {
	      __POP3_IN_ERR("TLS already active, mate");
      }
    } 
#endif /* WITH_SSL_SUPPORT */

    if(strncasecmp((char *)token_buf(t), POP3_CMD_USER, token_len(t))==0){
      if(return_pw->pw_name!=NULL){
	      __POP3_IN_ERR(POP3_CMD_USER " is already set, mate");
      }
      if(vanessa_queue_length(q)!=1){
	      __POP3_IN_ERR("Mate, try: " POP3_CMD_USER " <username>");
      }

      if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
        VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
        t=NULL;
        break;
      }
      if(token_is_null(t)) {
	      __POP3_IN_ERR("Mate, try: " POP3_CMD_USER " <username>");
      }

      if((return_pw->pw_name=token_to_string(t, TOKEN_NO_STRIP))==NULL){
        VANESSA_LOGGER_DEBUG("token_to_string");
        break;
      }
      token_destroy(&t);
      
      message = str_cat(3, POP3_CMD_USER " ", return_pw->pw_name, " set, mate");
      if (!message) {
        VANESSA_LOGGER_DEBUG("str_cat");
        goto loop;
      }
      if(pop3_write(io, NULL_FLAG, NULL, POP3_OK, 1, "%s", message)<0){
        VANESSA_LOGGER_DEBUG("pop3_write user set");
        goto loop;
      }
    }
    else if(strncasecmp((char *)token_buf(t), POP3_CMD_PASS, token_len(t))==0){
      if(return_pw->pw_name==NULL){
	      __POP3_IN_ERR(POP3_CMD_USER " not yet set, mate");
      }
      if(!vanessa_queue_length(q)){
	      __POP3_IN_ERR("Mate, try: " POP3_CMD_PASS " <password>");
      }
      if((return_pw->pw_passwd=queue_to_string(q))==NULL){
        VANESSA_LOGGER_DEBUG("token_to_string");
        free(return_pw->pw_name);
        break;
      }
      return(0);
    }
    else if(strncasecmp((char *)token_buf(t), POP3_CMD_QUIT, token_len(t))==0){
      if(vanessa_queue_length(q)) {
	      __POP3_IN_ERR("Mate, try: " POP3_CMD_QUIT);
      }
      if(pop3_write(io, NULL_FLAG, NULL, POP3_OK, 0, POP3_CMD_QUIT)<0){
        VANESSA_LOGGER_DEBUG("pop3_write quit");
        break;
      }
      vanessa_queue_destroy(q);
      return(1);
    }
    else {
	    __POP3_IN_INVALID_CMD("the command ");
    }

    /*Clean up before looping*/
    loop:
    token_destroy(&t);
    vanessa_queue_destroy(q);
    str_free(message);
  }

  /*If we get here clean up and bail*/
  token_destroy(&t);
  vanessa_queue_destroy(q);
  str_free(message);
  free(capability);
  return(-1);
}
