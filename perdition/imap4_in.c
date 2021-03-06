/**********************************************************************
 * imap4_in.c                                            September 1999
 * Horms                                             horms@verge.net.au
 *
 * Handle IMAP4 commands from a client
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
#include "imap4_in.h"
#include "options.h"
#include "perdition_globals.h"

#include <stdlib.h>

/* limits.h should be sufficient on most systems 
 * http://www.opengroup.org/onlinepubs/007908799/headix.html */
#include <limits.h>
#if 0
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#ifdef __FreeBSD__
#if __FreeBSD_version < 500112
#include <machine/limits.h> /* For ULONG_MAX on FreeBSD */
#else
#include <sys/limits.h>
#endif
#endif
#endif
#endif

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define IMAP4_QUOTED_STRING             0x1
#define IMAP4_SYNCHRONISING_TOKEN     0x2
#define IMAP4_NON_SYNCHRONISING_TOKEN 0x3

/**********************************************************************
 * imap4_in_noop_cmd
 * Do a response to a NOOP command
 * pre: io: io_t to write to
 * post: Tagged response to NOOP is written to io
 * return: 0 on success
 *         -1 otherwise
 **********************************************************************/

static int imap4_in_noop_cmd(io_t *io, const token_t *tag)
{
	if (imap4_write_str(io, NULL_FLAG, tag, IMAP4_OK, IMAP4_CMD_NOOP) < 0) {
		VANESSA_LOGGER_DEBUG("imap4_write_str");
		return -1;
	}

	return 0;
}

/**********************************************************************
 * imap4_in_logout_cmd
 * Do a response to a LOGOUT command
 * pre: io: io_t to write to
 * post: An untagged response advising of logout is written to io
 *       A tagged response to the LOGOUT is written to io
 * return 0 on success
 *        -1 otherwise
 **********************************************************************/

static int imap4_in_logout_cmd(io_t *io, const token_t *tag)
{
	if (imap4_write_str(io, NULL_FLAG, NULL, IMAP4_BYE,
			    "IMAP4 server logging out, mate") < 0) {
		VANESSA_LOGGER_DEBUG("imap4_write_str untagged");
		return(-1);
	}

	if (imap4_write_str(io, NULL_FLAG, tag, IMAP4_OK,
			    IMAP4_CMD_LOGOUT) < 0) {
		VANESSA_LOGGER_DEBUG("imap4_write_str tagged");
		return -1;
	}

	return 0;
}

/**********************************************************************
 * imap4_in_capability_cmd
 * Do a response to a CAPABILITY command
 * pre: io: io_t to write to
 * post: An untagged response giving capabilities is written to io
 *       A tagged response to the CAPABILITY command is written to io
 * return 0 on success
 *        -1 otherwise
 **********************************************************************/

static int imap4_in_capability_cmd(io_t *io, const token_t *tag,
				   flag_t tls_flags, flag_t tls_state)
{
	char *capability;

	capability = imap4_capability(tls_flags, tls_state);
	if (!capability)
		 return -1;

	if (imap4_write_str(io, NULL_FLAG, NULL, IMAP4_CMD_CAPABILITY,
			    capability) < 0) {
		VANESSA_LOGGER_DEBUG("imap4_write_str untagged");
		goto err;
	}

	if (imap4_write_str(io, NULL_FLAG, tag, IMAP4_OK,
			    IMAP4_CMD_CAPABILITY) < 0) {
		VANESSA_LOGGER_DEBUG("imap4_write_str tagged");
		goto err;
	}

err:
	free(capability);
	return 0;
}

/**********************************************************************
 * imap4_in_authenticate_cmd
 * Do a response to an AUTHENTICATE command
 * pre: io: io_t to write to
 * post: A tagged error to the AUTHENTICATE command is given
 * return 0 on success
 *        -1 otherwise
 **********************************************************************/

static int imap4_in_authenticate_cmd(io_t *io, const token_t *tag)
{
	if (imap4_write_str(io, NULL_FLAG, tag, IMAP4_NO,
			    IMAP4_CMD_AUTHENTICATE
			    " mechanism not supported, mate") < 0) {
		VANESSA_LOGGER_DEBUG("imap4_write_str");
		return -1;
	}

	return 0;
}

/**********************************************************************
 * imap4_token_is_literal
 * Determine if a token is a literal as defined in RFC 1730
 * That is a string of the form "{n}" where n is a positive integral 
 * value. The quotes may be omitted.
 * pre: token: token to examine
 *      i: will be seeded with the value of n if token is a literal
 * post: i is seeded with the value of n if token is a literal
 * return: IMAP4_NON_SYNCHRONISING_TOKEN if token is 
 *           a non-synchronising literal
 *         IMAP4_SYNCHRONISING_TOKEN if token is a synchronising literal
 *         IMAP4_QUOTED_STRING if token is not a literal
 *         -1 on error
 **********************************************************************/

static int imap4_token_is_literal(const token_t *token, unsigned long *i) 
{
	char *str;
	char *str2;
	int non_synchronising = IMAP4_SYNCHRONISING_TOKEN;

	if(!token_is_eol(token)) {
		return(IMAP4_QUOTED_STRING);
	}

	/* Get the string out of the token */
	if((str=token_to_string(token, '\"'))==NULL){
		VANESSA_LOGGER_DEBUG("token_to_string");
		return(-1);
	}

	/* Check for surrounding {} */
	if(*str != '{' || *(str+strlen(str)-1) != '}') {
		return(IMAP4_QUOTED_STRING);
	}
	*(str+strlen(str)-1) = '\0';

	/* If the trailing character is a + then it is a 
	 * non_synchronising literal */

	if(*(str+strlen(str)-1) == '+') {
		non_synchronising = IMAP4_NON_SYNCHRONISING_TOKEN;
		*(str+strlen(str)-1) = '\0';
	}

	/* Check that what is left is only digits */
	if(!vanessa_socket_str_is_digit(str+1)) {
		return(IMAP4_QUOTED_STRING);
	}

	/* Convert it into binary */
	*i = strtoul(str+1, &str2, 10);
	if(*i == ULONG_MAX) {
		VANESSA_LOGGER_DEBUG_ERRNO("strtoul");
		return(-1);
	}

	return(non_synchronising);
}


/**********************************************************************
 * imap4_token_wrapper
 * Interpret a token.
 * If the token is not a literal, as defined in RFC 1930 then the
 * token nothing is done. Else the number of bytes specified in
 * the literal token are returned as a new input_token and the
 * original input_token is destroyed.
 * Either way, the input_token return can be used as an 8bit clean value.
 * pre: io: IO to read from if necessary
 *      q: Queue of pending tokens, not including input_token
 *      input_token: token to examine.
 *                   also used to return the token
 * post: If input_token is a literal
 *         interpret the literal as a byte-count using
 *             imap4_token_is_literal
 *         Destroy input_token
 *         Make sure the q is empty, else there is a syntax error
 *         Return "+ OK" to the client by writing to io
 *         Read bytes from io, as specified by input_token
 *         Place these bytes in a new input_token
 *         Return
 *      Else
 *         Return
 * return: The type of the original input_token as per
 *         imap4_token_is_literal()
 *         -1 on error
 **********************************************************************/

static int imap4_token_wrapper(io_t *io, vanessa_queue_t *q, 
		token_t **input_token) 
{
	unsigned long i;
      	int status;
  
    	status = imap4_token_is_literal(*input_token, &i);
  	if(status < 0) {
      		VANESSA_LOGGER_DEBUG("imap4_token_is_literal");
		token_destroy(input_token);
	  	return(-1);
	}
	if(status == IMAP4_QUOTED_STRING) {
		return(status);
	}
  
	token_destroy(input_token);

	if(vanessa_queue_length(q) != 0) {
		return(-1);
	}

	if(status == IMAP4_SYNCHRONISING_TOKEN) {
		*input_token=token_create();
		if(*input_token == NULL) {
			VANESSA_LOGGER_DEBUG("token_create");
			return(-1);
		}
		token_assign(*input_token, strdup(IMAP4_CONT_TAG), 1, 0);
		imap4_write_str(io, NULL_FLAG, *input_token, IMAP4_OK,
				"ready for additional input");
		token_destroy(input_token);
	}

	if(i == 0) {
		*input_token=token_create();
		return(status);
	}

	if((*input_token=token_read(io, NULL, NULL, TOKEN_IMAP4_LITERAL, i,
				PERDITION_LOG_STR_CLIENT))==NULL){
		VANESSA_LOGGER_DEBUG("token_read");
		return(-1);
	}

	return(status);
}


static char *imap4_token_to_string(token_t *t, int type)
{
	char *str;

	if(type == IMAP4_QUOTED_STRING) {
		str=token_to_string(t, '\"');
		if(!str) {
			VANESSA_LOGGER_DEBUG("token_to_string 1");
			return(NULL);
		}
		str=str_replace(str, 4, "\\\"", "\"", "\\\\", "\\");
		if(!str) {
			VANESSA_LOGGER_DEBUG("str_replace");
			return(NULL);
		}
	}
	else {
		str=token_to_string(t, TOKEN_NO_STRIP);
		if(!str) {
			VANESSA_LOGGER_DEBUG("token_to_string 2");
			return(NULL);
		}
	}

	return(str);
}


#ifdef WITH_PAM_SUPPORT

/**********************************************************************
 * imap4_in_authenticate
 * Authenticate an incoming pop session
 * Not really needed if we are going to authenticate with an upstream
 * pop server but it may be useful in some cases
 * pre: auth: login credentials
 *      io: io_t to write errors to
 *      tag: Tag to use in (Error) responses
 * post: An attempt is made to authenticate the user locally
 *       If this fails then an tagged response is written to io
 *       Else no output is made
 * return: 1 if authentication succeeds
 *         0 if authentication fails
 *         -1 if an error occurs
 **********************************************************************/

int imap4_in_authenticate(const struct auth *auth, io_t *io,
			  const token_t *tag){
  pam_handle_t *pamh=NULL;
  const char *name = auth_get_authorisation_id(auth);

  if((
     pam_retval = pam_start(SERVICE_NAME, name, &conv_struct, &pamh)
  )!=PAM_SUCCESS){
    VANESSA_LOGGER_DEBUG_ERRNO("pam_start");
    do_pam_end(pamh, EX_PAM_ERROR);
    return(-1);
  }
  if (do_pam_authentication(pamh, name, auth->passwd) < 0) {
    sleep(PERDITION_AUTH_FAIL_SLEEP);
    if (imap4_write_str(io, NULL_FLAG, tag, IMAP4_NO,
			"Authentication failure") < 0){
      VANESSA_LOGGER_DEBUG("imap4_write");
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

/**********************************************************************
 * imap4_in_verify_tag_str
 * Verify that a tag is valid
 * Pre: tag: io_t to write to
 * Return 0 on success
 *        -1 otherwise
 **********************************************************************/

/* Excerpts from rfc3501, Section 9. Formal Syntax
 *
 * The ASCII NUL character, %x00, MUST NOT be used at any time.
 *
 * tag             = 1*<any ASTRING-CHAR except "+">
 *
 * ATOM-CHAR       = <any CHAR except atom-specials>
 *
 * atom-specials   = "(" / ")" / "{" / SP / CTL / list-wildcards /
 *                quoted-specials / resp-specials
 *
 * list-wildcards  = "%" / "*"
 *
 * quoted-specials = DQUOTE / "\"
 *
 * resp-specials   = "]"
 *
 * Excerpts from rfc2060, Section 9. Formal Syntax
 *
 * CHAR            ::= <any 7-bit US-ASCII character except NUL,
 *                      0x01 - 0x7f>
 *
 * CTL             ::= <any ASCII control character and DEL,
 *                         0x00 - 0x1f, 0x7f>
 */

static int imap4_in_verify_tag_str(const token_t *tag)
{
	char *tag_str;
	size_t tag_str_len, i;

	tag_str_len = token_len(tag);

	if (!tag_str_len)
		return -1;

	tag_str = token_buf(tag);

	for (i = 0; i < tag_str_len; i++) {
		/* Must be ASCII, must not be a control character */
		if (tag_str[i] <= 0x1f || tag_str[i] >= 0x7f)
			return -1;
		/* Must not be other reserved characters */
		switch(tag_str[i]) {
			case '\0':
			case '(':
			case ')':
			case '{':
			case ' ':
			case '%':
			case '*':
			case '"':
			case '\\':
			case ']':
				return -1;
		}
	}

	return 0;
}



/**********************************************************************
 * imap4_in_get_auth
 * read USER and PASS commands and return them in a struct passwd *
 * allocated by this function
 * Pre: io: io_t to read from and write to
 *      tls_flags: the encryption flags that have been set
 *      tls_state: the current state of encryption for the session
 *      return_auth: pointer to an allocated struct auth,
 *                   where login credentials will be returned
 *      return_tag: pointer to return clients tag
 * Post: auth_return is seeded
 *       tag_return is seeded with the next IMAP tag to use
 * Return: 0: on success
 *         1: if user quits (LOGOUT command)
 *         2: if TLS negotiation should be done
 *        -1: on error
 **********************************************************************/

#define __IMAP4_IN_BAD(_reason)                                             \
        sleep(VANESSA_LOGGER_ERR_SLEEP);                                    \
        if (imap4_write_str(io, NULL_FLAG, tag, IMAP4_BAD, (_reason)) < 0) {\
		VANESSA_LOGGER_DEBUG("imap4_write_str syntax error");       \
		break;                                                      \
        }                                                                   \
	goto loop;
	

#define __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR                                \
	__IMAP4_IN_BAD("Mate, try " IMAP4_CMD_LOGIN " <username> <passwd>");

#define __IMAP4_IN_CHECK_NO_ARG(_cmd)                                       \
	if(vanessa_queue_length(q)) {                                       \
		__IMAP4_IN_BAD("Argument given to " _cmd                    \
				" but there shouldn't be one, mate");       \
	}

int imap4_in_get_auth(io_t *io, flag_t tls_flags, flag_t tls_state,
		      struct auth *return_auth, token_t **return_tag)
{
  int status;
  vanessa_queue_t *q = NULL;
  token_t *tag = NULL;
  token_t *t = NULL;
  char *name = NULL, *passwd = NULL;

  while(1){
    q=read_line(io, NULL, NULL, TOKEN_IMAP4, 0, PERDITION_LOG_STR_CLIENT);
    if(!q) {
      VANESSA_LOGGER_DEBUG("read_imap4_line 1");
      break;
    }

    if((q=vanessa_queue_pop(q, (void **)&tag))==NULL){
      VANESSA_LOGGER_DEBUG("vanessa_queue_pop 1");
      break;
    }

	if (imap4_in_verify_tag_str(tag)) {
		token_assign(tag, strdup(IMAP4_UNTAGGED),
		             strlen(IMAP4_UNTAGGED), 0);
		__IMAP4_IN_BAD("Invalid tag, mate");
		goto loop;
	}

    if(token_is_eol(tag)){
      __IMAP4_IN_BAD("Missing command, mate");
      goto loop;
    }

    if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
      VANESSA_LOGGER_DEBUG("vanessa_queue_pop 2");
      t=NULL;
      break;
    }

    if(token_is_null(t)){
      __IMAP4_IN_BAD("Null command, mate");
    }

    if (token_len(t) == IMAP4_CMD_NOOP_LEN && 
			! strncasecmp((char *)token_buf(t), IMAP4_CMD_NOOP, 
				token_len(t))) {
      __IMAP4_IN_CHECK_NO_ARG(IMAP4_CMD_NOOP);
      if(imap4_in_noop_cmd(io, tag)){
        VANESSA_LOGGER_DEBUG("imap4_in_noop");
        break;
      }
    }
#ifdef WITH_SSL_SUPPORT
    else if (token_len(t) == IMAP4_CMD_STARTTLS_LEN && 
			! strncasecmp((char *)token_buf(t), IMAP4_CMD_STARTTLS, 
				token_len(t))) {
      __IMAP4_IN_CHECK_NO_ARG(IMAP4_CMD_STARTTLS);
      if(!(opt.ssl_mode & SSL_MODE_TLS_LISTEN)) {
	__IMAP4_IN_BAD("STARTTLS disabled, mate");
      }
      if(io_get_type(io) != io_type_ssl){
        if (imap4_write_str(io, NULL_FLAG, tag, IMAP4_OK,
			    "Begin TLS negotiation now") < 0) {
          VANESSA_LOGGER_DEBUG("imap4_write_str begin TLS");
          return(-1);
        }
        vanessa_queue_destroy(q);
        return(2);
      }
      else {
	__IMAP4_IN_BAD("SSL already active, mate");
      }
    }    
#endif /* WITH_SSL_SUPPORT */
    else if (token_len(t) == IMAP4_CMD_CAPABILITY_LEN && 
			! strncasecmp((char *)token_buf(t), 
				IMAP4_CMD_CAPABILITY, token_len(t))){
      __IMAP4_IN_CHECK_NO_ARG(IMAP4_CMD_CAPABILITY);
      if(imap4_in_capability_cmd(io, tag, tls_flags, tls_state)){
        VANESSA_LOGGER_DEBUG("imap4_in_capability");
        break;
      }
    }
    else if (token_len(t) == IMAP4_CMD_AUTHENTICATE_LEN &&
			! strncasecmp((char *)token_buf(t), 
				IMAP4_CMD_AUTHENTICATE, token_len(t))){
      if(vanessa_queue_length(q) != 1) {
        __IMAP4_IN_BAD("Mate, try " IMAP4_CMD_AUTHENTICATE " <mechanism>");
      }
      if(imap4_in_authenticate_cmd(io, tag)){
        VANESSA_LOGGER_DEBUG("imap4_in_noop 2");
        break;
      }
    }
    else if (token_len(t) == IMAP4_CMD_LOGOUT_LEN && 
    			! strncasecmp((char *)token_buf(t), IMAP4_CMD_LOGOUT, 
    				token_len(t))) {
      __IMAP4_IN_CHECK_NO_ARG(IMAP4_CMD_LOGOUT);
      if(imap4_in_logout_cmd(io, tag)){
        VANESSA_LOGGER_DEBUG("imap4_in_noop 3");
        break;
      }
      return(1);
    }
    else if (token_len(t) == IMAP4_CMD_LOGIN_LEN &&
			! strncasecmp((char *)token_buf(t), IMAP4_CMD_LOGIN, 
				token_len(t))) {
      if(vanessa_queue_length(q)!=2 && vanessa_queue_length(q)!=1){
	__IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
        goto loop;
      }

      token_destroy(&t);
      if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
        VANESSA_LOGGER_DEBUG("vanessa_queue_pop 3");
	t=NULL;
        break;
      }

      status = imap4_token_wrapper(io, q, &t);
      if(status < 0) {
        __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
        goto loop;
      }
      else if(status != IMAP4_QUOTED_STRING) {
	token_t *tmp_t;

        /* Read again to get the space and literal */
        vanessa_queue_destroy(q);
        q=read_line(io, NULL, NULL, TOKEN_IMAP4, 0, 
		  PERDITION_LOG_STR_CLIENT);
        if(!q) {
          VANESSA_LOGGER_DEBUG("read_imap4_line 2");
          break;
        }

        if(vanessa_queue_length(q) != 2) {
          __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
         goto loop;
        }

        /* Pop off the space, we don't need it */
        if((q=vanessa_queue_pop(q, (void **)&tmp_t))==NULL){
          VANESSA_LOGGER_DEBUG("vanessa_queue_pop 4");
          tag=NULL;
          break;
        }
        token_destroy(&tmp_t);
      }

      /* Check for empty user */
      if(!token_len(t)) {
        __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
        goto loop;
      }

      name = imap4_token_to_string(t, status);
      if (!name) {
        VANESSA_LOGGER_DEBUG("imap4_token_to_string");
        break;
      }
      token_destroy(&t);

      if(vanessa_queue_length(q)==1){
        if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
          VANESSA_LOGGER_DEBUG("vanessa_queue_pop 5");
	  tag=NULL;
          break;
        }

	if (imap4_token_wrapper(io, q, &t) < 0) {
	  __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
	  goto loop;
	}

	/* Check for empty password */
	if(!token_len(t)) {
	  __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
	  goto loop;
	}

        passwd = imap4_token_to_string(t, status);
        if (!passwd) {
          VANESSA_LOGGER_DEBUG("imap4_token_to_string");
          break;
        }
      }
      else {
	__IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
	goto loop;
      }
 
      token_destroy(&t);
      vanessa_queue_destroy(q);
      *return_tag=tag;
      *return_auth = auth_set_pwd(name, passwd);
      return(0);
    }
    else {
      __IMAP4_IN_BAD("Unrecognised command, mate");
    }

    /*Clean up before looping*/
loop:
    token_destroy(&t);
    token_destroy(&tag);
    vanessa_queue_destroy(q);
    free(name); name = NULL;
    free(passwd); passwd = NULL;
  }

  /*If we get here clean up and bail*/
  token_destroy(&t);
  token_destroy(&tag);
  vanessa_queue_destroy(q);
  free(name);
  free(passwd);

  return(-1);
}
