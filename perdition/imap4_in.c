/**********************************************************************
 * imap4_in.c                                            September 1999
 * Horms                                             horms@vergenet.net
 *
 * Handle IMAP4 commands from a client
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

#include "imap4_in.h"
#include "options.h"

#include <stdlib.h>
#include <limits.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif


#define IMAP4_NON_LITERAL             0x1
#define IMAP4_SYNCHRONISING_TOKEN     0x2
#define IMAP4_NON_SYNCHRONISING_TOKEN 0x3

/**********************************************************************
 * imap4_token_is_literal
 * Determine if a token is a literal as defined in RFC 1730
 * That is a string of the form "{n}" where n is a positive integral 
 * value. The quotes may be ommitted.
 * pre: token: token to examine
 *      i: will be seeded with the value of n if token is a literal
 * post: i is seeded with the value of n if token is a literal
 * return: IMAP4_NON_SYNCHRONISING_TOKEN if token is 
 *           a non-synchronising litereal
 *         IMAP4_SYNCHRONISING_TOKEN if token is a sunchronising literal
 *         IMAP4_NON_LITERAL if token is not a literal
 *         -1 on error
 **********************************************************************/

static int imap4_token_is_literal(const token_t *token, unsigned long *i) 
{
	char *str;
	char *str2;
	int non_synchronising = IMAP4_SYNCHRONISING_TOKEN;

	if(!token_is_eol(token)) {
		return(IMAP4_NON_LITERAL);
	}

	/* Get the string out of the token */
	if((str=token_to_string(token, '\"'))==NULL){
		VANESSA_LOGGER_DEBUG("token_to_string");
		return(-1);
	}

	/* Check for surrounding {} */
	if(*str != '{' || *(str+strlen(str)-1) != '}') {
		return(IMAP4_NON_LITERAL);
	}
	*(str+strlen(str)-1) = '\0';

	/* If the traling character is a + then it is a 
	 * non_synchronising literal */

	if(*(str+strlen(str)-1) == '+') {
		non_synchronising = IMAP4_NON_SYNCHRONISING_TOKEN;
		*(str+strlen(str)-1) = '\0';
	}

	/* Check that what is left is only digits */
	if(!vanessa_socket_str_is_digit(str+1)) {
		return(IMAP4_NON_LITERAL);
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
 * Inteprate a token.
 * If the token is not a literal, as defined in RFC 1930 then the
 * token nothing is done. Else the number of bytes specified in
 * the literal token are returned as a new input_token and the
 * original input_token is destroyed.
 * Either way, the input_token return can be used as an 8bit clean value.
 * pre: io: IO to read from if neccessary
 *      q: Queue of pending tokens, not including input_token
 *      input_token: token to examine.
 *                   also used to return the token
 * post: If input_token is a literal
 *         inteprate the litereal as a byte-count using
 *             imap4_token_is_literal
 *         Destroy input_token
 *         Make sure the q is empty, else there is a syntax error
 *         Return "+ OK" to the client by writing to io
 *         Read bytes from io, as specifed by input_token
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
	if(status == IMAP4_NON_LITERAL) {
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
		imap4_write(io, NULL_FLAG, *input_token, IMAP4_OK, 
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

#ifdef WITH_PAM_SUPPORT

/**********************************************************************
 * imap4_in_authenticate
 * Authenticate an incoming pop session
 * Not really needed if we are going to authenticate with an upstream
 * pop server but it may be useful in some cases
 * pre: pw: passwd structure with username and password to authenticate
 *      io: io_t to write errors to
 *      tag: Tag to use in (Error) responses
 * post: An atempt is made to authenticate the user locallay
 *       If this fails then an tagged response is written to io
 *       Else no output is made
 * return: 1 if authentication succedes
 *         0 if authentication fails
 *         -1 if an error occurs
 **********************************************************************/

int imap4_in_authenticate(
  const struct passwd *pw, 
  io_t *io,
  const token_t *tag 
){
  pam_handle_t *pamh=NULL;

  extern int pam_retval;
  extern struct pam_conv conv_struct;

  if((
     pam_retval=pam_start(SERVICE_NAME, pw->pw_name, &conv_struct, &pamh)
  )!=PAM_SUCCESS){
    VANESSA_LOGGER_DEBUG_ERRNO("pam_start");
    do_pam_end(pamh, EX_PAM_ERROR);
    return(-1);
  }
  if(do_pam_authentication(pamh, pw->pw_name, pw->pw_passwd)<0){
    sleep(PERDITION_AUTH_FAIL_SLEEP);
    if(imap4_write(io, NULL_FLAG, tag, IMAP4_NO, "Authentication failure")<0){
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
 * imap4_in_get_pw
 * read USER and PASS commands and return them in a struct passwd *
 * allocated by this function
 * Pre: io: io_t to read from and write to
 *      return_pw: pointer to an allocated struct pw, 
 *                 where username and password
 *                 will be returned if one is found
 *      return_tag: pointer to return clients tag
 * Post: pw_return structure with pw_name and pw_passwd set
 * Return: 0: on success
 *         1: if user quits (LOGOUT command)
 *         2: if TLS negotion should be done
 *        -1: on error
 **********************************************************************/

#define __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR                                \
        if(return_pw->pw_name) {                                            \
		free(return_pw->pw_name);                                   \
		return_pw->pw_name=NULL;                                    \
	}                                                                   \
        if(return_pw->pw_passwd) {                                          \
		free(return_pw->pw_passwd);                                 \
		return_pw->pw_passwd=NULL;                                  \
	}                                                                   \
        sleep(VANESSA_LOGGER_ERR_SLEEP);                                    \
        if(imap4_write(io, NULL_FLAG, tag, IMAP4_BAD,                       \
				"Try " IMAP4_CMD_LOGIN                      \
				" <username> <passwd>")<0){                 \
		VANESSA_LOGGER_DEBUG("imap4_write syntax error");           \
		break;                                                      \
        }

#define __IMAP4_IN_CHECK_NO_ARG(_cmd)                                       \
	if(vanessa_queue_length(q)) {                                       \
		sleep(VANESSA_LOGGER_ERR_SLEEP);                            \
		if(imap4_write(io, NULL_FLAG, tag, IMAP4_BAD,               \
					"Argument given to " _cmd           \
					" but there shouldn't be one")<0){  \
			VANESSA_LOGGER_DEBUG("imap4_write syntax error");   \
				break;                                      \
		}                                                           \
		goto loop;                                                  \
	}

int imap4_in_get_pw(io_t *io, struct passwd *return_pw, token_t **return_tag)
{
  int status;
  vanessa_queue_t *q = NULL;
  token_t *tag = NULL;
  token_t *t = NULL;
  char * command_string = NULL;

  return_pw->pw_name=NULL;

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

    if(token_is_eol(tag)){
      sleep(VANESSA_LOGGER_ERR_SLEEP);
      if(token_is_null(tag)){
        if(imap4_write(io, NULL_FLAG, NULL, IMAP4_BAD, "Null command")<0){
          VANESSA_LOGGER_DEBUG("imap4_write 1");
          goto loop;
        }
      }
      else {
        if(imap4_write(io, NULL_FLAG, NULL, IMAP4_BAD, "Missing command")){
          VANESSA_LOGGER_DEBUG("imap4_write 2");
          goto loop;
        }
      }
      goto loop;
    }

    if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
      VANESSA_LOGGER_DEBUG("vanessa_queue_pop 2");
      t=NULL;
      break;
    }

    if((command_string=token_to_string(t, TOKEN_NO_STRIP))==NULL){
      VANESSA_LOGGER_DEBUG("token_to_string");
      break;
    }
     
    if(strcasecmp(command_string, IMAP4_CMD_NOOP)==0){
      __IMAP4_IN_CHECK_NO_ARG(IMAP4_CMD_NOOP);
      if(imap4_in_noop_cmd(io, tag)){
        VANESSA_LOGGER_DEBUG("imap4_in_noop");
        break;
      }
    }
#ifdef WITH_SSL_SUPPORT
    else if(strcasecmp(command_string, IMAP4_CMD_STARTTLS)==0){
      __IMAP4_IN_CHECK_NO_ARG(IMAP4_CMD_STARTTLS);
      if(io_get_type(io) != io_type_ssl){
        if(imap4_write(io, NULL_FLAG, tag, IMAP4_OK, 
				"Begin TLS negotiation now")<0){
           VANESSA_LOGGER_DEBUG("imap4_write");
          return(-1);
        }
        vanessa_queue_destroy(q);
        return(2);
      }
      else
      {
        sleep(VANESSA_LOGGER_ERR_SLEEP);
        if(imap4_write(io, NULL_FLAG, tag, IMAP4_BAD, "SSL already active")<0){
          VANESSA_LOGGER_DEBUG("ssl already active");
          break;
        }
      }
    }    
#endif /* WITH_SSL_SUPPORT */
    else if(strcasecmp(command_string, IMAP4_CMD_CAPABILLTY)==0){
      __IMAP4_IN_CHECK_NO_ARG(IMAP4_CMD_CAPABILLTY);
      if(imap4_in_capability_cmd(io, tag)){
        VANESSA_LOGGER_DEBUG("imap4_in_capability");
        break;
      }
    }
    else if(strcasecmp(command_string, IMAP4_CMD_AUTHENTICATE)==0){
      __IMAP4_IN_CHECK_NO_ARG(IMAP4_CMD_AUTHENTICATE);
      if(imap4_in_authenticate_cmd(io, tag)){
        VANESSA_LOGGER_DEBUG("imap4_in_noop 2");
        break;
      }
    }
    else if(strcasecmp(command_string, IMAP4_CMD_LOGOUT)==0){
      __IMAP4_IN_CHECK_NO_ARG(IMAP4_CMD_LOGOUT);
      if(imap4_in_logout_cmd(io, tag)){
        VANESSA_LOGGER_DEBUG("imap4_in_noop 3");
        break;
      }
      vanessa_queue_destroy(q);
      return(1);
    }
    else if(strcasecmp(command_string, IMAP4_CMD_LOGIN)==0){
      str_free(command_string);
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
      else if(status != IMAP4_NON_LITERAL) {
	token_t tmp_t;

        /* Read again to get the space and litereal */
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
      if((return_pw->pw_name=token_to_string(t, '\"'))==NULL){
        VANESSA_LOGGER_DEBUG("token_to_string");
        break;
      }
      token_destroy(&t);

      if(vanessa_queue_length(q)==1){
        if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
          VANESSA_LOGGER_DEBUG("vanessa_queue_pop 5");
	  tag=NULL;
          break;
        }

	imap4_token_wrapper(io, q, &t);
	if(t < 0) {
	  __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
	  goto loop;
	}

	/* Check for empty password */
	if(!token_len(t)) {
	  __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
	  goto loop;
	}

        if((return_pw->pw_passwd=token_to_string(t, '\"'))==NULL){
          VANESSA_LOGGER_DEBUG("token_to_string");
          free(return_pw->pw_name);
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
      return(0);
    }
    else {
      sleep(VANESSA_LOGGER_ERR_SLEEP);
      if(imap4_write(io, NULL_FLAG, tag, IMAP4_BAD, "Unrecognised command")<0){
        VANESSA_LOGGER_DEBUG("imap4_write 3");
        break;
      }
    }

    /*Clean up before looping*/
    loop:
    token_destroy(&t);
    token_destroy(&tag);
    str_free(command_string);
    vanessa_queue_destroy(q);
  }

  /*If we get here clean up and bail*/
  token_destroy(&t);
  token_destroy(&tag);
  str_free(command_string);
  vanessa_queue_destroy(q);
  return(-1);
}


/**********************************************************************
 * imap4_in_noop_cmd
 * Do a response to a NOOP command
 * pre: io: io_t to write to
 * post: Taged response to NOOP is written to io
 * return: 0 on success
 *         -1 otherwise
 **********************************************************************/

int imap4_in_noop_cmd(io_t *io, const token_t *tag){
  if(imap4_write(io, NULL_FLAG, tag, IMAP4_OK, IMAP4_CMD_NOOP)<0){
    VANESSA_LOGGER_DEBUG("imap4_write");
    return(-1);
  }

  return(0);
}


/**********************************************************************
 * imap4_in_logout_cmd
 * Do a response to a LOGOUT command
 * pre: io: io_t to write to
 * post: An untagged response advising of logout is written to io
 *       A tagged response to the LOGGOUT is written to io
 * return 0 on success
 *        -1 otherwise
 **********************************************************************/

int imap4_in_logout_cmd(io_t *io, const token_t *tag){
  if(imap4_write(io, NULL_FLAG, NULL, IMAP4_BYE, 
			  "IMAP4 server loging out")<0){
    VANESSA_LOGGER_DEBUG("imap4_write 1");
    return(-1);
  }

  if(imap4_write(io, NULL_FLAG, tag, IMAP4_OK, IMAP4_CMD_LOGOUT)<0){
    VANESSA_LOGGER_DEBUG("imap4_write 2");
    return(-1);
  }

  return(0);
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

int imap4_in_capability_cmd(io_t *io, const token_t *tag){
  extern options_t opt;

  if(imap4_write(io, NULL_FLAG, NULL, IMAP4_CMD_CAPABILLTY,
			  str_null_safe(opt.capability))<0){
    VANESSA_LOGGER_DEBUG("imap4_write 1");
    return(-1);
  }

  if(imap4_write(io, NULL_FLAG, tag, IMAP4_OK, IMAP4_CMD_CAPABILLTY)<0){
    VANESSA_LOGGER_DEBUG("imap4_write 2");
    return(-1);
  }

  return(0);
}


/**********************************************************************
 * imap4_in_authenticate_cmd
 * Do a response to an AUTHENTICATE command
 * pre: io: io_t to write to
 * post: A tagged error to the AUTHENTICATE command is given
 * return 0 on success
 *        -1 otherwise
 **********************************************************************/

int imap4_in_authenticate_cmd(io_t *io, const token_t *tag){
  if(imap4_write(
    io, 
    NULL_FLAG,
    tag, 
    IMAP4_NO, 
    IMAP4_CMD_AUTHENTICATE "mechchanism not supported"
  )<0){
    VANESSA_LOGGER_DEBUG("imap4_write 2");
    return(-1);
  }

  return(0);
}
