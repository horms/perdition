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




static int imap4_token_is_literal(const token_t *token, unsigned long *i) 
{
	char *str;
	char *str2;

	if(!token_is_eol(token)) {
		return(-1);
	}

	if((str=token_to_string(token, '\"'))==NULL){
		PERDITION_DEBUG("token_to_string");
		return(-2);
	}

	if(*str != '{' || *(str+strlen(str)-1) != '}') {
		return(-1);
	}

	*(str+strlen(str)-1) = '\0';
	if(!vanessa_socket_str_is_digit(str+1)) {
		return(-1);
	}

	*i = strtoul(str+1, &str2, 10);
	if(*i == ULONG_MAX) {
		PERDITION_DEBUG_ERRNO("strtoul");
		return(-2);
	}

	return(0);
}

static token_t *imap4_token_wrapper(io_t *io, vanessa_queue_t *q, 
		token_t *input_token) 
{
	token_t *tag;
	unsigned long i;
      	int status;
  
    	status = imap4_token_is_literal(input_token, &i);
  	if(status < -1) {
      		PERDITION_DEBUG("imap4_token_is_literal");
		token_destroy(&input_token);
	  	return(NULL);
	}
	if(status == -1) {
		return(input_token);
	}
  
	token_destroy(&input_token);

	if(vanessa_queue_length(q) != 0) {
		return(NULL);
	}

	tag=token_create();
	if(tag == NULL) {
		PERDITION_DEBUG("token_create");
		return(NULL);
	}
	token_assign(tag, strdup("+"), 1, 0);
	imap4_write(io, NULL_FLAG, tag, IMAP4_OK, 
			"ready for additional input");
	token_destroy(&tag);

	if((tag=token_read(io, NULL, NULL, TOKEN_IMAP4_LITERAL, i))==NULL){
		PERDITION_DEBUG("token_read");
		return(NULL);
	}

	return(tag);
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
    PERDITION_DEBUG_ERRNO("pam_start");
    do_pam_end(pamh, EX_PAM_ERROR);
    return(-1);
  }
  if(do_pam_authentication(pamh, pw->pw_name, pw->pw_passwd)<0){
    sleep(PERDITION_AUTH_FAIL_SLEEP);
    if(imap4_write(io, NULL_FLAG, tag, IMAP4_NO, "Authentication failure")<0){
      PERDITION_DEBUG("imap4_write");
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
 * Return: 0 on success
 *         1 if user quits (LOGOUT command)
 *         -1 on error
 **********************************************************************/

#define __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR \
        sleep(PERDITION_ERR_SLEEP); \
        if(imap4_write( \
          io, \
          NULL_FLAG, \
          tag, \
          IMAP4_BAD, \
          "Try LOGIN <username> <passwd>" \
        )<0){ \
          PERDITION_DEBUG("imap4_write"); \
          break; \
        }

int imap4_in_get_pw(io_t *io, struct passwd *return_pw, token_t **return_tag){
  vanessa_queue_t *q=NULL;
  token_t *tag=NULL;
  token_t *t=NULL;
  char * command_string=NULL;

  return_pw->pw_name=NULL;

  while(1){
    if((q=read_line(io, NULL, NULL, TOKEN_IMAP4, 0))==NULL){
      PERDITION_DEBUG("read_imap4_line 1");
      break;
    }

    if((q=vanessa_queue_pop(q, (void **)&tag))==NULL){
      PERDITION_DEBUG("vanessa_queue_pop 1");
      break;
    }

    if(token_is_eol(tag)){
      if(token_is_null(tag)){
        if(imap4_write(io, NULL_FLAG, NULL, IMAP4_BAD, "Null command")<0){
          PERDITION_DEBUG("imap4_write 1");
          goto loop;
        }
      }
      else {
        if(imap4_write(io, NULL_FLAG, NULL, IMAP4_BAD, "Missing command")){
          PERDITION_DEBUG("imap4_write 2");
          goto loop;
        }
      }
      goto loop;
    }

    if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
      PERDITION_DEBUG("vanessa_queue_pop 2");
      t=NULL;
      break;
    }

    if((command_string=token_to_string(t, TOKEN_NO_STRIP))==NULL){
      PERDITION_DEBUG("token_to_string");
      break;
    }
     
    if(strcasecmp(command_string, "NOOP")==0){
      if(imap4_in_noop_cmd(io, tag)){
        PERDITION_DEBUG("imap4_in_noop 1");
        break;
      }
    }
    else if(strcasecmp(command_string, "CAPABILITY")==0){
      if(imap4_in_capability_cmd(io, tag)){
        PERDITION_DEBUG("imap4_in_capability");
        break;
      }
    }
    else if(strcasecmp(command_string, "AUTHENTICATE")==0){
      if(imap4_in_authenticate_cmd(io, tag)){
        PERDITION_DEBUG("imap4_in_noop 2");
        break;
      }
    }
    else if(strcasecmp(command_string, "LOGOUT")==0){
      if(imap4_in_logout_cmd(io, tag)){
        PERDITION_DEBUG("imap4_in_noop 3");
        break;
      }
      vanessa_queue_destroy(q);
      return(1);
    }
    else if(strcasecmp(command_string, "LOGIN")==0){
      str_free(command_string);
      if(vanessa_queue_length(q)!=2 && vanessa_queue_length(q)!=1){
	__IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
        goto loop;
      }

      token_destroy(&t);
      if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
        PERDITION_DEBUG("vanessa_queue_pop 3");
	t=NULL;
        break;
      }


      {
	token_t *tmp_t;

	tmp_t = t;
        t = imap4_token_wrapper(io, q, tmp_t);
        if(t == NULL) {
          __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
          goto loop;
        }

	if(t != tmp_t) {
	  /* Read again to get the space password */
	  vanessa_queue_destroy(q);
          if((q=read_line(io, NULL, NULL, TOKEN_IMAP4, 0))==NULL){
            PERDITION_DEBUG("read_imap4_line 2");
            break;
          }

	  if(vanessa_queue_length(q) != 2) {
            __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
	    goto loop;
	  }

	  /* Pop off the space, we don't need it */
          if((q=vanessa_queue_pop( q, (void **)&tmp_t))==NULL){
            PERDITION_DEBUG("vanessa_queue_pop 4");
	    tag=NULL;
            break;
          }
	  token_destroy(&tmp_t);
	}
      }

      if((return_pw->pw_name=token_to_string(t, '\"'))==NULL){
        PERDITION_DEBUG("token_to_string");
        break;
      }

      token_destroy(&t);
      if(vanessa_queue_length(q)==1){
        if((q=vanessa_queue_pop( q, (void **)&t))==NULL){
          PERDITION_DEBUG("vanessa_queue_pop 5");
	  tag=NULL;
          break;
        }

	t = imap4_token_wrapper(io, q, t);
	if(t == NULL) {
	  __IMAP4_IN_GET_PW_LOGIN_SYNTAX_ERROR;
	  goto loop;
	}

        if((return_pw->pw_passwd=token_to_string(t, '\"'))==NULL){
          PERDITION_DEBUG("token_to_string");
          free(return_pw->pw_name);
          break;
        }
      }
      else {
	return_pw->pw_passwd=NULL;
      }

      token_destroy(&t);
      vanessa_queue_destroy(q);
      *return_tag=tag;
      return(0);
    }
    else {
      sleep(PERDITION_ERR_SLEEP);
      if(imap4_write(io, NULL_FLAG, tag, IMAP4_BAD, "Unrecognised command")<0){
        PERDITION_DEBUG("imap4_write");
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
  if(imap4_write(io, NULL_FLAG, tag, IMAP4_OK, "NOOP")<0){
    PERDITION_DEBUG("imap4_write");
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
  if(imap4_write(io, NULL_FLAG, NULL, "BYE", "IMAP4 server loging out")<0){
    PERDITION_DEBUG("imap4_write 1");
    return(-1);
  }

  if(imap4_write(io, NULL_FLAG, tag, IMAP4_OK, "LOGOUT")<0){
    PERDITION_DEBUG("imap4_write 2");
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

  if(imap4_write(io, NULL_FLAG, NULL, "CAPABILITY", 
			  str_null_safe(opt.imap_capability))<0){
    PERDITION_DEBUG("imap4_write 1");
    return(-1);
  }

  if(imap4_write(io, NULL_FLAG, tag, IMAP4_OK, "CAPABILITY")<0){
    PERDITION_DEBUG("imap4_write 2");
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
    "AUTHENTICATE mechchanism not supported"
  )<0){
    PERDITION_DEBUG("imap4_write 2");
    return(-1);
  }

  return(0);
}
