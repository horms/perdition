/**********************************************************************
 * pop3_in.c                                             September 1999
 * Horms                                             horms@vergenet.net
 *
 * Handle pop commands from a client
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

#include "pop3_in.h"
#include "options.h"

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
    if(pop3_write(io, NULL_FLAG, NULL, POP3_ERR, 
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


/**********************************************************************
 * pop3_in_get_pw
 * read USER and PASS commands and return them in a struct passwd *
 * allocated by this function
 * pre: io: io_t to write to and read from
 *      return_pw: pointer to an allocated struct pw, 
 *                 where username and password
 *                 will be returned if one is found
 *      return_tag: ignored 
 * post: pw_return structure with pw_name and pw_passwd set
 * return: 0 on success
 *         1 if user quits (QUIT command)
 *         -1 on error
 **********************************************************************/

int pop3_in_get_pw(
  io_t *io,
  struct passwd *return_pw,
  token_t **return_tag
){
  vanessa_queue_t *q = NULL;
  char *command_string = NULL;
  token_t *t = NULL;
  char *message=NULL;

  extern options_t opt;

  return_pw->pw_name=NULL;

  while(1){
    q=read_line(io, NULL, NULL, TOKEN_POP3, 0, PERDITION_LOG_STR_CLIENT);
    if(!q) {
      VANESSA_LOGGER_DEBUG("pop3_in_get_pw: read_line");
      break;
    }

    if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
      VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
      t=NULL;
      break;
    }

    if((command_string=token_to_string(t, TOKEN_NO_STRIP))==NULL){
      VANESSA_LOGGER_DEBUG("token_to_string");
      break;
    }
    token_unassign(t);

    if(strcasecmp(command_string, POP3_CMD_CAPA)==0){
      if(vanessa_queue_length(q)!=0){
	VANESSA_LOGGER_DEBUG_UNSAFE(
	  "vanessa_queue_length(q)=%d\n",
	  vanessa_queue_length(q)
	);
        sleep(VANESSA_LOGGER_ERR_SLEEP);
        if(pop3_write(io, NULL_FLAG, NULL, POP3_ERR, 
				"Mate, try: " POP3_CMD_CAPA)<0){
          VANESSA_LOGGER_DEBUG("pop3_write capa args");
          break;
        }
        goto loop;
      }
      pop3_write(io, NULL_FLAG, NULL, POP3_OK, "Capability list follows, mate");
      pop3_write(io, WRITE_STR_NO_CLLF, NULL, NULL, opt.mangled_capability);
      goto loop;
    }

#ifdef WITH_SSL_SUPPORT
    if(opt.ssl_mode & SSL_MODE_TLS_LISTEN &&
        !strcasecmp(command_string, POP3_CMD_STLS)){
      if(vanessa_queue_length(q)!=0){
	VANESSA_LOGGER_DEBUG_UNSAFE(
	  "vanessa_queue_length(q)=%d\n",
	  vanessa_queue_length(q)
	);
        sleep(VANESSA_LOGGER_ERR_SLEEP);
        if(pop3_write(io, NULL_FLAG, NULL, POP3_ERR,
				"Mate, try: " POP3_CMD_STLS)<0){
          VANESSA_LOGGER_DEBUG("pop3_write stls args");
          break;
        }
        goto loop;
      }
      if(io_get_type(io) != io_type_ssl){
        pop3_write(io, NULL_FLAG, NULL, POP3_OK, 
			"Begin TLS negotiation, mate");
        token_destroy(&t);
        vanessa_queue_destroy(q);
        return(2);
      }
      else
      {
        sleep(VANESSA_LOGGER_ERR_SLEEP);
        if(pop3_write(io, NULL_FLAG, NULL, POP3_ERR, 
	    "TLS already active, mate")<0){
          VANESSA_LOGGER_DEBUG("pop3_write stls set");
          break;
        }
        goto loop;
      }
    } 
#endif /* WITH_SSL_SUPPORT */

    if(strcasecmp(command_string, POP3_CMD_USER)==0){
      if(return_pw->pw_name!=NULL){
        sleep(VANESSA_LOGGER_ERR_SLEEP);
        if(pop3_write(io, NULL_FLAG, NULL, POP3_ERR, 
	    POP3_CMD_USER " is already set, mate")<0){
          VANESSA_LOGGER_DEBUG("pop3_write user set");
          break;
        }
        goto loop;
      }
      if(vanessa_queue_length(q)!=1){
	VANESSA_LOGGER_DEBUG_UNSAFE(
	  "vanessa_queue_length(q)=%d\n",
	  vanessa_queue_length(q)
	);
        sleep(VANESSA_LOGGER_ERR_SLEEP);
        if(pop3_write(io, NULL_FLAG, NULL, POP3_ERR,
	    "Mate, try: " POP3_CMD_USER " <username>")<0){
          VANESSA_LOGGER_DEBUG("pop3_write user args");
          break;
        }
        goto loop;
      }

      if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
        VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
        t=NULL;
        break;
      }
      if((return_pw->pw_name=token_to_string(t, TOKEN_NO_STRIP))==NULL){
        VANESSA_LOGGER_DEBUG("token_to_string");
        break;
      }
      token_destroy(&t);
      
      if((message=str_cat(3, POP3_CMD_USER " ", return_pw->pw_name, 
				      " set, mate"))<0){
        VANESSA_LOGGER_DEBUG("str_cat");
        goto loop;
      }
      if(pop3_write(io, NULL_FLAG, NULL, POP3_OK, message)<0){
        VANESSA_LOGGER_DEBUG("pop3_write user set");
        goto loop;
      }
    }
    else if(strcasecmp(command_string, POP3_CMD_PASS)==0){
      str_free(command_string);
      if(return_pw->pw_name==NULL){
        sleep(VANESSA_LOGGER_ERR_SLEEP);
        if(pop3_write(io, NULL_FLAG, NULL, POP3_ERR, 
	    POP3_CMD_USER " not yet set, mate")<0){
          VANESSA_LOGGER_DEBUG("pop3_write pass, user not set");
          break;
        }
        goto loop;
      }
      if(vanessa_queue_length(q)>1){
        sleep(VANESSA_LOGGER_ERR_SLEEP);
        if(pop3_write(io, NULL_FLAG, NULL, POP3_ERR, 
	    "Mate, try: " POP3_CMD_PASS " <password>")<0){
          VANESSA_LOGGER_DEBUG("pop3_write pass args");
          break;
        }
        goto loop;
      }
      if(vanessa_queue_length(q)==1){
        if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
          VANESSA_LOGGER_DEBUG("vanessq_queue_pop");
          free(return_pw->pw_name);
          break;
        }
        if((return_pw->pw_passwd=token_to_string(t, TOKEN_NO_STRIP))==NULL){
          VANESSA_LOGGER_DEBUG("token_to_string");
          free(return_pw->pw_name);
          break;
        }
      }
      else {
        return_pw->pw_passwd=NULL;
      }
      token_destroy(&t);
      vanessa_queue_destroy(q);
      return(0);
    }
    else if(strcasecmp(command_string, POP3_CMD_QUIT)==0){
      if(pop3_write(io, NULL_FLAG, NULL, POP3_OK, POP3_CMD_QUIT)<0){
        VANESSA_LOGGER_DEBUG("pop3_write quit");
        break;
      }
      vanessa_queue_destroy(q);
      return(1);
    }
    else{
      if(pop3_write(io, NULL_FLAG, NULL, POP3_ERR, 
            "Mate, the command must be one of " POP3_CMD_CAPA ", " 
	    POP3_CMD_USER ", " POP3_CMD_PASS " or " POP3_CMD_QUIT) < 0) {
        VANESSA_LOGGER_DEBUG("pop3_write command");
        break;
      }
    }

    /*Clean up before looping*/
    loop:
    token_destroy(&t);
    str_free(command_string);
    vanessa_queue_destroy(q);
    str_free(message);
  }

  /*If we get here clean up and bail*/
  token_destroy(&t);
  str_free(command_string);
  vanessa_queue_destroy(q);
  str_free(message);
  return(-1);
}
