/**********************************************************************
 * pop3_in.c                                             September 1999
 * Horms                                             horms@vergenet.net
 *
 * Handle pop commands from a client
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

#include "pop3_in.h"

#ifdef WITH_PAM_SUPPORT

/**********************************************************************
 * pop3_in_authenticate
 * Authenticate an incoming pop session
 * Not really needed if we are going to authenticate with an upstream
 * pop server but it may be useful in some cases
 *
 * Return 1 on success, 0 on failure and -1 on error.
 **********************************************************************/

int pop3_in_authenticate(
  const struct passwd *pw, 
  const int err_fd,
  const token_t *tag
){
  pam_handle_t *pamh=NULL;

  extern int pam_retval;
  extern struct pam_conv conv_struct;

  if((
     pam_retval=pam_start(SERVICE_NAME, pw->pw_name, &conv_struct, &pamh)
  )!=PAM_SUCCESS){
    PERDITION_LOG(LOG_DEBUG, "main: pam_start: %s", strerror(errno));
    do_pam_end(pamh, EX_PAM_ERROR);
    return(-1);
  }
  if(do_pam_authentication(pamh, pw->pw_name, pw->pw_passwd)<0){
    sleep(PERDITION_AUTH_FAIL_SLEEP);
    if(pop3_write(err_fd,NULL_FLAG,NULL,POP3_ERR,"Authentication failure")<0){
      PERDITION_LOG(LOG_DEBUG, "main: pop3_write");
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
 * Pre: in_fd: file descriptor to read from
 *      out_fd: file descriptor to write to
 *      return_pw: pointer to an allocated struct pw, 
 *                 where username and password
 *                 will be returned if one is found
 *      return_tag:   ignored 
 * Post: pw_return structure with pw_name and pw_passwd set
 * Return: 0 on success
 *         1 if user quits (QUIT command)
 *         -1 on error
 **********************************************************************/

int pop3_in_get_pw(
  const int in_fd, 
  const int out_fd,
  struct passwd *return_pw,
  token_t ** return_tag
){
  vanessa_queue_t *q = NULL;
  char *command_string=NULL;
  token_t *t = NULL;
  char *message=NULL;

  return_pw->pw_name=NULL;

  while(1){
    if((q=read_line(in_fd, NULL, NULL))==NULL){
      PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: read_line");
      break;
    }

    if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
      PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: vanessa_queue_pop");
      t=NULL;
      break;
    }

    if((command_string=token_to_string(t, TOKEN_NO_STRIP))==NULL){
      PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: token_to_string");
      break;
    }
    token_unassign(t);

    if(strcasecmp(command_string, "USER")==0){
      if(return_pw->pw_name!=NULL){
        sleep(PERDITION_ERR_SLEEP);
        if(pop3_write(out_fd,NULL_FLAG,NULL,POP3_ERR,"USER is already set")<0){
          PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: pop3_write 1");
          break;
        }
        goto loop;
      }
      if(vanessa_queue_length(q)!=1){
	PERDITION_LOG(
	  LOG_DEBUG,
	  "vanessa_queue_length(q)=%d\n",
	  vanessa_queue_length(q)
	);
        sleep(PERDITION_ERR_SLEEP);
        if(pop3_write(out_fd,NULL_FLAG,NULL,POP3_ERR,"Try USER <username>")<0){
          PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: pop3_write 2");
          break;
        }
        goto loop;
      }

      if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
        PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: vanessa_queue_pop");
        t=NULL;
        break;
      }
      if((return_pw->pw_name=token_to_string(t, TOKEN_NO_STRIP))==NULL){
        PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: token_to_string");
        break;
      }
      token_destroy(&t);
      
      if((message=cat_str(3, "USER ", return_pw->pw_name, " set"))<0){
        PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: cat_str");
        goto loop;
      }
      if(pop3_write(out_fd, NULL_FLAG, NULL, POP3_OK, message)<0){
        PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: pop3_write");
        goto loop;
      }
    }
    else if(strcasecmp(command_string, "PASS")==0){
      str_free(command_string);
      if(return_pw->pw_name==NULL){
        sleep(PERDITION_ERR_SLEEP);
        if(pop3_write(out_fd, NULL_FLAG, NULL, POP3_ERR, "USER not yet set")<0){
          PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: pop3_write");
          break;
        }
        goto loop;
      }
      if(vanessa_queue_length(q)>1){
        sleep(PERDITION_ERR_SLEEP);
        if(pop3_write(out_fd,NULL_FLAG,NULL,POP3_ERR,"Try PASS <password>")<0){
          PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: pop3_write");
          break;
        }
        goto loop;
      }
      if(vanessa_queue_length(q)==1){
        if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
          PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: vanessq_queue_pop");
          free(return_pw->pw_name);
          break;
        }
        if((return_pw->pw_passwd=token_to_string(t, TOKEN_NO_STRIP))==NULL){
          PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: token_to_string");
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
    else if(strcasecmp(command_string, "QUIT")==0){
      if(pop3_write(out_fd, NULL_FLAG, NULL, POP3_OK, "QUIT")<0){
        PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: pop3_write");
        break;
      }
      vanessa_queue_destroy(q);
      return(1);
    }
    else{
      sleep(PERDITION_ERR_SLEEP);
      if(pop3_write(
        out_fd, 
	NULL_FLAG,
	NULL,
        POP3_ERR,
        "Command must be one of USER, PASS or QUIT"
      )<0){
        PERDITION_LOG(LOG_DEBUG, "pop3_in_get_pw: pop3_write");
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
