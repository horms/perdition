/**********************************************************************
 * imap4_in.c                                            September 1999
 * Horms                                             horms@vergenet.net
 *
 * Handle IMAP4 commands from a client
 *
 * perdition
 * Mail retreival proxy server
 * Copyright (C) 1999  Horms
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

#include "imap4_in.h"

#ifdef WITH_PAM_SUPPORT

/**********************************************************************
 * imap4_in_authenticate
 * Authenticate an incoming pop session
 * Not really needed if we are going to authenticate with an upstream
 * pop server but it may be useful in some cases
 *
 * Return 1 on success, 0 on failure and -1 on error.
 **********************************************************************/

int imap4_in_authenticate(
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
    if(imap4_write(err_fd,NULL_FLAG,tag,IMAP4_NO,"Authentication failure")<0){
      PERDITION_LOG(LOG_DEBUG, "main: imap4_write");
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
 * Pre: in_fd: file descriptor to read from
 *      out_fd: file descriptor to write to
 *      return_pw: pointer to an allocated struct pw, 
 *                 where username and password
 *                 will be returned if one is found
 *      return_tag: pointer to return clients tag
 * Post: pw_return structure with pw_name and pw_passwd set
 * Return: 0 on success
 *         1 if user quits (LOGOUT command)
 *         -1 on error
 **********************************************************************/

int imap4_in_get_pw(
  const int in_fd, 
  const int out_fd,
  struct passwd *return_pw,
  token_t **return_tag
){
  vanessa_queue_t *q=NULL;
  token_t *tag=NULL;
  token_t *t=NULL;
  char * command_string=NULL;

  return_pw->pw_name=NULL;

  while(1){
    if((q=read_line(in_fd, NULL, NULL))==NULL){
      PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: read_imap4_line");
      break;
    }

    if((q=vanessa_queue_pop(q, (void **)&tag))==NULL){
      PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: vanessa_queue_pop 1");
      break;
    }

    if(token_is_eol(tag)){
      if(token_is_null(tag)){
        if(imap4_write(out_fd, NULL_FLAG, NULL, IMAP4_BAD, "Null command")<0){
          PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: imap4_write 1");
          goto loop;
        }
      }
      else {
        if(imap4_write(out_fd, NULL_FLAG, NULL, IMAP4_BAD, "Missing command")){
          PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: imap4_write 2");
          goto loop;
        }
      }
      goto loop;
    }

    if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
      PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: vanessa_queue_pop 2");
      t=NULL;
      break;
    }

    if((command_string=token_to_string(t))==NULL){
      PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: token_to_string");
      break;
    }
     
    if(strcasecmp(command_string, "NOOP")==0){
      if(imap4_in_noop(out_fd, tag)){
        PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: imap4_in_noop");
        break;
      }
    }
    else if(strcasecmp(command_string, "CAPABILITY")==0){
      if(imap4_in_capability(out_fd, tag)){
        PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: imap4_in_capability");
        break;
      }
    }
    else if(strcasecmp(command_string, "AUTHENTICATE")==0){
      if(imap4_in_authenticate_cmd(out_fd, tag)){
        PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: imap4_in_noop");
        break;
      }
    }
    else if(strcasecmp(command_string, "LOGOUT")==0){
      if(imap4_in_logout(out_fd, tag)){
        PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: imap4_in_noop");
        break;
      }
      vanessa_queue_destroy(q);
      return(1);
    }
    else if(strcasecmp(command_string, "LOGIN")==0){
      str_free(command_string);
      if(vanessa_queue_length(q)!=2){
        sleep(PERDITION_ERR_SLEEP);
        if(imap4_write(
          out_fd,
          NULL_FLAG,
          tag,
          IMAP4_BAD,
          "Try LOGIN <username> <passwd>"
        )<0){
          PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: imap4_write");
          break;
        }
        goto loop;
      }

      destroy_token(&t);
      if((q=vanessa_queue_pop(q, (void **)&t))==NULL){
        PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: vanessa_queue_pop");
	t=NULL;
        break;
      }
      if((return_pw->pw_name=token_to_string(t))==NULL){
        PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: token_to_string");
        break;
      }

      destroy_token(&t);
      if((q=vanessa_queue_pop( q, (void **)&t))==NULL){
        PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: vanessa_queue_pop");
	tag=NULL;
        break;
      }
      if((return_pw->pw_passwd=token_to_string(t))==NULL){
        PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: token_to_string");
        free(return_pw->pw_name);
        break;
      }
      destroy_token(&t);
      vanessa_queue_destroy(q);
      *return_tag=tag;
      return(0);
    }
    else {
      sleep(PERDITION_ERR_SLEEP);
      if(imap4_write(out_fd,NULL_FLAG,tag,IMAP4_BAD,"Unrecognised command")<0){
        PERDITION_LOG(LOG_DEBUG, "imap4_in_get_pw: imap4_write");
        break;
      }
    }

    /*Clean up before looping*/
    loop:
    destroy_token(&t);
    destroy_token(&tag);
    str_free(command_string);
    vanessa_queue_destroy(q);
  }


  /*If we get here clean up and bail*/
  destroy_token(&t);
  destroy_token(&tag);
  str_free(command_string);
  vanessa_queue_destroy(q);
  return(-1);
}


/**********************************************************************
 * imap4_in_noop
 * Do a noop - doesn't do anything special at the moment
 * Pre: fd: file descriptor to write to
 * Return 1 on success
 *        0 otherwise
 **********************************************************************/

int imap4_in_noop(const int fd, const token_t *tag){
  if(imap4_write(fd, NULL_FLAG, tag, IMAP4_OK, "NOOP")<0){
    PERDITION_LOG(LOG_DEBUG, "imap4_in_noop: imap4_write");
    return(-1);
  }

  return(0);
}


/**********************************************************************
 * imap4_in_logout
 * Do a response to a logout
 * Pre: fd: file descriptor to write to
 * Return 1 on success
 *        0 otherwise
 **********************************************************************/

int imap4_in_logout(const int fd, const token_t *tag){
  if(imap4_write(fd, NULL_FLAG, NULL, "BYE", "IMAP4 server loging out")<0){
    PERDITION_LOG(LOG_DEBUG, "imap4_in_logout: imap4_write 1");
    return(-1);
  }

  if(imap4_write(fd, NULL_FLAG, tag, IMAP4_OK, "LOGOUT")<0){
    PERDITION_LOG(LOG_DEBUG, "imap4_in_logout: imap4_write 2");
    return(-1);
  }

  return(0);
}


/**********************************************************************
 * imap4_in_capability
 * Do a response to a capability command
 * Pre: fd: file descriptor to write to
 * Return 1 on success
 *        0 otherwise
 **********************************************************************/

int imap4_in_capability(const int fd, const token_t *tag){
  if(imap4_write(fd, NULL_FLAG, NULL, "CAPABILITY", IMAP4_CAPABILITIES)<0){
    PERDITION_LOG(LOG_DEBUG, "imap4_in_logout: imap4_write 1");
    return(-1);
  }

  if(imap4_write(fd, NULL_FLAG, tag, IMAP4_OK, "CAPABILITY")<0){
    PERDITION_LOG(LOG_DEBUG, "imap4_in_logout: imap4_write 2");
    return(-1);
  }

  return(0);
}


/**********************************************************************
 * imap4_in_authenticate_cmd
 * Do a response to a capability command
 * Pre: fd: file descriptor to write to
 * Return 1 on success
 *        0 otherwise
 **********************************************************************/

int imap4_in_authenticate_cmd(const int fd, const token_t *tag){
  if(imap4_write(
    fd, 
    NULL_FLAG,
    tag, 
    IMAP4_NO, 
    "AUTHENTICATE mechchanism not supported"
  )<0){
    PERDITION_LOG(LOG_DEBUG, "imap4_in_logout: imap4_write 2");
    return(-1);
  }

  return(0);
}


