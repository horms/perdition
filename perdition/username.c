/**********************************************************************
 * username.c                                                 June 2001
 * Horms                                             horms@vergenet.net
 *
 * Perdition, POP3 and IMAP4 proxy daemon
 * Routines to mangle usernames.
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


#include <netdb.h>

#include "username.h"
#include "options.h"
#include "str.h"

/**********************************************************************
 * username_add_domain
 * Append the domain part of the address connected to after
 * the domain delimiter if not already present.
 * pre: username: username to strip domain from
 *      in_addr: Source address of connection
 *      state: The current state. Should be one of STATE_GET_SERVER,
 *             STATE_LOCAL_AUTH or STATE_REMOTE_LOGIN.
 * post: if state&opt.add_domain &&
 *           username doesn't contain the domain delimiter
 *         append the domain delimiter and the domain for the reverse
 *         lookup of to_addr
 *       else return username
 * return: domain delimiter and domain added as appropriate
 *         NULL on error
 * Note: to free any memory that may be used call username_add_domain_free()
 *       You should call this each time username changes as the result
 *       is chached internally and is not checked for staleness.
 **********************************************************************/

static char *__username_add_domain_str=NULL;

char *username_add_domain(char *username, struct in_addr *to_addr, 
  int state){
  struct hostent *hp;
  char *domainpart;

  extern options_t opt;

  if(!(opt.add_domain&state) || to_addr==NULL)
    return(username);

  switch(state){
    case STATE_GET_SERVER:
    case STATE_LOCAL_AUTH:
    case STATE_REMOTE_LOGIN:
      break;
    default:
      PERDITION_DEBUG("unknown state\n");
      return(NULL);
  }

  /* If we have already added the domain, just return that value */
  if(__username_add_domain_str!=NULL) {
    PERDITION_DEBUG(
      "username already contains domain delimiter, not adding domain");
    return(__username_add_domain_str);
  }

  /* If we already have a domain delimiter, stop now */
  if(strstr(username, opt.domain_delimiter)!=NULL)
    return(username);

  /* If we have no reverse IP address, stop now */
  if((hp=gethostbyaddr((char *)to_addr,sizeof(struct in_addr),AF_INET))==NULL){
    PERDITION_DEBUG("no reverse IP lookup, domain not added");
    return(username);
  }

  /* Make some space for the domain part */
  domainpart=strchr(hp->h_name, '.');
  if (domainpart == NULL || *(++domainpart)=='\0'){
    PERDITION_DEBUG("No domain in reverse lookup, domain not added");
    return(username);
  }

  if ((__username_add_domain_str=(char *)malloc(
        strlen(username)+strlen(opt.domain_delimiter)+strlen(domainpart)+1
  ))==NULL){
    PERDITION_DEBUG_ERRNO("malloc");
    return(username);
  }

  /* Build the new username */
  strcpy(__username_add_domain_str, username);
  strcat(__username_add_domain_str, opt.domain_delimiter);
  strcat(__username_add_domain_str, domainpart);

  return(__username_add_domain_str);
}


/**********************************************************************
 * username_add_domain_free
 * Free any memory held by username_add_domain state
 * pre: none
 * post: If any memory has been allocated internally by 
 *       username_add_domain() it is freed
 * return: none
 **********************************************************************/

void username_add_domain_free(void){
  if(__username_add_domain_str!=NULL){
    free(__username_add_domain_str);
  }
  __username_add_domain_str=NULL;
}


/**********************************************************************
 * username_strip
 * Strip the domain name, all characters after opt.domain_delimiter,
 * from a username if it is permitted for a given state.
 * pre: username: username to strip domain from
 *      state: The current state. Should be one of STATE_GET_SERVER,
 *             STATE_LOCAL_AUTH or STATE_REMOTE_LOGIN.
 * post: if state&opt.strip_domain
 *         if state is STATE_GET_SERVER and opt.client_server_specification 
 *           return username
 *         else strip the domain name if it is present
 *       else return username
 * return: username, stripped as appropriate
 *         NULL on error
 * Note: to free any memory that may be used call username_strip_free()
 *       You should call this each time username changes as the result
 *       is chached internally and is not checked for staleness.
 **********************************************************************/

static char *__username_strip_str=NULL;

char *username_strip(char *username, int state){
  extern options_t opt;
  char *end;
  size_t len;

  if(!(opt.strip_domain&state))
    return(username);

  switch(state){
    case STATE_GET_SERVER:
      if(opt.client_server_specification)
        return(username);
      break;
    case STATE_LOCAL_AUTH:
    case STATE_REMOTE_LOGIN:
      break;
    default:
      PERDITION_DEBUG("unknown state\n");
      return(NULL);
  }

  if(__username_strip_str==NULL){
    if((end=strstr(username, opt.domain_delimiter))==NULL){
      __username_strip_str=username;
    }
    else {
      len=end-username;
      if((__username_strip_str=(char *)malloc(len+1))==NULL){
	PERDITION_DEBUG_ERRNO("malloc");
	return(NULL);
      }
      strncpy(__username_strip_str, username, len);
      *(__username_strip_str+len)='\0';
    }
  }

  return(__username_strip_str);
}


/**********************************************************************
 * username_strip_free
 * Free any memory held by username_strip state
 * pre: none
 * post: If any memory has been allocated internally by username_strip()
 *       then it is freed
 * return: none
 **********************************************************************/

void username_strip_free(void){
  if(__username_strip_str!=NULL){
    free(__username_strip_str);
  }
  __username_strip_str=NULL;
}


/**********************************************************************
 * username_lower_case
 * Strip the domain name, all characters after opt.domain_delimiter,
 * from a username if it is permitted for a given state.
 * pre: username: username to strip domain from
 *      state: The current state. Should be one of STATE_GET_SERVER,
 *             STATE_LOCAL_AUTH or STATE_REMOTE_LOGIN.
 * post: if state&opt.strip_domain
 *         if state is STATE_GET_SERVER and opt.client_server_specification 
 *           return username
 *         else strip the domain name if it is present
 *       else return username
 * return: username, stripped as appropriate
 *         NULL on error
 * Note: to free any memory that may be used call username_lower_case_free()
 **********************************************************************/

static char *__username_lower_case_str=NULL;

char *username_lower_case(char *username, int state){
  extern options_t opt;

  if(!(opt.lower_case&state))
    return(username);

  switch(state){
    case STATE_GET_SERVER:
    case STATE_LOCAL_AUTH:
    case STATE_REMOTE_LOGIN:
      break;
    default:
      PERDITION_DEBUG("unknown state\n");
      return(NULL);
  }

  username_lower_case_free();

  if((__username_lower_case_str=strdup(username))==NULL){
    PERDITION_DEBUG_ERRNO("strdup");
    return(NULL);
  }

  return(str_tolower(__username_lower_case_str));
}


/**********************************************************************
 * username_lower_case_free
 * Free any memory held by username_lower_case state
 * pre: none
 * post: If any memory has been allocated internally by 
 *       username_lower_case()
 *       then it is freed
 * return: none
 **********************************************************************/

void username_lower_case_free(void){
  if(__username_lower_case_str!=NULL){
    free(__username_lower_case_str);
  }
  __username_lower_case_str=NULL;
}


/**********************************************************************
 * username_mangle
 * Strip the username as per username_strip() then append a domain
 * as per username_add_domain() then convert the result to lowercase
 * using username_lower_case().
 * pre: username: username to manipulate
 *      to_addr: address to do reverse lookup of for username_add_domain
 *      state: The current state. Should be one of STATE_GET_SERVER,
 *             STATE_LOCAL_AUTH or STATE_REMOTE_LOGIN.
 * post: Call username_strip(), then username_add_domain() and
 *       username_lower_case().
 * return: username modified as appropriate
 *         NULL on error
 * Note: to free any memory that may be used call
 *       strip_username_and_add_domain_free()
 *       You should call this each time username changes as some
 *       intermediate results are cached are not checked for staleness.
 **********************************************************************/

char *username_mangle(char *username, 
    struct in_addr *to_addr, int state){
  char *result;

  if((result=username_strip(username, state))==NULL){
    PERDITION_DEBUG("username_strip");
    return(NULL);
  }
  if((result=username_add_domain(result, to_addr, state))==NULL){
    PERDITION_DEBUG("username_add_domain");
    return(NULL);
  }
  if((result=username_lower_case(result, state))==NULL){
    PERDITION_DEBUG("username_lower_case");
    return(NULL);
  }

  return(result);
}


/**********************************************************************
 * username_mangle_free
 * Free any memory held by strip_username and add_domain states
 * pre: none
 * post: Memory is freed as per username_strip_free(),
 *       username_add_domain_free() and username_lower_case_free();
 * return: none
 **********************************************************************/

void username_mangle_free(void){
  username_strip_free();
  username_add_domain_free();
  username_lower_case_free();
}
