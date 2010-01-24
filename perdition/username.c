/**********************************************************************
 * username.c                                                 June 2001
 * Horms                                             horms@verge.net.au
 *
 * Perdition, POP3 and IMAP4 proxy daemon
 * Routines to mangle usernames.
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


#include <netdb.h>

#include "username.h"
#include "options.h"
#include "str.h"
#include "sock.h"


#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include "perdition_globals.h"


/**********************************************************************
 * username_add_domain
 * Append the domain part of the address connected to after
 * the domain delimiter if not already present.
 * pre: username: username to strip domain from
 *      state: The current state. Should be one of STATE_GET_SERVER,
 *             STATE_LOCAL_AUTH or STATE_REMOTE_LOGIN.
 *      strip_depth: number of leading levels of the domain to strip
 * post: if state&opt.add_domain &&
 *           username doesn't contain the domain delimiter
 *         append the domain delimiter and the domain for the reverse
 *         lookup of to_addr
 *       else return username
 * return: domain delimiter and domain added as appropriate
 *         NULL on error
 **********************************************************************/

char *
username_add_domain(char *username, int state, unsigned int strip_depth) {
  int rc;
  char *domainpart;
  char *new_str;
  char host[NI_MAXHOST];

  VANESSA_LOGGER_DEBUG_UNSAFE("username_add_domain %x %x", opt.add_domain,
			      state);

  if(!(opt.add_domain & state))
    return(username);

  /* If we already have a domain delimiter, stop now */
  if(strstr(username, opt.domain_delimiter)!=NULL)
    return(username);

  if (opt.explicit_domain) {
    domainpart = opt.explicit_domain;
  }
  else if (!sockname) {
    return username;
  }
  else {
    rc = getnameinfo((struct sockaddr *)sockname,
		     perdition_get_salen((struct sockaddr *)sockname),
		     host, NI_MAXHOST, NULL, 0, 0);
    if (rc) {
      VANESSA_LOGGER_DEBUG_UNSAFE("getnameinfo sockname: %s",
				  gai_strerror(rc));
      return NULL;
    }

    domainpart = host;
    while (strip_depth-- && *domainpart) {
      char *subdomain;
      subdomain = strchr(domainpart, '.');
      if (!subdomain) {
        VANESSA_LOGGER_DEBUG("No domain completely stripped away, not added");
        return username;
      }
      domainpart = subdomain + 1;  /* +1 to remove the leading '.' */
    }

    if (!*domainpart) 
      return username;
  }

  if ((new_str=(char *)malloc(
        strlen(username)+strlen(opt.domain_delimiter)+strlen(domainpart)+1
  ))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc");
    return(NULL);
  }

  /* Build the new username */
  strcpy(new_str, username);
  strcat(new_str, opt.domain_delimiter);
  strcat(new_str, domainpart);

  return(new_str);
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
 **********************************************************************/

char *username_strip(char *username, int state){
  char *end;
  char *new_str;
  size_t len;

  if(!(opt.strip_domain&state))
    return(username);

  if(state==STATE_GET_SERVER && opt.client_server_specification){
    return(username);
  }

  if((end=strrstr(username, opt.domain_delimiter))==NULL){
    return(username);
  }

  len=end-username;
  if((new_str=(char *)malloc(len+1))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc");
    return(NULL);
  }
  strncpy(new_str, username, len);
  *(new_str+len)='\0';

  return(new_str);
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
 **********************************************************************/

char *username_lower_case(char *username, int state){
  char *new_str;

  if(!(opt.lower_case&state))
    return(username);

  if((new_str=strdup(username))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("strdup");
    return(NULL);
  }

  return(str_tolower(new_str));
}


/**********************************************************************
 * username_mangle
 * Strip the username as per username_strip() then append a domain
 * as per username_add_domain() then convert the result to lowercase
 * using username_lower_case().
 * pre: username: username to manipulate
 *      state: The current state. Should be one of STATE_GET_SERVER,
 *             STATE_LOCAL_AUTH or STATE_REMOTE_LOGIN.
 * post: Call username_strip(), then username_add_domain() and
 *       username_lower_case().
 * return: username modified as appropriate
 *         NULL on error
 **********************************************************************/

char *username_mangle(char *username, int state){
  char *result;
  char *old_result;

  if((result=username_strip(username, state))==NULL){
    VANESSA_LOGGER_DEBUG("username_strip");
    return(NULL);
  }

  old_result = result;
  result = username_add_domain(result, state, opt.add_domain_strip_depth);
  if (!result) {
    VANESSA_LOGGER_DEBUG("username_add_domain");
    return(NULL);
  }
  if(old_result != result && old_result != username) {
      free(old_result);
  }

  old_result = result;
  if((result=username_lower_case(old_result, state))==NULL){
    VANESSA_LOGGER_DEBUG("username_lower_case");
    return(NULL);
  }
  if(old_result != result && old_result != username) {
      free(old_result);
  }

  return(result);
}
