/**********************************************************************
 * greeting.c                                              October 1999
 * Horms                                             horms@vergenet.net
 *
 * Protocol independent greeting
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

#include "greeting.h"
#include "options.h"

/**********************************************************************
 * greeting
 * Send a greeting to the user
 * Pre: fd: file descriptor to write to
 *      protocol: Protocol in use
 *      message: Message to display
 *      flag: Flags as per greeting.h
 * Return 0 on success
 *        -1 on error
 **********************************************************************/

int greeting(const int fd, const protocol_t *protocol, flag_t flag){
  char *message=NULL;

  if((message=greeting_str(message, protocol, flag))==NULL){
    PERDITION_LOG(LOG_DEBUG, "greeting: greeting_str");
    return(-1);
  }
  if(protocol->write(
    fd, 
    NULL_FLAG, 
    NULL, 
    protocol->type[PROTOCOL_OK], 
    message
  )<0){
    PERDITION_LOG(LOG_DEBUG, "greeting: protocol->write");
    return(-1);
  }
  free(message);
  return(0);
}


/**********************************************************************
 * greeting_str
 * Produce greeting string
 * Pre: message: unallocated ponter to put greeting string in
 *      protocol: Protocol in use
 *      flag: Flags as per greeting.h
 * Return message string on success
 *        NULL on error
 **********************************************************************/

char * greeting_str(char *message, const protocol_t *protocol, flag_t flag){
  char *host;
  struct hostent *hp;
  struct in_addr in;

  extern struct utsname *system_uname;
  extern options_t opt;
  extern int h_errno;

  if(flag&GREETING_ADD_NODENAME){
    if(!opt.no_bind_banner && !opt.no_lookup && opt.bind_address!=NULL){
      if((hp=gethostbyname(opt.bind_address))==NULL){
        PERDITION_LOG(
	  LOG_DEBUG, 
	  "warning: greeting_str: gethostbyname: %s", 
	  strerror(errno)
	);
        host=opt.bind_address;
      }
      else {
	bcopy(hp->h_addr, &in, hp->h_length);
	if((hp=gethostbyaddr(&in, sizeof(struct in_addr), AF_INET))==NULL){
          PERDITION_LOG(
	    LOG_DEBUG, 
	    "warning: greeting_str: gethostbyaddr: %s", 
	    strerror(errno)
	  );
          host=opt.bind_address;
	}
	else {
          host=opt.bind_address;
	  host=hp->h_name;
	}
      }
    }
    else{
      host=system_uname->nodename;
    }
    if((message=cat_str(3, protocol->greeting_string, " ", host))==NULL){
      PERDITION_LOG(LOG_DEBUG, "greeting_str: cat_str");
      return(NULL);
    }
  }
  else{
    if((message=strdup(protocol->greeting_string))==NULL){
      PERDITION_LOG(LOG_DEBUG, "greeting_str: strdup");
      return(NULL);
    }
  }
  return(message);
}
