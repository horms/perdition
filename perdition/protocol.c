/**********************************************************************
 * protocol.c                                            September 1999
 * Horms                                             horms@verge.net.au
 *
 * Generic protocol layer
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

#include "pop3.h"
#include "pop3s.h"
#include "imap4.h"
#include "imap4s.h"
#include "managesieve.h"
#include "protocol.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


#ifdef WITH_SSL_SUPPORT
char *protocol_known[] = {"5", "POP3", "IMAP4", "POP3S", "IMAP4S",
			  "MANAGESIEVE"};
#else
char *protocol_known[] = {"3", "POP3", "IMAP4", "MANAGESIEVE"};
#endif

/**********************************************************************
 * protocol_initialise
 * initialise protocol structure
 * Pre: protocol_type: protocol type to use
 *      protocol: pointer to protocol structure to be initialised
 * Post: protocol is initialised
 *       NULL on error
 **********************************************************************/

protocol_t *protocol_initialise(const int protocol_type, protocol_t *protocol){
  if((protocol=(protocol_t *)malloc(sizeof(protocol_t)))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc");
    return(NULL);
  }

  /* Seed the protocol structure with protocol specific values */
  switch (protocol_type){
    case PROTOCOL_POP3:
      if((protocol=pop3_initialise_protocol(protocol))==NULL){
        VANESSA_LOGGER_DEBUG("pop3_initialise_protocol");
	return(NULL);
      }
      break;
    case PROTOCOL_POP3S:
      if((protocol=pop3s_initialise_protocol(protocol))==NULL){
        VANESSA_LOGGER_DEBUG("pop3s_initialise_protocol");
	return(NULL);
      }
      break;
    case PROTOCOL_IMAP4:
      if((protocol=imap4_initialise_protocol(protocol))==NULL){
        VANESSA_LOGGER_DEBUG("imap4_initialise_protocol");
	return(NULL);
      }
      break;
    case PROTOCOL_IMAP4S:
      if((protocol=imap4s_initialise_protocol(protocol))==NULL){
        VANESSA_LOGGER_DEBUG("imap4s_initialise_protocol");
	return(NULL);
      }
      break;
    case PROTOCOL_MANAGESIEVE:
      protocol = managesieve_initialise_protocol(protocol);
      if (!protocol) {
        VANESSA_LOGGER_DEBUG("managesieve_initialise_protocol");
	return NULL;
      }
      break;
    default:
      VANESSA_LOGGER_DEBUG("Unknown protocol");
      return(NULL);
  }

  return(protocol);
}


/**********************************************************************
 * protocol_destroy
 * destroy a protocol structure
 * Pre: protocol: allocated protocol structure
 * Return: none
 **********************************************************************/

void protocol_destroy(protocol_t *protocol){
  if(protocol==NULL){
    return;
  }

  /*Protocol specific destruction*/
  protocol->destroy(protocol);

  free(protocol);
  protocol=NULL;

  return;
}


/**********************************************************************
 * protocol_index
 * Return the index of a protocol in protocol_known
 * Pre: protocol_string: Protocol in ASCII: IMAP4 or POP3
 *                       case insensitive
 * Post: Index of protocol in protocol_known
 *       0 if not found (unrecognised protocol)
 *       -1 on error
 **********************************************************************/

int protocol_index(const char *protocol_string){
  int i;

  for(i=atoi(protocol_known[0]);i>0;i--){
    if(strcasecmp(protocol_string, protocol_known[i])==0){
      return(i);
    }
  }

  return(-1);
}


/**********************************************************************
 * protocol_list
 * List protocols in protocol_known
 * (known protocols)
 * Pre: string: pointer to  an unallocated string
 *      delimiter: delimiter to use in return string
 *      request: Index of protocol to list.
 *               List all protocols if 0
 * Post: string listing valid protocols
  *      NULL on error
 **********************************************************************/

char *protocol_list(char *string, const char *delimiter, const int request){
  int i;
  int noknown;
  size_t length;
  char *pos;
  char l;

  noknown=atoi(protocol_known[0]);
  
  if((request<1 || request>noknown) && request!=PROTOCOL_ALL){
    VANESSA_LOGGER_DEBUG_UNSAFE("protocol \"%d\" out of range", request);
    return(NULL);
  }

  if(request!=PROTOCOL_ALL){
    return(strdup(protocol_known[request]));
  }

  /*extra 1 to allow space tor trailing '\0'*/
  length=1+(strlen(delimiter)*(noknown-1));

  for(i=noknown;i>0;i--){
    length+=strlen(protocol_known[i]);
  }

  if((string=(char *)malloc(length))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc");
    return(NULL);
  }

  pos=string;
  for(i=1;i<=noknown && length>0;i++){
    l=snprintf(pos, length, "%s", protocol_known[i]);
    pos+=l;
    length-=l;
    if(i<noknown && length>0){
      l=snprintf(pos, length, "%s", delimiter);
      pos+=l;
      length-=l;
    }
  }

  return(string);
}


char *protocol_capability(flag_t mode, const char *existing_capability,
                          const char *add_capability,
                          const char *capability_delimiter)
{
  char *capability;

  if(mode & PROTOCOL_C_ADD) {
    capability = str_append_substring_if_missing(existing_capability,
                                                 add_capability,
                                                 capability_delimiter);
    if(capability == NULL) {
      VANESSA_LOGGER_DEBUG("str_append_substring_if_missing");
      return(NULL);
    }
  }
  else {
    capability = str_delete_substring(existing_capability, add_capability,
                                      capability_delimiter);
    if(capability == NULL) {
      VANESSA_LOGGER_DEBUG("str_delete_substring");
      return(NULL);
    }
  }

  return(capability);
}
