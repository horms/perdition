/**********************************************************************
 * protocol.c                                            September 1999
 * Horms                                             horms@vergenet.net
 *
 * Generic protocol layer
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

#include "protocol.h"

char *protocol_known[] = {"2", "POP3", "IMAP4"};

/**********************************************************************
 * protocol_intitialise
 * initialise protocol structure
 * Pre: protocol_type: protocol type to use PROTOCOL_IMAP or PROTOCOL_POP3
 *      protocol: pointer to protocol strucure to be intialised
 * Post: protocol is intialised
 *       NULL on error
 **********************************************************************/

protocol_t *protocol_initialise(const int protocol_type, protocol_t *protocol){
  if((protocol=(protocol_t *)malloc(sizeof(protocol_t)))==NULL){
    PERDITION_DEBUG_ERRNO("malloc");
    return(NULL);
  }

  /* Seed the protocol structure with protocol specific values */
  switch (protocol_type){
    case PROTOCOL_POP3:
      if((protocol=pop3_initialise_protocol(protocol))==NULL){
        PERDITION_DEBUG("pop3_initialise_protocol");
	return(NULL);
      }
      break;
    case PROTOCOL_IMAP4:
      if((protocol=imap4_initialise_protocol(protocol))==NULL){
        PERDITION_DEBUG("imap4_initialise_protocol");
	return(NULL);
      }
      break;
    default:
      PERDITION_DEBUG("Unknown protocol");
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
 * Pre: protocol_string: Protocol inn assci: IMAP4 or POP3
 *                       case insensitive
 * Post: Index of protocol in protocol_known
 *       0 if not found (unrecognised protocol)
 *       -1 on error
 **********************************************************************/

int protocol_index(const char *protocol_string){
  int i;

  extern char *protocol_known[];

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
 * Pre: string: pointer to  an unalocated string
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

  extern char *protocol_known[];

  noknown=atoi(protocol_known[0]);
  
  if((request<1 || request>noknown) && request!=PROTOCOL_ALL){
    PERDITION_DEBUG("protocol \"%d\" out of range", request);
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
    PERDITION_DEBUG_ERRNO("malloc");
    return(NULL);
  }

  pos=string;
  for(i=1;i<=noknown;i++){
    pos+=sprintf(pos, "%s", protocol_known[i]);
    if(i<noknown){
      pos+=sprintf(pos, "%s", delimiter);
    }
  }

  return(string);
}
