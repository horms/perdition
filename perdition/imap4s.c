/**********************************************************************
 * imap4s.c                                                  March 2002
 * Horms                                             horms@vergenet.net
 *
 * IMAP4 protocol defines
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imap4.h"
#include "imap4s.h"
#include "options.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * imap4s_intitialise_proto
 * Intialialoise the protocol structure for the imap4s protocol
 * Pre: protocol: pointer to an allocated protocol structure
 * Post: Return seeded protocol stricture
 *              NULL on error
 **********************************************************************/

char *imap4s_type[]={IMAP4_OK, IMAP4_NO, IMAP4_BAD};

protocol_t *imap4s_initialise_protocol(protocol_t *protocol){
  extern char *imap4s_type[];

  protocol->type = imap4s_type;
  protocol->write = imap4_write;
  protocol->greeting_string = IMAP4_GREETING;
  protocol->quit_string = IMAP4_QUIT;
  protocol->one_time_tag = IMAP4_ONE_TIME_TAG;
  protocol->in_get_pw= imap4_in_get_pw;
  protocol->out_authenticate=imap4_out_authenticate;
#ifdef WITH_PAM_SUPPORT
  protocol->in_authenticate= imap4_in_authenticate;
#else
  protocol->in_authenticate= NULL;
#endif
  protocol->out_response=imap4_out_response;
  protocol->destroy = imap4s_destroy_protocol;
  protocol->port = imap4s_port;
  protocol->encryption = imap4s_encryption;

  return(protocol);
}


/**********************************************************************
 * imap4s_destroy_proto 
 * Destory protocol specifig elements of the protocol struture
 **********************************************************************/

void imap4s_destroy_protocol(protocol_t *protocol){
  ;
}


/**********************************************************************
 * imap4s_port 
 * Return the port to be used
 * pre: port: port that has been set
 * post: IMAP4S_DEFAULT_PORT if port is PERDITION_PROTOCOL_DEPENDANT
 *       port otherwise
 **********************************************************************/

char *imap4s_port(char *port){
  if(!strcmp(PERDITION_PROTOCOL_DEPENDANT, port)){
    return(IMAP4S_DEFAULT_PORT);
  }

  return(port);
}


/**********************************************************************
 * imap4s_encryption 
 * Return the encription states to be used.
 * pre: ssl_flags: the encryption flags that bave been set
 * post: If ssl_flags != SSL_MODE_EMPTY then return them,
 *       Else return SSL_MODE_SSL_ALL
 **********************************************************************/

flag_t imap4s_encryption(flag_t ssl_flags) {
  if(ssl_flags != SSL_MODE_EMPTY) {
    return(ssl_flags);
  }
  return(SSL_MODE_SSL_ALL);
}
