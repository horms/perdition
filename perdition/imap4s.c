/**********************************************************************
 * imap4s.c                                                  March 2002
 * Horms                                             horms@verge.net.au
 *
 * IMAP4 protocol defines
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

#include "imap4.h"
#include "imap4s.h"
#include "options.h"
#include "perdition_globals.h"
#include "unused.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


static void imap4s_destroy_protocol(protocol_t *protocol);
static char *imap4s_port(char *port);
static flag_t imap4s_encryption(flag_t ssl_flags);

/**********************************************************************
 * imap4s_initialise_protocol
 * Initialise the protocol structure for the imap4s protocol
 * Pre: protocol: pointer to an allocated protocol structure
 * Post: Return seeded protocol stricture
 *              NULL on error
 **********************************************************************/

char *imap4s_type[]={IMAP4_OK, IMAP4_NO, IMAP4_BAD};

protocol_t *imap4s_initialise_protocol(protocol_t *protocol){
  protocol->type = imap4s_type;
  protocol->write_str = imap4_write_str;
  protocol->greeting = imap4_greeting;
  protocol->quit_string = IMAP4_QUIT;
  protocol->bye = NULL;
  protocol->in_get_auth = imap4_in_get_auth;
#ifdef WITH_PAM_SUPPORT
  protocol->in_authenticate= imap4_in_authenticate;
#else
  protocol->in_authenticate= NULL;
#endif
  protocol->out_setup=imap4_out_setup;
  protocol->out_authenticate=imap4_out_authenticate;
  protocol->out_response=imap4_out_response;
  protocol->destroy = imap4s_destroy_protocol;
  protocol->port = imap4s_port;
  protocol->encryption = imap4s_encryption;

  return(protocol);
}


/**********************************************************************
 * imap4s_destroy_protocol 
 * Destroy protocol specific elements of the protocol structure
 **********************************************************************/

static void imap4s_destroy_protocol(protocol_t *UNUSED(protocol))
{
  ;
}


/**********************************************************************
 * imap4s_port 
 * Return the port to be used
 * pre: port: port that has been set
 * post: IMAP4S_DEFAULT_PORT if port is PERDITION_PROTOCOL_DEPENDANT
 *       port otherwise
 **********************************************************************/

static char *imap4s_port(char *port)
{
	if(strcmp(PERDITION_PROTOCOL_DEPENDANT, port))
		return port;
	if (opt.no_lookup)
		return IMAP4S_DEFAULT_PORT_NUMBER;
	return IMAP4S_DEFAULT_PORT_NAME;
}


/**********************************************************************
 * imap4s_encryption 
 * Return the encryption states to be used.
 * pre: ssl_flags: the encryption flags that have been set
 * post: If ssl_flags != SSL_MODE_EMPTY then return them,
 *       Else return SSL_MODE_SSL_ALL
 **********************************************************************/

static flag_t imap4s_encryption(flag_t ssl_flags) 
{
  if(ssl_flags != SSL_MODE_EMPTY) {
    return(ssl_flags);
  }
  return(SSL_MODE_SSL_ALL);
}
