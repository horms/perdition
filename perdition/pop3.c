/**********************************************************************
 * pop3.c                                                September 1999
 * Horms                                             horms@verge.net.au
 *
 * POP3 protocol defines
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
#include "pop3_in.h"
#include "pop3_out.h"
#include "pop3_write.h"
#include "options.h"
#include "protocol.h"
#include "unused.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif



static void pop3_destroy_protocol(protocol_t *protocol);
static char *pop3_port(char *port);
static flag_t pop3_encryption(flag_t ssl_flags);

/**********************************************************************
 * pop3_initialise_protocol
 * Initialise the protocol structure for the pop3 protocol
 * Pre: protocol: pointer to an allocated protocol structure
 * Post: Return seeded protocol stricture
 *              NULL on error
 **********************************************************************/

char *pop3_type[]={POP3_OK, POP3_ERR, POP3_ERR};

protocol_t *pop3_initialise_protocol(protocol_t *protocol){
  protocol->type = pop3_type;
  protocol->write = pop3_write;
  protocol->greeting_string = POP3_GREETING;
  protocol->quit_string = POP3_QUIT;
  protocol->in_get_pw= pop3_in_get_pw;
#ifdef WITH_PAM_SUPPORT
  protocol->in_authenticate= pop3_in_authenticate;
#else
  protocol->in_authenticate= NULL;
#endif
  protocol->out_setup = pop3_out_setup;
  protocol->out_authenticate = pop3_out_authenticate;
  protocol->out_response= pop3_out_response;
  protocol->destroy = pop3_destroy_protocol;
  protocol->port = pop3_port;
  protocol->encryption = pop3_encryption;

  return(protocol);
}


/**********************************************************************
 * pop3_destroy_protocol 
 * Destroy protocol specific elements of the protocol structure
 **********************************************************************/

static void pop3_destroy_protocol(protocol_t *UNUSED(protocol))
{
  ;
}


/**********************************************************************
 * pop3_port 
 * Return the port to be used
 * pre: port: port that has been set
 * post: POP3_DEFAULT_PORT if port is PERDITION_PROTOCOL_DEPENDANT
 *       port otherwise
 **********************************************************************/

static char *pop3_port(char *port)
{
  if(!strcmp(PERDITION_PROTOCOL_DEPENDANT, port)){
    return(POP3_DEFAULT_PORT);
  }

  return(port);
}


/**********************************************************************
 * pop3_encryption 
 * Return the encryption states to be used.
 * pre: ssl_flags: the encryption flags that have been set
 * post: return ssl_flags (does nothing)
 **********************************************************************/

static flag_t pop3_encryption(flag_t ssl_flags) 
{
  return(ssl_flags);
}
