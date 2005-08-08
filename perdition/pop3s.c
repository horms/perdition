/**********************************************************************
 * pop3s.c                                                   March 2002
 * Horms                                             horms@verge.net.au
 *
 * POP3S protocol defines
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pop3.h"
#include "pop3s.h"
#include "pop3_write.h"
#include "pop3_in.h"
#include "pop3_out.h"
#include "options.h"
#include "protocol.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

static void pop3s_destroy_protocol(protocol_t *protocol);
static char *pop3s_port(char *port);
static flag_t pop3s_encryption(flag_t ssl_flags);
static char *pop3s_capability(char *capability, char **mangled_capability,
		flag_t tls_flags, flag_t tls_state);


/**********************************************************************
 * pop3s_initialise_protocol
 * Initialise the protocol structure for the pop3s protocol
 * Pre: protocol: pointer to an allocated protocol structure
 * Post: Return seeded protocol stricture
 *              NULL on error
 **********************************************************************/

char *pop3s_type[]={POP3_OK, POP3_ERR, POP3_ERR};

protocol_t *pop3s_initialise_protocol(protocol_t *protocol){
  protocol->type = pop3s_type;
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
  protocol->destroy = pop3s_destroy_protocol;
  protocol->port = pop3s_port;
  protocol->encryption = pop3s_encryption;
  protocol->capability = pop3s_capability;

  return(protocol);
}


/**********************************************************************
 * pop3s_destroy_proto 
 * Destroy protocol specific elements of the protocol structure
 **********************************************************************/

static void pop3s_destroy_protocol(protocol_t *protocol)
{
  ;
}


/**********************************************************************
 * pop3s_port 
 * Return the port to be used
 * pre: port: port that has been set
 * post: POP3S_DEFAULT_PORT if port is PERDITION_PROTOCOL_DEPENDANT
 *       port otherwise
 **********************************************************************/

static char *pop3s_port(char *port)
{
  if(!strcmp(PERDITION_PROTOCOL_DEPENDANT, port)){
    return(POP3S_DEFAULT_PORT);
  }

  return(port);
}


/**********************************************************************
 * pop3s_encryption 
 * Return the encryption states to be used.
 * pre: ssl_flags: the encryption flags that bave been set
 * post: If ssl_flags != SSL_MODE_EMPTY then return them,
 *       Else return SSL_MODE_SSL_ALL
 **********************************************************************/

static flag_t pop3s_encryption(flag_t ssl_flags) 
{
  if(ssl_flags != SSL_MODE_EMPTY) {
    return(ssl_flags);
  }
  return(SSL_MODE_SSL_ALL);
}


/**********************************************************************
 * pop3s_capability 
 * Return the capability string to be used.
 * pre: capability: capability string that has been set
 *      mangled_capability: ignored
 *      tls_flags: ignored
 *      tls_state: ignored
 * post: capability to use, as per protocol_capability
 *       with POP parameters
 **********************************************************************/

static char *pop3s_capability(char *capability, 
		char **mangled_capability, flag_t tls_flags,
		flag_t tls_state)
{
      	capability = protocol_capability(capability, PROTOCOL_C_DEL, 
      			POP3_DEFAULT_CAPABILITY, POP3_CMD_STLS,
      			POP3_CAPABILITY_DELIMITER);
	if(capability == NULL) {
		VANESSA_LOGGER_DEBUG("protocol_capability");
		return(NULL);
	}

	capability = pop3_mangle_capability(capability, mangled_capability);
	if(capability == NULL) {
		VANESSA_LOGGER_DEBUG("pop3_mangle_capability");
		return(NULL);
	}

	return(capability);
}

