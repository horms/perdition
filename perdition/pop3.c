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
#include "perdition_globals.h"
#include "protocol.h"
#include "unused.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif



static void pop3_destroy_protocol(protocol_t *protocol);
static char *pop3_port(char *port);
static flag_t pop3_encryption(flag_t ssl_flags);

/**********************************************************************
 * pop3_greeting
 * Send a greeting to the user
 * pre: io_t: io_t to write to
 *      flag: Flags as per greeting.h
 *      tls_flags: the encryption flags that have been set
 * post: greeting is written to io
 * return 0 on success
 *        -1 on error
 **********************************************************************/

int pop3_greeting(io_t *io, flag_t flag)
{
	char *message = NULL;
	int status = -1;

	message = greeting_str(POP3_GREETING, flag);
	if (!message) {
		VANESSA_LOGGER_DEBUG("greeting_str");
		return -1;
	}

	if (pop3_write_str(io, NULL_FLAG, NULL, POP3_OK, message) < 0) {
		VANESSA_LOGGER_DEBUG("pop3_write_str");
		goto err;
	}

	status = 0;
err:
	free(message);
	return status;
}

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
  protocol->write_str = pop3_write_str;
  protocol->greeting = pop3_greeting;
  protocol->quit_string = POP3_QUIT;
  protocol->bye = NULL;
  protocol->in_get_auth = pop3_in_get_auth;
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
	if (strcmp(PERDITION_PROTOCOL_DEPENDANT, port))
		return port;
	if (opt.no_lookup)
		return POP3_DEFAULT_PORT_NUMBER;
	return POP3_DEFAULT_PORT_NAME;
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
