/**********************************************************************
 * imap4.c                                               September 1999
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
#include "protocol.h"
#include "options.h"
#include "perdition_globals.h"
#include "unused.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


static void imap4_destroy_protocol(protocol_t *protocol);
static char *imap4_port(char *port);
static flag_t imap4_encryption(flag_t ssl_flags);

/**********************************************************************
 * imap4_greeting
 * Send a greeting to the user
 * pre: io_t: io_t to write to
 *      flag: Flags as per greeting.h
 *      tls_flags: the encryption flags that have been set
 * post: greeting is written to io
 * return 0 on success
 *        -1 on error
 **********************************************************************/

int imap4_greeting(io_t *io, flag_t flag)
{
	char *message = NULL;
	int status = -1;

	message = greeting_str(IMAP4_GREETING, flag);
	if (!message) {
		VANESSA_LOGGER_DEBUG("greeting_str");
		return -1;
	}

	if (imap4_write(io, NULL_FLAG, NULL, IMAP4_OK, 1, "%s", message) < 0) {
		VANESSA_LOGGER_DEBUG("imap4_write");
		goto err;
	}

	status = 0;
err:
	free(message);
	return status;
}

/**********************************************************************
 * imap4_initialise_protocol
 * Initialise the protocol structure for the imap4 protocol
 * Pre: protocol: pointer to an allocated protocol structure
 * Post: Return seeded protocol stricture
 *              NULL on error
 **********************************************************************/

char *imap4_type[]={IMAP4_OK, IMAP4_NO, IMAP4_BAD};

protocol_t *imap4_initialise_protocol(protocol_t *protocol){
  protocol->type = imap4_type;
  protocol->write = imap4_write;
  protocol->greeting = imap4_greeting;
  protocol->quit_string = IMAP4_QUIT;
  protocol->in_get_pw= imap4_in_get_pw;
#ifdef WITH_PAM_SUPPORT
  protocol->in_authenticate= imap4_in_authenticate;
#else
  protocol->in_authenticate= NULL;
#endif
  protocol->out_setup=imap4_out_setup;
  protocol->out_authenticate=imap4_out_authenticate;
  protocol->out_response=imap4_out_response;
  protocol->destroy = imap4_destroy_protocol;
  protocol->port = imap4_port;
  protocol->encryption = imap4_encryption;

  return(protocol);
}


/**********************************************************************
 * imap4_destroy_protocol 
 * Destroy protocol specific elements of the protocol structure
 **********************************************************************/

static void imap4_destroy_protocol(protocol_t *UNUSED(protocol))
{
  ;
}


/**********************************************************************
 * imap4_port 
 * Return the port to be used
 * pre: port: port that has been set
 * post: IMAP4_DEFAULT_PORT if port is PERDITION_PROTOCOL_DEPENDANT
 *       port otherwise
 **********************************************************************/

static char *imap4_port(char *port)
{
  if(!strcmp(PERDITION_PROTOCOL_DEPENDANT, port)){
    return(IMAP4_DEFAULT_PORT);
  }

  return(port);
}


/**********************************************************************
 * imap4_encryption 
 * Return the encryption states to be used.
 * pre: ssl_flags: the encryption flags that have been set
 * post: return ssl_flags (does nothing)
 **********************************************************************/

static flag_t imap4_encryption(flag_t ssl_flags) 
{
  return(ssl_flags);
}

