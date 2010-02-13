/**********************************************************************
 * imap4.h                                               September 1999
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

#ifndef _PERDITION_IMAP4_H
#define _PERDITION_IMAP4_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "log.h"
#include "token.h"
#include "protocol_t.h"
#include "str.h"
#include "imap4_in.h"
#include "imap4_out.h"

/**********************************************************************
 * imap4_greeting_str
 * String for imap greeting
 * pre: flag: Flags as per greeting.h
 * return greeting string
 *        NULL on error
 **********************************************************************/

char *imap4_greeting_str(flag_t flag);

/**********************************************************************
 * imap4_greeting
 * Send a greeting to the user
 * pre: io_t: io_t to write to
 *      flag: Flags as per greeting.h
 * post: greeting is written to io
 * return 0 on success
 *        -1 on error
 **********************************************************************/

int imap4_greeting(io_t *io, flag_t flag);

/**********************************************************************
 * imap4_initialise_protocol
 * Initialise the protocol structure for the imap4 protocol
 * Pre: protocol: pointer to an allocated protocol structure
 * Post: Return seeded protocol stricture
 *              NULL on error
 **********************************************************************/

protocol_t *imap4_initialise_protocol(protocol_t *protocol);

/**********************************************************************
 * imap4_capability
 * Return the capability string to be used.
 * pre: tls_flags: the encryption flags that have been set
 *      tls_state: the current state of encryption for the session
 * post: capability to use, as per protocol_capability
 *       with IMAP4 parameters. Should be freed by caller.
 **********************************************************************/

char *imap4_capability(flag_t tls_flags, flag_t tls_state);

#endif
