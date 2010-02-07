/**********************************************************************
 * pop3.h                                                September 1999
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

#ifndef _PERDITION_POP3_H
#define _PERDITION_POP3_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "protocol_t.h"


/**********************************************************************
 * pop3_initialise_protocol
 * Initialise the protocol structure for the pop3 protocol
 * Pre: protocol: pointer to an allocated protocol structure
 * Post: Return seeded protocol stricture
 *              NULL on error
 **********************************************************************/

protocol_t *pop3_initialise_protocol(protocol_t *protocol);


/**********************************************************************
 * pop3_capability 
 * Return the capability string to be used.
 * pre: capability: capability string that has been set
 *      tls_flags: not used
 *      tls_state: not used
 * post: capability to use, as per protocol_capability
 *       with POP parameters
 **********************************************************************/

char *pop3_capability(char *capability, char **mangled_capability,
		flag_t tls_flags, flag_t tls_state);
#endif

