/**********************************************************************
 * imap4.h                                               September 1999
 * Horms                                             horms@vergenet.net
 *
 * IMAP4 protocol defines
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2002  Horms
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
 * imap4_intitialise_proto
 * Intialialoise the protocol structure for the imap4 protocol
 * Pre: protocol: pointer to an allocated protocol structure
 * Post: Return seeded protocol stricture
 *              NULL on error
 **********************************************************************/

protocol_t *imap4_initialise_protocol(protocol_t *protocol);


/**********************************************************************
 * imap4_destroy_proto 
 * Destory protocol specifig elements of the protocol struture
 **********************************************************************/

void imap4_destroy_protocol(protocol_t *protocol);


/**********************************************************************
 * imap4_port 
 * Return the port to be used
 * pre: port: port that has been set
 * post: IMAP4_DEFAULT_PORT if port is PERDITION_PROTOCOL_DEPENDANT
 *       port otherwise
 **********************************************************************/

char *imap4_port(char *port);


/**********************************************************************
 * imap4_encryption 
 * Return the encription states to be used.
 * pre: ssl_flags: the encryption flags that bave been set
 * post: return ssl_flags (does nothing)
 **********************************************************************/

flag_t imap4_encryption(flag_t ssl_flags);


/**********************************************************************
 * imap4_capability 
 * Return the capability string to be used.
 * pre: capability: capability string that has been set
 *      mangled_capability: not used
 *      ssl_flags: the encryption flags that bave been set
 * post: capability to use, as per protocol_capability
 *       with IMAP4 parameters
 **********************************************************************/

char *imap4_capability(char *capability, char **mangled_capability,
		flag_t ssl_flags);


#endif
