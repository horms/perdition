/**********************************************************************
 * pop3s.h                                                   March 2002
 * Horms                                             horms@verge.net.au
 *
 * POP3S protocol defines
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2004  Horms
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

#ifndef _PERDITION_POP3S_H
#define _PERDITION_POP3S_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "protocol_t.h"


/**********************************************************************
 * pop3s_initialise_protocol
 * Initialise the protocol structure for the pop3s protocol
 * Pre: protocol: pointer to an allocated protocol structure
 * Post: Return seeded protocol stricture
 *              NULL on error
 **********************************************************************/

protocol_t *pop3s_initialise_protocol(protocol_t *protocol);

#endif /* _PERDITION_POP3S_H */
