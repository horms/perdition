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
 * imap4_initialise_protocol
 * Initialise the protocol structure for the imap4 protocol
 * Pre: protocol: pointer to an allocated protocol structure
 * Post: Return seeded protocol stricture
 *              NULL on error
 **********************************************************************/

protocol_t *imap4_initialise_protocol(protocol_t *protocol);

#endif
