/**********************************************************************
 * protocol.h                                            September 1999
 * Horms                                             horms@vergenet.net
 *
 * Generic protocol layer
 *
 * NB: protocol_t.h and not protocol.h (this file) should
 *     be included by other source files
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

#ifndef PROTOCOL_FLIM
#define PROTOCOL_FLIM

#include <vanessa_adt.h>

#include "protocol_t.h"

/* This is nasty
 * protocol_known[1]=number oof protocols as a string
 * the rest of the elements are the name of protocols as strings
 * as gan be given as command line arguments to perdtion
 *
 * PROTOCOL_<BLAH> indicates the index of <BLAH> in 
 * protocol_known. This is used internally
 *
 * protocol_known is defined in protocol.c
 */

#define PROTOCOL_POP3 1
#define PROTOCOL_IMAP4 2
#define PROTOCOL_POP3S 3
#define PROTOCOL_IMAP4S 4
#define PROTOCOL_DEFAULT PROTOCOL_POP3
#define PROTOCOL_ALL 0

#define PROTOCOL_S_OK            0x1 
#define PROTOCOL_S_STARTTLS      0x2
#define PROTOCOL_S_LOGINDISABLED 0x4

#define PROTOCOL_C_ADD           0x01
#define PROTOCOL_C_DEL           0x02

/*End of nastiness*/

protocol_t *protocol_initialise(int protocol_type, protocol_t *protocol);

void protocol_destroy(protocol_t *protocol);

int protocol_index(const char *protocol_string);

char *protocol_list(char *string, const char *delimiter, const int request);

char *protocol_capability(char *capability, flag_t ssl_flags,
		const char *default_capability, const char *tls_capability,
		const char *capability_delimiter);

#endif

