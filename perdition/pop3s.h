/**********************************************************************
 * pop3s.h                                                   March 2002
 * Horms                                             horms@vergenet.net
 *
 * POP3S protocol defines
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

#ifndef _PERDITION_POP3S_H
#define _PERDITION_POP3S_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "log.h"
#include "protocol_t.h"
#include "str.h"
#include "pop3_in.h"
#include "pop3_out.h"
#include "pop3_write.h"

protocol_t *pop3s_initialise_protocol(protocol_t *protocol);

void pop3s_destroy_protocol(protocol_t *protocol);

char *pop3s_port(char *port);

flag_t pop3s_encryption(flag_t ssl_flags);

#endif

