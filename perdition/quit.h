/**********************************************************************
 * quit.h                                                  October 1999
 * Horms                                             horms@verge.net.au
 *
 * Protocol independent quit
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

#ifndef QUIT_BLUM
#define QUIT_BLUM

#include <pwd.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <vanessa_adt.h>

#ifdef HAVE_CONFIG_H
#include "config.h" 
#endif

#include "protocol_t.h"
#include "token.h"
#include "io.h"

int quit(io_t *io, const protocol_t *protocol, token_t *tag);

#endif
