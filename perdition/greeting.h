/**********************************************************************
 * greeting.h                                              October 1999
 * Horms                                             horms@vergenet.net
 *
 * Protocol indepentant writes
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999  Horms
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

#ifndef GREETING_BLUM
#define GREETING_BLUM

#include <pwd.h>
#include <sys/types.h>
#include <sys/utsname.h>

#ifdef HAVE_CONFIG_H
#include "config.h" 
#endif

#include "perdition_types.h"
#include "imap4_write.h"
#include "log.h"
#include "protocol_t.h"

/* Flags for greeting() and greeting_str()*/
#define GREETING_ADD_NODENAME (flag_t)0x1    /*Append nodename to message*/

int greeting(const int fd, const protocol_t *protocol, flag_t flag);

char *greeting_str(char *message, const protocol_t *protocol, flag_t flag);

#endif
